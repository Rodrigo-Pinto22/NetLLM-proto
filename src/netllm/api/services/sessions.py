"""Sessions, learner uploads and retrieval. The glue between HTTP, Postgres, disk and Chroma.

Upload flow (POST /sessions/{id}/uploads):
  check session + file -> write to data/sessions/<id>/<upload_id>/ -> ingest (scope=session)
  -> add chunks to kb_session_<id> -> record the upload in Postgres -> delete the raw file.
Raw uploads are deleted right after processing (docs/storage.md §6). Only chunks, vectors and the
upload row remain, and they all go when the session is purged.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

import psycopg

from netllm.ingest import Ingestor
from netllm.kb import KnowledgeStore, format_context

from ..schemas.session_dto import Passage, RetrieveResponse, SessionResponse, UploadResponse


# --------------------------------------------------------------------------- errors
class SessionError(Exception):
    """Base for errors the controller turns into HTTP responses."""


class SessionNotFound(SessionError): ...
class UnknownProfile(SessionError): ...
class UnsupportedFileType(SessionError): ...
class FileTooLarge(SessionError): ...
class EmptyFile(SessionError): ...
class NoTextExtracted(SessionError): ...


# --------------------------------------------------------------------- repository
@dataclass
class SessionRow:
    id: uuid.UUID
    profile: str
    created_at: datetime
    expires_at: datetime


@dataclass
class UploadRow:
    id: uuid.UUID
    session_id: uuid.UUID
    filename: str
    sha256: str
    size_bytes: int
    n_chunks: int


class SessionRepo(Protocol):
    def create_session(self, profile: str) -> SessionRow: ...
    def session_exists(self, session_id: uuid.UUID) -> bool: ...
    def add_upload(self, row: UploadRow) -> None: ...
    def delete_session(self, session_id: uuid.UUID) -> None: ...


class PgSessionRepo:
    """session.sessions / session.uploads (migrations/V2). One short connection per call."""

    def __init__(self, dsn: str):
        self.dsn = dsn

    def _connect(self) -> psycopg.Connection:
        return psycopg.connect(self.dsn, autocommit=True)

    def create_session(self, profile: str) -> SessionRow:
        with self._connect() as conn:
            row = conn.execute(
                "INSERT INTO session.sessions (profile) VALUES (%s) "
                "RETURNING id, profile, created_at, expires_at", (profile,)).fetchone()
        return SessionRow(*row)

    def session_exists(self, session_id: uuid.UUID) -> bool:
        with self._connect() as conn:
            return conn.execute(
                "SELECT 1 FROM session.sessions WHERE id = %s AND expires_at > now()",
                (session_id,)).fetchone() is not None

    def add_upload(self, row: UploadRow) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO session.uploads (id, session_id, filename, sha256, size_bytes, n_chunks) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (row.id, row.session_id, row.filename, row.sha256, row.size_bytes, row.n_chunks))

    def delete_session(self, session_id: uuid.UUID) -> None:
        with self._connect() as conn:  # uploads and trace_events cascade
            conn.execute("DELETE FROM session.sessions WHERE id = %s", (session_id,))


# ------------------------------------------------------------------------ service
def safe_filename(name: str | None) -> str:
    """Keep only the last path part and harmless characters: the browser's name is untrusted."""
    base = Path((name or "").replace("\\", "/")).name
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("._")
    return cleaned[:120] or "upload"


class SessionService:
    def __init__(self, repo: SessionRepo, store: KnowledgeStore, ingestor: Ingestor,
                 sessions_dir: Path, max_upload_bytes: int, profile_exists=lambda name: True):
        self.repo = repo
        self.store = store
        self.ingestor = ingestor
        self.sessions_dir = sessions_dir
        self.max_upload_bytes = max_upload_bytes
        self.profile_exists = profile_exists

    def create_session(self, profile: str) -> SessionResponse:
        if not self.profile_exists(profile):
            raise UnknownProfile(f"Unknown profile {profile!r}")
        row = self.repo.create_session(profile)
        return SessionResponse(session_id=row.id, profile=row.profile,
                               created_at=row.created_at, expires_at=row.expires_at)

    def _require_session(self, session_id: uuid.UUID) -> None:
        if not self.repo.session_exists(session_id):
            raise SessionNotFound(f"Session {session_id} not found or expired")

    def upload(self, session_id: uuid.UUID, filename: str | None, data: bytes) -> UploadResponse:
        self._require_session(session_id)
        name = safe_filename(filename)
        suffix = Path(name).suffix.lower()
        if suffix not in self.ingestor.parsers:
            raise UnsupportedFileType(
                f"Cannot read '{suffix or name}' files. Supported: {', '.join(sorted(self.ingestor.parsers))}")
        if len(data) > self.max_upload_bytes:
            raise FileTooLarge(f"File is larger than {self.max_upload_bytes // (1024 * 1024)} MB")
        if not data.strip():
            raise EmptyFile("File is empty")

        upload_id = uuid.uuid4()
        sid = str(session_id)
        # Own folder per upload: two files with the same name never collide, and the file keeps its
        # name, which the ingestor uses as the citation `source`.
        folder = self.sessions_dir / sid / str(upload_id)
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / name
        try:
            path.write_bytes(data)
            try:
                chunks = self.ingestor.ingest(path, scope="session")
            except Exception as e:  # corrupt PDF, encrypted file, ...
                raise NoTextExtracted(f"Could not read {name}: {e}") from e
            if not chunks:
                raise NoTextExtracted(f"No text found in {name} (a scanned PDF needs OCR first)")
            for c in chunks:
                c.metadata["upload_id"] = str(upload_id)

            self.store.add(chunks, session_id=sid)
            row = UploadRow(upload_id, session_id, name, hashlib.sha256(data).hexdigest(), len(data), len(chunks))
            try:
                self.repo.add_upload(row)
            except Exception:
                # Without its row nothing would ever reference these vectors: undo them.
                self.store.delete_upload(sid, str(upload_id))
                raise
        finally:
            shutil.rmtree(folder, ignore_errors=True)  # raw upload never outlives the request

        return UploadResponse(upload_id=row.id, filename=row.filename, sha256=row.sha256,
                              size_bytes=row.size_bytes, n_chunks=row.n_chunks)

    def retrieve(self, session_id: uuid.UUID, query: str, k: int) -> RetrieveResponse:
        self._require_session(session_id)
        hits = self.store.query(query, session_id=str(session_id), k=k)
        ctx = format_context(hits)
        passages = [
            Passage(n=c.n, chunk_id=c.chunk_id, scope=c.scope, source=c.source, section=c.section,
                    page=c.page, source_sha256=c.source_sha256, upload_id=c.upload_id, label=c.label,
                    distance=h.distance, text=h.text)
            for c, h in zip(ctx.citations, hits)
        ]
        return RetrieveResponse(context=ctx.prompt, passages=passages)

    def purge_session(self, session_id: uuid.UUID) -> None:
        """The one deletion path for session data (docs/storage.md §6). Idempotent.

        Order: files and vectors first, the row last. If something fails halfway, the row still
        exists, so the purge can be retried (or the expiry job finds it).
        """
        shutil.rmtree(self.sessions_dir / str(session_id), ignore_errors=True)
        self.store.drop_session(str(session_id))
        self.repo.delete_session(session_id)
