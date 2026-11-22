"""Chroma-backed knowledge base, one collection per scope (ADR 0003, docs/storage.md).

  kb_admin                 - curated KB, shared by every session and by eval runs
  kb_session_<session_id>  - one learner's uploads; only that session ever reads it

Scopes never mix: a chunk goes to the collection its `metadata["scope"]` names, and a query only
reads the admin collection plus (if a session id is given) that one session's collection. Dropping
a session's collection is how `purge_session` removes its vectors.

We embed ourselves (instead of a Chroma embedding function) so documents and queries use the same
model as the chunker's tokenizer, and bge's query instruction can be added to queries only.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from chromadb.errors import NotFoundError

from netllm.config import get_settings
from netllm.ingest.models import Chunk

SESSION_PREFIX = "kb_session_"
# Session ids become part of a collection name: allow only what Chroma accepts (and nothing that
# could address another collection).
SESSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}")
BGE_QUERY_PROMPT = "Represent this sentence for searching relevant passages: "


class Embedder(Protocol):
    def embed_documents(self, texts: list[str]) -> list[list[float]]: ...
    def embed_query(self, text: str) -> list[float]: ...


class SentenceTransformerEmbedder:
    """Local embedding model (default BAAI/bge-small-en-v1.5). Vectors are L2-normalised."""

    def __init__(self, model_name: str = "BAAI/bge-small-en-v1.5", query_prompt: str | None = None):
        from sentence_transformers import SentenceTransformer

        self.model = SentenceTransformer(model_name)
        # bge models expect an instruction in front of queries (not documents).
        self.query_prompt = query_prompt if query_prompt is not None else (
            BGE_QUERY_PROMPT if "bge-" in model_name.lower() else "")

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return self.model.encode(texts, normalize_embeddings=True).tolist()

    def embed_query(self, text: str) -> list[float]:
        return self.model.encode(self.query_prompt + text, normalize_embeddings=True).tolist()


@dataclass
class Hit:
    """A retrieved chunk with its provenance (source, section, page, scope, source_sha256, ...)."""

    id: str
    text: str
    metadata: dict
    distance: float  # cosine distance: 0 = same direction, lower is closer

    @property
    def scope(self) -> str:
        return self.metadata.get("scope", "")

    @property
    def citation(self) -> str:
        """Human-readable reference, e.g. 'kurose.pdf, 3.5 TCP > 3.5.6 Flow Control, p. 268'."""
        parts = [self.metadata.get("source", "unknown source")]
        if self.metadata.get("section"):
            parts.append(self.metadata["section"])
        if self.metadata.get("page"):
            parts.append(f"p. {self.metadata['page']}")
        return ", ".join(parts)


def session_collection_name(session_id: str) -> str:
    if not SESSION_ID.fullmatch(session_id):
        raise ValueError(f"Invalid session id {session_id!r}: use letters, digits, '-' or '_' (max 63)")
    return SESSION_PREFIX + session_id


class KnowledgeStore:
    def __init__(self, client, embedder: Embedder, admin_collection: str = "kb_admin"):
        if admin_collection.startswith(SESSION_PREFIX):
            raise ValueError(f"Admin collection may not start with {SESSION_PREFIX!r}")
        self.client = client
        self.embedder = embedder
        self.admin_collection = admin_collection

    # ------------------------------------------------------------------ collections
    def _collection_name(self, scope: str, session_id: str | None) -> str:
        if scope == "admin":
            return self.admin_collection
        if scope == "session":
            if not session_id:
                raise ValueError("Session-scope chunks need a session_id")
            return session_collection_name(session_id)
        raise ValueError(f"Unknown scope {scope!r}")

    def _get_or_create(self, name: str):
        return self.client.get_or_create_collection(
            name, embedding_function=None, configuration={"hnsw": {"space": "cosine"}})

    def _get(self, name: str):
        """Existing collection or None. Reads never create collections."""
        try:
            return self.client.get_collection(name, embedding_function=None)
        except (NotFoundError, ValueError):
            return None

    # ----------------------------------------------------------------------- write
    def add(self, chunks: list[Chunk], session_id: str | None = None) -> int:
        """Upsert chunks into the collection of their scope. Returns how many were written.

        Session chunks also get `session_id` in their metadata, so a hit can always be traced back
        to the session (and upload) it came from.
        """
        by_collection: dict[str, list[Chunk]] = {}
        for c in chunks:
            scope = c.metadata.get("scope")
            name = self._collection_name(scope, session_id)
            if scope == "session":
                c.metadata["session_id"] = session_id
            by_collection.setdefault(name, []).append(c)

        for name, group in by_collection.items():
            self._get_or_create(name).upsert(
                ids=[c.id for c in group],
                documents=[c.text for c in group],
                metadatas=[c.metadata for c in group],
                embeddings=self.embedder.embed_documents([c.text for c in group]),
            )
        return sum(len(g) for g in by_collection.values())

    # ------------------------------------------------------------------------ read
    def query(self, text: str, session_id: str | None = None, k: int = 5) -> list[Hit]:
        """Top-k chunks from the admin KB plus, if session_id is given, that session's uploads."""
        names = [self.admin_collection]
        if session_id:
            names.append(session_collection_name(session_id))

        vector = self.embedder.embed_query(text)
        hits: list[Hit] = []
        for name in names:
            col = self._get(name)
            if col is None or (n := col.count()) == 0:
                continue
            res = col.query(query_embeddings=[vector], n_results=min(k, n),
                            include=["documents", "metadatas", "distances"])
            hits.extend(Hit(i, d, dict(m or {}), dist) for i, d, m, dist in zip(
                res["ids"][0], res["documents"][0], res["metadatas"][0], res["distances"][0]))
        # Same embedder and metric in both collections, so distances are comparable.
        return sorted(hits, key=lambda h: h.distance)[:k]

    # ---------------------------------------------------------------------- delete
    def delete_upload(self, session_id: str, upload_id: str) -> None:
        """Delete the chunks of one upload (they carry metadata["upload_id"]). Idempotent."""
        col = self._get(session_collection_name(session_id))
        if col is not None:
            col.delete(where={"upload_id": upload_id})

    def drop_session(self, session_id: str) -> None:
        """Delete a session's collection. Idempotent; part of purge_session."""
        try:
            self.client.delete_collection(session_collection_name(session_id))
        except (NotFoundError, ValueError):
            pass


def open_store() -> KnowledgeStore:
    """Store backed by the Chroma server and embed model from settings (.env)."""
    import chromadb

    s = get_settings()
    return KnowledgeStore(chromadb.HttpClient(host=s.chroma_host, port=s.chroma_port),
                          SentenceTransformerEmbedder(s.embed_model), s.kb_admin_collection)


def main() -> None:
    ap = argparse.ArgumentParser(description="Add documents to the KB or query it.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    add = sub.add_parser("add", help="ingest a file or folder into a scope")
    add.add_argument("input")
    add.add_argument("--scope", choices=["admin", "session"], default="admin")
    add.add_argument("--session", help="session id (required for --scope session)")
    q = sub.add_parser("query", help="retrieve chunks and print them with their provenance")
    q.add_argument("text")
    q.add_argument("--session", help="also search this session's uploads")
    q.add_argument("-k", type=int, default=5)
    drop = sub.add_parser("drop-session", help="delete a session's collection")
    drop.add_argument("session")
    args = ap.parse_args()

    store = open_store()
    if args.cmd == "add":
        if args.scope == "session" and not args.session:
            ap.error("--scope session needs --session")
        from netllm.ingest import Ingestor

        ing = Ingestor()
        src = Path(args.input)
        chunks = ing.ingest_dir(src, args.scope) if src.is_dir() else ing.ingest(src, args.scope)
        n = store.add(chunks, session_id=args.session)
        target = store._collection_name(args.scope, args.session)
        print(f"{n} chunks -> {target}")
    elif args.cmd == "query":
        for i, h in enumerate(store.query(args.text, session_id=args.session, k=args.k), 1):
            print(f"[{i}] {h.distance:.3f}  {h.scope:<7}  {h.citation}")
            print(f"     {h.text[:160].replace(chr(10), ' ')}")
    else:
        store.drop_session(args.session)
        print(f"dropped {session_collection_name(args.session)}")


if __name__ == "__main__":
    main()
