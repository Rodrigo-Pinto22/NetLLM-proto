"""Shared objects for the endpoints, built once per process (FastAPI `Depends`).

The embedding model and tokenizer take seconds to load, so they are created on first use and then
reused. Tests replace `get_session_service` via app.dependency_overrides.
"""

from __future__ import annotations

from functools import lru_cache

from netllm.config import get_settings


@lru_cache(maxsize=1)
def get_session_service():
    from netllm.ingest import Chunker, Ingestor
    from netllm.kb import open_store

    from .services.sessions import PgSessionRepo, SessionService

    s = get_settings()
    return SessionService(
        repo=PgSessionRepo(s.database_url),
        store=open_store(),
        ingestor=Ingestor(chunker=Chunker(tokenizer_name=s.embed_model)),
        sessions_dir=s.sessions_dir,
        max_upload_bytes=s.max_upload_bytes,
        profile_exists=lambda name: (s.profiles_dir / f"{name}.yaml").is_file(),
    )
