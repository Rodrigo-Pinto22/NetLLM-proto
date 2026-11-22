from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


class CreateSessionRequest(BaseModel):
    profile: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9_-]{1,64}$", description="Learner profile (file name in configs/profiles/, without .yaml). "
                                  "Defaults to NETLLM_PROFILE.")


class SessionResponse(BaseModel):
    session_id: UUID = Field(description="Random, pseudonymous session id")
    profile: str
    created_at: datetime
    expires_at: datetime = Field(description="When the session and everything in it is deleted")


class UploadResponse(BaseModel):
    upload_id: UUID
    filename: str = Field(description="Sanitised file name; this is the `source` shown in citations")
    sha256: str = Field(description="SHA-256 of the uploaded bytes")
    size_bytes: int
    n_chunks: int = Field(description="Chunks added to this session's knowledge base")


class RetrieveRequest(BaseModel):
    query: str = Field(min_length=1, max_length=2000)
    k: int = Field(default=5, ge=1, le=20, description="How many passages to return")


class Passage(BaseModel):
    n: int = Field(description="Number used in the context block and in citations, e.g. [1]")
    chunk_id: str
    scope: Literal["admin", "session"]
    source: str = Field(description="File the chunk came from")
    section: str = Field(description="Heading path, e.g. '3.5 TCP > 3.5.6 Flow Control'")
    page: int | None
    source_sha256: str | None = Field(description="SHA-256 of the exact source file version")
    upload_id: UUID | None = Field(description="Session passages only: the upload it came from")
    label: str = Field(description="Human-readable citation")
    distance: float = Field(description="Cosine distance to the query; lower is closer")
    text: str


class RetrieveResponse(BaseModel):
    context: str = Field(description="Passages as a quoted-data block, ready to put in a prompt (ADR 0011)")
    passages: list[Passage]
