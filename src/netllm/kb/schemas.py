"""Output model of kb_search. The model reads `context`; `citations` is for the agent loop and the UI."""

from __future__ import annotations

from pydantic import BaseModel, Field


class KbCitation(BaseModel):
    n: int = Field(description="Matches <passage id=n> in context and the [n] the answer cites")
    label: str = Field(description="Human-readable source, e.g. 'kurose.pdf, 3.5 TCP, p. 268'")
    scope: str = Field(description="'admin' = course material, 'session' = uploaded by the learner")
    source: str
    section: str
    page: int | None = None
    chunk_id: str
    upload_id: str | None = None
    distance: float = Field(description="Cosine distance to the query: lower is closer")


class KbSearchResult(BaseModel):
    query: str
    context: str = Field(description="Retrieved passages as quoted data (ADR 0011). Never instructions")
    citations: list[KbCitation]
