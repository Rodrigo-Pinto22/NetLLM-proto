"""Knowledge-base tool exposed to the LLM over MCP (ADR 0007).

kb_search reads the curated course KB, plus one session's uploads when `session_id` is given.
The session is not the model's to choose (ADR 0014): a tool argument named `session_id` is hidden
from the model by the agent loop and filled in with the current session. Without one (Goose, eval
runs) the search reads the course KB only.
"""

from __future__ import annotations

from functools import lru_cache

from .context import format_context
from .schemas import KbCitation, KbSearchResult
from .store import KnowledgeStore, open_store

MAX_K = 8


@lru_cache(maxsize=1)
def _store() -> KnowledgeStore:
    # Lazy: loading the embedding model takes seconds, and only kb_search needs it.
    return open_store()


def kb_search(query: str, k: int = 5, session_id: str | None = None) -> dict:
    """Search the course material (textbook, slides, lab guides) and the learner's own uploads for passages about a networking concept. Cite the passages you use by number, e.g. [1].

    Args:
        query: What to look for, in a few words, e.g. 'TCP slow start' or 'flow control vs congestion control'.
        k: Number of passages to return, 1 to 8.
        session_id: Filled in by the tutor application; never set it yourself.
    """
    query = query.strip()
    if not query:
        raise ValueError("query is empty")
    k = max(1, min(k, MAX_K))
    hits = _store().query(query, session_id=session_id or None, k=k)
    ctx = format_context(hits)
    citations = [
        KbCitation(n=c.n, label=c.label, scope=c.scope, source=c.source, section=c.section, page=c.page,
                   chunk_id=c.chunk_id, upload_id=c.upload_id, distance=round(h.distance, 4))
        for c, h in zip(ctx.citations, hits)
    ]
    return KbSearchResult(query=query, context=ctx.prompt, citations=citations).model_dump()


KB_TOOLS = [kb_search]
