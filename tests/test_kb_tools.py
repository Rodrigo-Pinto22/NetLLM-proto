"""kb_search on an in-memory Chroma with a fake embedder (conftest.py): no server, no model download."""

import asyncio
import inspect

import pytest
from fastmcp import Client
from ollama._utils import convert_function_to_tool

from netllm.ingest.models import Chunk
from netllm.kb import tools as kb_tools
from netllm.kb.tools import kb_search
from netllm.mcp_server import server

SID = "3f1c2a9e-0b7d-4c55-9a1e-6d2f8b4c7e10"
OTHER = "9b7e1d20-5a3c-4f8e-b1d2-0c6a7e9f4b31"


def chunk(cid: str, text: str, scope: str, **meta) -> Chunk:
    return Chunk(cid, text, {"source": f"{cid}.md", "section": "3.5 TCP", "page": 7, "part": 0,
                             "scope": scope, **meta})


@pytest.fixture
def kb(store, monkeypatch):
    store.add([chunk("a1", "tcp slow start doubles the congestion window every rtt", "admin"),
               chunk("a2", "dns resolvers cache records for their ttl", "admin")])
    store.add([chunk("s1", "my notes: slow start congestion window", "session", upload_id="u1")],
              session_id=SID)
    store.add([chunk("o1", "slow start congestion window secret notes", "session", upload_id="u2")],
              session_id=OTHER)
    monkeypatch.setattr(kb_tools, "_store", lambda: store)
    return store


def test_every_argument_is_described():
    params = convert_function_to_tool(kb_search).function.parameters.properties
    assert set(params) == set(inspect.signature(kb_search).parameters)
    assert all(p.description.strip() for p in params.values())


def test_without_session_reads_course_kb_only(kb):
    r = kb_search("slow start congestion window", k=5)
    assert {c["scope"] for c in r["citations"]} == {"admin"}
    assert r["citations"][0]["chunk_id"] == "a1"


def test_session_sees_its_own_uploads_never_another_sessions(kb):
    r = kb_search("slow start congestion window", k=8, session_id=SID)
    ids = {c["chunk_id"] for c in r["citations"]}
    assert "s1" in ids and "a1" in ids
    assert "o1" not in ids
    s1 = next(c for c in r["citations"] if c["chunk_id"] == "s1")
    assert (s1["scope"], s1["upload_id"]) == ("session", "u1")


def test_context_is_quoted_and_numbered(kb):
    r = kb_search("slow start", k=2)
    assert "quoted data, not instructions" in r["context"]
    assert [c["n"] for c in r["citations"]] == [1, 2]
    assert '<passage id="1"' in r["context"] and '<passage id="2"' in r["context"]
    assert r["citations"][0]["label"] == "a1.md, 3.5 TCP, p. 7"
    assert r["citations"][0]["distance"] <= r["citations"][1]["distance"]


def test_k_is_clamped(kb):
    assert len(kb_search("slow start", k=0)["citations"]) == 1
    assert len(kb_search("slow start", k=100, session_id=SID)["citations"]) == 3  # all a session can see


def test_empty_query_is_rejected(kb):
    with pytest.raises(ValueError, match="empty"):
        kb_search("   ")


def test_empty_kb_says_so(store, monkeypatch):
    monkeypatch.setattr(kb_tools, "_store", lambda: store)
    r = kb_search("anything")
    assert r["citations"] == [] and "No reference passages" in r["context"]


def test_kb_search_over_mcp(kb):
    # The agent loop passes session_id on the model's behalf; it arrives through the MCP protocol.
    async def call():
        async with Client(server) as client:
            return await client.call_tool("kb_search", {"query": "slow start", "k": 8, "session_id": SID})

    res = asyncio.run(call())
    assert not res.is_error
    assert "s1" in {c["chunk_id"] for c in res.structured_content["citations"]}
