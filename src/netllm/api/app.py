"""Tutor API. For now only health and a stack smoke test; the agent loop comes later.

Run: uvicorn netllm.api.app:app --port 8080
"""

from __future__ import annotations

import asyncio

import chromadb
import psycopg
from fastapi import FastAPI
from fastmcp import Client
from psycopg.types.json import Jsonb

from netllm.config import get_settings

app = FastAPI(title="NetLLM")


@app.get("/health")
def health() -> dict:
    """Liveness only: the process is up. Dependencies are checked by /smoke."""
    return {"status": "ok"}


@app.post("/smoke")
async def smoke() -> dict:
    """End-to-end check: call a tool on mcp, write a trace event to postgres, query chroma."""
    s = get_settings()

    args = {"pcap_path": "stub.pcap", "limit": 3}
    async with Client(s.mcp_url) as mcp:
        result = await mcp.call_tool("list_flows", args)
    flows = getattr(result, "structured_content", None)

    async with await psycopg.AsyncConnection.connect(s.database_url) as conn:
        cur = await conn.execute(
            "INSERT INTO session.trace_events (kind, payload) VALUES (%s, %s) RETURNING id",
            ("tool_call", Jsonb({"tool": "list_flows", "args": args, "ok": flows is not None})),
        )
        row = await cur.fetchone()

    chroma = await asyncio.to_thread(_chroma_roundtrip, s.chroma_host, s.chroma_port)

    return {"mcp": flows, "trace_event_id": row[0] if row else None, "chroma": chroma}


def _chroma_roundtrip(host: str, port: int) -> dict:
    # Explicit embeddings and no embedding function, so the smoke test needs no embedding model.
    client = chromadb.HttpClient(host=host, port=port)
    col = client.get_or_create_collection("netllm_smoke", embedding_function=None)
    col.upsert(ids=["smoke"], embeddings=[[1.0, 0.0, 0.0]], documents=["smoke"])
    hit = col.query(query_embeddings=[[1.0, 0.0, 0.0]], n_results=1)
    return {"heartbeat": client.heartbeat(), "top_id": hit["ids"][0][0]}
