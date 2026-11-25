from __future__ import annotations

from pydantic import BaseModel, Field

from netllm.pcap.schemas import CaptureList


class ChromaCheck(BaseModel):
    heartbeat: int = Field(description="Chroma server heartbeat (nanosecond timestamp)")
    top_id: str = Field(description="Id of the nearest vector to the smoke query; 'smoke' when the round-trip works")


class SmokeResult(BaseModel):
    mcp: CaptureList | None = Field(description="Result of the list_captures tool called on the mcp service")
    trace_event_id: int | None = Field(description="Id of the row written to session.trace_events")
    chroma: ChromaCheck
