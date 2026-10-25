"""Tool output models. Conventions are part of the contract, because the LLM reads these values.

- Packet numbers are 1-based and equal Wireshark's frame.number.
- Timestamps are seconds as float. `ts` is epoch (UTC); `rel_ts` is relative to the first packet.
- Byte counts are frame lengths on the wire (frame.len), not payload sizes.
- A flow is bidirectional. src is the endpoint that sent the first packet seen.
- Lists are truncated to `limit`; `truncated` says whether more existed.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class Flow(BaseModel):
    flow_id: int = Field(description="Stable within one capture, e.g. tcp.stream / udp.stream")
    protocol: str = Field(description="Transport protocol: TCP, UDP, ...")
    src: str
    src_port: int | None = None
    dst: str
    dst_port: int | None = None
    packets: int
    bytes: int
    first_packet: int
    start_rel_ts: float
    duration: float


class FlowList(BaseModel):
    flows: list[Flow]
    total: int
    truncated: bool


class Layer(BaseModel):
    name: str = Field(description="Wireshark layer name, e.g. ip, tcp, dns")
    fields: dict[str, str]


class PacketDetail(BaseModel):
    number: int
    ts: float
    rel_ts: float
    length: int
    summary: str = Field(description="Wireshark Info column")
    layers: list[Layer]


class PacketSummary(BaseModel):
    number: int
    rel_ts: float
    src: str | None
    dst: str | None
    protocol: str
    length: int
    summary: str


class FilterResult(BaseModel):
    display_filter: str
    packets: list[PacketSummary]
    total: int
    truncated: bool


class TcpOptions(BaseModel):
    mss: int | None = None
    window_scale: int | None = Field(None, description="Shift count; the multiplier is 2**window_scale")
    sack_permitted: bool = False
    timestamps: bool = False


class HandshakeSegment(BaseModel):
    number: int
    rel_ts: float
    seq: int = Field(description="Raw (absolute) sequence number, not Wireshark's relative one")
    ack: int | None = Field(None, description="Raw acknowledgement number; None when the ACK flag is clear")
    flags: str = Field(description="Set flags, e.g. 'SYN', 'SYN,ACK', 'ACK'")
    window: int = Field(description="Window field as sent; never scaled in SYN segments")
    options: TcpOptions


class TcpHandshake(BaseModel):
    stream: int = Field(description="tcp.stream, same as Flow.flow_id for TCP flows")
    client: str
    client_port: int
    server: str
    server_port: int
    syn: HandshakeSegment | None
    syn_ack: HandshakeSegment | None
    ack: HandshakeSegment | None
    complete: bool = Field(description="All three segments seen, with matching seq/ack numbers")
    rtt: float | None = Field(None, description="SYN to SYN-ACK time in seconds, measured at the capture point")
