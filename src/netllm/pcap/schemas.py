"""Tool output models. Conventions are part of the contract, because the LLM reads these values.

- Packet numbers are 1-based and equal Wireshark's frame.number.
- Timestamps are seconds as float. `ts` is epoch (UTC); `rel_ts` is relative to the first packet.
- Byte counts are frame lengths on the wire (frame.len), not payload sizes.
- A flow is bidirectional. src is the endpoint that sent the first packet seen.
- Lists are truncated to `limit`; `truncated` says whether more existed.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class CaptureInfo(BaseModel):
    id: str = Field(description="Value to pass as `capture` to the other tools")
    description: str


class CaptureList(BaseModel):
    captures: list[CaptureInfo]


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


# --- Computed TCP facts (tcp_analysis.py). Sequence numbers here are RELATIVE: first data byte = 1.

class TcpSegment(BaseModel):
    number: int
    rel_ts: float
    seq: int = Field(description="Relative sequence number of the segment's first byte (first data byte = 1)")
    len: int = Field(description="TCP payload bytes")
    retransmission: bool = Field(description="Starts below the highest byte already sent")
    acked_by: int | None = Field(None, description="Frame of the first ACK covering the whole segment")
    ack_rel_ts: float | None = None
    sample_rtt: float | None = Field(
        None, description="ack_rel_ts - rel_ts, seconds. None if unacknowledged, or if these bytes were "
                          "retransmitted (Karn's rule: the ACK could be for either copy)")
    ack_advance: int | None = Field(
        None, description="Bytes newly acknowledged by that ACK: one full segment (e.g. 1448) means every "
                          "segment is ACKed; two segments' worth means a delayed ACK")


class TcpSegmentList(BaseModel):
    stream: int
    sender: str
    sender_port: int
    receiver: str
    receiver_port: int
    segments: list[TcpSegment] = Field(description="Data segments from sender, in capture order")
    total: int
    truncated: bool


class TcpDirectionStats(BaseModel):
    sender: str
    sender_port: int
    packets: int = Field(description="All packets this side sent")
    data_segments: int = Field(description="Packets with payload, retransmissions included")
    payload_bytes: int = Field(description="Unique payload bytes (highest byte sent - first byte); "
                                           "retransmitted bytes counted once")
    bytes_sent: int = Field(description="Payload bytes put on the wire, retransmissions included")
    retransmissions: int
    duplicate_acks: int = Field(description="Duplicate ACKs this side sent (it is missing the other side's data)")
    mss: int | None = Field(None, description="MSS option this side announced in its SYN")
    window_min: int | None = Field(None, description="Smallest receive window this side advertised, in bytes, "
                                                     "scaled (SYN segments are never scaled)")
    window_min_packet: int | None = None
    window_max: int | None = Field(None, description="Largest advertised receive window, bytes, scaled")
    first_data_rel_ts: float | None = None
    last_byte_acked: bool = Field(description="The other side acknowledged the last payload byte")
    last_byte_ack_rel_ts: float | None = None
    transfer_duration: float | None = Field(
        None, description="Seconds from the first data segment to the ACK of the last byte "
                          "(to the last data segment if that ACK is missing)")
    throughput_bytes_per_s: float | None = Field(None, description="payload_bytes / transfer_duration")
    throughput_mbit_per_s: float | None = None


class TcpStreamStats(BaseModel):
    stream: int
    client: str
    client_port: int
    server: str
    server_port: int
    handshake_rtt: float | None = Field(None, description="SYN to SYN-ACK, seconds, at the capture point")
    window_scaling: bool | None = Field(
        None, description="Both sides offered window scaling; None if the handshake is not in the capture "
                          "(windows are then reported unscaled)")
    client_to_server: TcpDirectionStats
    server_to_client: TcpDirectionStats


class TcpFleet(BaseModel):
    index: int = Field(description="1-based, in time order")
    first_packet: int
    last_packet: int
    start_rel_ts: float
    end_rel_ts: float
    segments: int
    bytes: int = Field(description="Payload bytes in the fleet")


class TcpFleetList(BaseModel):
    stream: int
    sender: str
    sender_port: int
    rtt_used: float | None = Field(None, description="RTT used to split fleets, seconds")
    rtt_source: str = Field(description="'handshake' (SYN to SYN-ACK), 'samples' (median sample RTT) or 'none'")
    gap_threshold: float = Field(description="A pause longer than this (seconds; a third of the RTT) starts a "
                                         "new fleet. Later fleets blur once the sender is ACK-clocked")
    fleets: list[TcpFleet]
    total: int
    truncated: bool
    start_intervals: list[float] = Field(description="Seconds between the starts of consecutive fleets")
    median_period: float | None = Field(None, description="Median of start_intervals")
