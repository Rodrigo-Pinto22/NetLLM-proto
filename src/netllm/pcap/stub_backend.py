"""PcapBackend with fixed outputs, for tool-calling smoke tests: no tshark, no file needed.

Values come from tcp-wireshark-trace1-1 (Kurose-Ross TCP lab), so follow-up answers stay plausible.
Outputs are built from the real schemas, so they have the same shape as the tshark backend's.
"""

from __future__ import annotations

from pathlib import Path

from .backend import PcapBackend
from .schemas import (
    FilterResult,
    Flow,
    FlowList,
    HandshakeSegment,
    Layer,
    PacketDetail,
    PacketSummary,
    TcpFleetList,
    TcpHandshake,
    TcpOptions,
    TcpSegmentList,
    TcpStreamStats,
)
from .tcp_analysis import ACK, SYN, Pkt, TcpStream

CLIENT, SERVER = "192.168.86.68", "128.119.245.12"
C_ISN, S_ISN = 4236649187, 1068969752


def _c(number, t, seq, length=0, window=2058, **kw):  # client -> server
    return Pkt(number=number, t=t, src=CLIENT, sport=55639, dst=SERVER, dport=80, seq=C_ISN + seq,
               ack=kw.pop("ack", S_ISN + 1), flags=kw.pop("flags", ACK), length=length, window=window, **kw)


def _s(number, t, ack, window, **kw):  # server -> client (ACKs)
    return Pkt(number=number, t=t, src=SERVER, sport=80, dst=CLIENT, dport=55639, seq=kw.pop("seq", S_ISN + 1),
               ack=C_ISN + ack, flags=kw.pop("flags", ACK), length=0, window=window, **kw)


# Packets from the first 13 frames of the trace: handshake, a fleet of 3, their ACKs, a second fleet.
_PACKETS = [
    _c(1, 0.0, 0, window=65535, ack=None, flags=SYN, mss=1460, wscale=6, sack_perm=True, timestamps=True),
    _s(2, 0.022414, 1, 28960, seq=S_ISN, flags=SYN | ACK, mss=1460, wscale=7, sack_perm=True, timestamps=True),
    _c(3, 0.022505, 1, timestamps=True),
    _c(4, 0.024047, 1, 1448), _c(5, 0.024048, 1449, 1448), _c(6, 0.024049, 2897, 1448),
    _s(7, 0.052671, 1449, 249), _s(8, 0.052676, 2897, 272),
    _c(9, 0.052770, 4345, 1448), _c(10, 0.052771, 5793, 1448),
    _s(13, 0.052980, 4345, 295),
]


class StubBackend(PcapBackend):
    def __init__(self, path: str | Path = "stub.pcap"):
        self.path = Path(path)  # never opened

    def list_flows(self, limit: int = 50) -> FlowList:
        flow = Flow(flow_id=0, protocol="TCP", src=CLIENT, src_port=55639, dst=SERVER, dst_port=80,
                    packets=180, bytes=166102, first_packet=1, start_rel_ts=0.0, duration=0.192732)
        return FlowList(flows=[flow][:limit], total=1, truncated=limit < 1)

    def packet_detail(self, number: int) -> PacketDetail:
        return PacketDetail(
            number=number, ts=1612320206.716922, rel_ts=0.024047, length=1514,
            summary="55639 → 80 [ACK] Seq=1 Ack=1 Win=131712 Len=1448",
            layers=[
                Layer(name="eth", fields={"eth.type": "0x0800"}),
                Layer(name="ip", fields={"ip.src": CLIENT, "ip.dst": SERVER, "ip.ttl": "64", "ip.len": "1500"}),
                Layer(name="tcp", fields={"tcp.stream": "0", "tcp.srcport": "55639", "tcp.dstport": "80",
                                          "tcp.seq_raw": "4236649188", "tcp.ack_raw": "1068969753",
                                          "tcp.flags": "0x0010", "tcp.hdr_len": "32", "tcp.len": "1448",
                                          "tcp.window_size_value": "2058"}),
            ],
        )

    def apply_filter(self, display_filter: str, limit: int = 50) -> FilterResult:
        packets = [
            PacketSummary(number=1, rel_ts=0.0, src=CLIENT, dst=SERVER, protocol="TCP", length=78,
                          summary="55639 → 80 [SYN] Seq=0 Win=65535 Len=0 MSS=1460 WS=64 SACK_PERM"),
            PacketSummary(number=2, rel_ts=0.022414, src=SERVER, dst=CLIENT, protocol="TCP", length=74,
                          summary="80 → 55639 [SYN, ACK] Seq=0 Ack=1 Win=28960 Len=0 MSS=1460 SACK_PERM WS=128"),
        ]
        return FilterResult(display_filter=display_filter, packets=packets[:limit], total=2, truncated=limit < 2)

    def tcp_handshake(self, stream: int) -> TcpHandshake:
        return TcpHandshake(
            stream=stream, client=CLIENT, client_port=55639, server=SERVER, server_port=80,
            syn=HandshakeSegment(number=1, rel_ts=0.0, seq=4236649187, flags="SYN", window=65535,
                                 options=TcpOptions(mss=1460, window_scale=6, sack_permitted=True, timestamps=True)),
            syn_ack=HandshakeSegment(number=2, rel_ts=0.022414, seq=1068969752, ack=4236649188, flags="SYN,ACK",
                                     window=28960, options=TcpOptions(mss=1460, window_scale=7, sack_permitted=True,
                                                                      timestamps=True)),
            ack=HandshakeSegment(number=3, rel_ts=0.022505, seq=4236649188, ack=1068969753, flags="ACK",
                                 window=2058, options=TcpOptions(timestamps=True)),
            complete=True,
            rtt=0.022414,
        )

    # The computed tools run the real analysis on the fixed packets above, so their output is
    # consistent with each other and has exactly the real shape.
    def tcp_segments(self, stream: int, direction: str = "auto", limit: int = 50) -> TcpSegmentList:
        return TcpStream(stream, _PACKETS).segments(direction, limit)

    def tcp_stream_stats(self, stream: int) -> TcpStreamStats:
        return TcpStream(stream, _PACKETS).stats()

    def tcp_fleets(self, stream: int, direction: str = "auto", limit: int = 20) -> TcpFleetList:
        return TcpStream(stream, _PACKETS).fleets(direction, limit)
