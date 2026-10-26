"""PcapBackend with fixed outputs, for tool-calling smoke tests: no tshark, no file needed.

Values come from tcp-wireshark-trace1-1 (Kurose-Ross TCP lab), so follow-up answers stay plausible.
Outputs are built from the real schemas, so they match what the pyshark backend will return.
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
    TcpHandshake,
    TcpOptions,
)

CLIENT, SERVER = "192.168.86.68", "128.119.245.12"


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
