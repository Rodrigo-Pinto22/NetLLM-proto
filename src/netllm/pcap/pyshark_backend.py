"""PcapBackend over pyshark (needs `tshark` on PATH)."""

from __future__ import annotations

from .backend import PcapBackend
from .schemas import FilterResult, FlowList, PacketDetail, TcpHandshake


class PysharkBackend(PcapBackend):
    def list_flows(self, limit: int = 50) -> FlowList:
        raise NotImplementedError

    def packet_detail(self, number: int) -> PacketDetail:
        raise NotImplementedError

    def apply_filter(self, display_filter: str, limit: int = 50) -> FilterResult:
        raise NotImplementedError

    def tcp_handshake(self, stream: int) -> TcpHandshake:
        raise NotImplementedError
