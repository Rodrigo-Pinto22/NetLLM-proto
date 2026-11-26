"""PcapBackend: the only thing tools.py knows about. Swap tshark for another decoder without touching tools."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from .schemas import (
    FilterResult,
    FlowList,
    PacketDetail,
    TcpFleetList,
    TcpHandshake,
    TcpSegmentList,
    TcpStreamStats,
)


class PcapBackend(ABC):
    def __init__(self, path: str | Path):
        self.path = Path(path)
        if not self.path.is_file():
            raise FileNotFoundError(self.path)

    @abstractmethod
    def list_flows(self, limit: int = 50) -> FlowList: ...

    @abstractmethod
    def packet_detail(self, number: int) -> PacketDetail: ...

    @abstractmethod
    def apply_filter(self, display_filter: str, limit: int = 50) -> FilterResult: ...

    @abstractmethod
    def tcp_handshake(self, stream: int) -> TcpHandshake: ...

    @abstractmethod
    def tcp_segments(self, stream: int, direction: str = "auto", limit: int = 50) -> TcpSegmentList: ...

    @abstractmethod
    def tcp_stream_stats(self, stream: int) -> TcpStreamStats: ...

    @abstractmethod
    def tcp_fleets(self, stream: int, direction: str = "auto", limit: int = 20) -> TcpFleetList: ...
