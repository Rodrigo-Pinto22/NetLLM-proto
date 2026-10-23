"""Tool functions exposed to the LLM (via MCP and the own agent loop).

Docstrings are the tool descriptions the model sees: keep them short and precise.
Each tool returns a JSON-able dict validated by a schema in schemas.py.
"""

from __future__ import annotations

from functools import lru_cache

from .backend import PcapBackend
from .pyshark_backend import PysharkBackend


@lru_cache(maxsize=8)
def _backend(pcap_path: str) -> PcapBackend:
    return PysharkBackend(pcap_path)


def list_flows(pcap_path: str, limit: int = 50) -> dict:
    """List the conversations (flows) in a capture, largest first."""
    return _backend(pcap_path).list_flows(limit).model_dump()


def packet_detail(pcap_path: str, number: int) -> dict:
    """Show all decoded layers and fields of one packet (1-based Wireshark frame number)."""
    return _backend(pcap_path).packet_detail(number).model_dump()


def apply_filter(pcap_path: str, display_filter: str, limit: int = 50) -> dict:
    """Return packets matching a Wireshark display filter, e.g. 'tcp.flags.syn == 1'."""
    return _backend(pcap_path).apply_filter(display_filter, limit).model_dump()


TOOLS = [list_flows, packet_detail, apply_filter]
