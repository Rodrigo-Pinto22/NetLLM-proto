"""Tool functions exposed to the LLM (via MCP and the own agent loop).

Docstrings are the tool descriptions the model sees: keep them short and precise. The `Args:`
section becomes the per-argument descriptions (Ollama parses it; MCP shows the whole docstring).
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
    """List the conversations (flows) in a capture, largest first, with endpoints, packet and byte counts.

    Args:
        pcap_path: Path to the .pcap/.pcapng file.
        limit: Maximum number of flows to return.
    """
    return _backend(pcap_path).list_flows(limit).model_dump()


def packet_detail(pcap_path: str, number: int) -> dict:
    """Show all decoded layers and fields of one packet.

    Args:
        pcap_path: Path to the .pcap/.pcapng file.
        number: 1-based Wireshark frame number (the No. column).
    """
    return _backend(pcap_path).packet_detail(number).model_dump()


def apply_filter(pcap_path: str, display_filter: str, limit: int = 50) -> dict:
    """Return a one-line summary of each packet matching a Wireshark display filter.

    Args:
        pcap_path: Path to the .pcap/.pcapng file.
        display_filter: Wireshark display filter, e.g. 'tcp.flags.syn == 1' or 'tcp.analysis.retransmission'.
        limit: Maximum number of packets to return.
    """
    return _backend(pcap_path).apply_filter(display_filter, limit).model_dump()


def tcp_handshake(pcap_path: str, stream: int) -> dict:
    """Show the three-way handshake of one TCP connection: raw seq/ack numbers, flags, windows, options, RTT.

    Args:
        pcap_path: Path to the .pcap/.pcapng file.
        stream: TCP stream index (tcp.stream), as returned in flow_id by list_flows.
    """
    return _backend(pcap_path).tcp_handshake(stream).model_dump()


TOOLS = [list_flows, packet_detail, apply_filter, tcp_handshake]
