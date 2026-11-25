"""Tool functions exposed to the LLM (via MCP and the own agent loop).

Docstrings are the tool descriptions the model sees: keep them short and precise. The `Args:`
section becomes the per-argument descriptions (Ollama parses it; MCP shows the whole docstring).
Each tool returns a JSON-able dict validated by a schema in schemas.py.

Captures are named by id (configs/captures.yaml), never by path (ADR 0013).
"""

from __future__ import annotations

from functools import lru_cache

from netllm.config import get_settings

from .backend import PcapBackend
from .captures import CaptureCatalog
from .schemas import CaptureInfo, CaptureList
from .stub_backend import StubBackend
from .tshark_backend import TsharkBackend


@lru_cache(maxsize=1)
def _catalog() -> CaptureCatalog:
    s = get_settings()
    return CaptureCatalog.load(s.captures_file, s.captures_dir)


@lru_cache(maxsize=8)
def _backend(capture: str) -> PcapBackend:
    # NETLLM_PCAP_BACKEND=stub serves fixed outputs (no tshark, no file), for smoke tests.
    s = get_settings()
    if s.pcap_backend == "stub":
        return StubBackend(capture)
    return TsharkBackend(_catalog().resolve(capture), tshark=s.tshark_path)


def list_captures() -> dict:
    """List the packet captures available for analysis, with the id to use as `capture` in the other tools."""
    return CaptureList(captures=[CaptureInfo(id=c.id, description=c.description)
                                 for c in _catalog().list()]).model_dump()


def list_flows(capture: str, limit: int = 50) -> dict:
    """List the conversations (flows) in a capture, largest first, with endpoints, packet and byte counts.

    Args:
        capture: Capture id, as returned by list_captures (e.g. 'tcp-trace1').
        limit: Maximum number of flows to return.
    """
    return _backend(capture).list_flows(limit).model_dump()


def packet_detail(capture: str, number: int) -> dict:
    """Show all decoded layers and fields of one packet.

    Args:
        capture: Capture id, as returned by list_captures (e.g. 'tcp-trace1').
        number: 1-based Wireshark frame number (the No. column).
    """
    return _backend(capture).packet_detail(number).model_dump()


def apply_filter(capture: str, display_filter: str, limit: int = 50) -> dict:
    """Return a one-line summary of each packet matching a Wireshark display filter.

    Args:
        capture: Capture id, as returned by list_captures (e.g. 'tcp-trace1').
        display_filter: Wireshark display filter, e.g. 'tcp.flags.syn == 1' or 'tcp.analysis.retransmission'.
        limit: Maximum number of packets to return.
    """
    return _backend(capture).apply_filter(display_filter, limit).model_dump()


def tcp_handshake(capture: str, stream: int) -> dict:
    """Show the three-way handshake of one TCP connection: raw seq/ack numbers, flags, windows, options, RTT.

    Args:
        capture: Capture id, as returned by list_captures (e.g. 'tcp-trace1').
        stream: TCP stream index (tcp.stream), as returned in flow_id by list_flows.
    """
    return _backend(capture).tcp_handshake(stream).model_dump()


# Tools that read one capture (each wraps the PcapBackend method of the same name).
PCAP_TOOLS = [list_flows, packet_detail, apply_filter, tcp_handshake]
TOOLS = [list_captures, *PCAP_TOOLS]
