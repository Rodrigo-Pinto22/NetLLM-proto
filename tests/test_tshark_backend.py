"""TsharkBackend against the real Kurose-Ross TCP trace.

Expected values come from questions/v0.2.yaml (expected_facts), so the question set doubles as the
ground truth for the tools. Tests that need tshark or the trace are skipped when either is missing.
"""

import shutil

import pytest

from netllm.config import ROOT
from netllm.pcap.tshark_backend import TsharkBackend, TsharkError, _flag_names, _flatten

TRACE = ROOT / "data" / "traces" / "tcp-wireshark-trace1-1.pcapng"
CLIENT, SERVER = "192.168.86.68", "128.119.245.12"

needs_tshark = pytest.mark.skipif(shutil.which("tshark") is None or not TRACE.is_file(),
                                  reason="needs tshark on PATH and the TCP trace in data/traces/")


# ------------------------------------------------------------ helpers (no tshark needed)
def test_flag_names():
    assert _flag_names(0x02) == "SYN"
    assert _flag_names(0x12) == "SYN,ACK"
    assert _flag_names(0x11) == "FIN,ACK"
    assert _flag_names(0x18) == "PSH,ACK"


def test_flatten_keeps_field_names_and_walks_subtrees():
    layer = {
        "tcp.srcport": "55639",
        "tcp.flags": "0x0012",
        "tcp.flags_tree": {"tcp.flags.syn": "1", "tcp.flags.ack": "1"},
        "Timestamps": {"tcp.time_relative": "0.0"},     # text label: skipped, children kept
        "tcp.option_kind": ["2", "4", "8"],              # repeated field
        "tcp.payload": "ab:" * 500,                      # long value: clipped
    }
    out = _flatten(layer)
    assert out["tcp.srcport"] == "55639"
    assert out["tcp.flags.syn"] == "1"
    assert out["tcp.time_relative"] == "0.0"
    assert out["tcp.option_kind"] == "2, 4, 8"
    assert "Timestamps" not in out
    assert len(out["tcp.payload"]) <= 201


# ------------------------------------------------------------ real trace
@pytest.fixture(scope="module")
def backend():
    return TsharkBackend(TRACE)


@pytest.fixture(scope="module")
def upload_flow(backend):
    """The connection that uploads alice.txt (tcp-endpoints-01)."""
    flows = backend.list_flows(limit=1000).flows
    matches = [f for f in flows if f.protocol == "TCP" and {(f.src, f.src_port), (f.dst, f.dst_port)}
               == {(CLIENT, 55639), (SERVER, 80)}]
    assert len(matches) == 1
    return matches[0]


@needs_tshark
def test_list_flows(backend, upload_flow):
    flows = backend.list_flows(limit=1000)
    assert [f.bytes for f in flows.flows] == sorted((f.bytes for f in flows.flows), reverse=True)
    assert (upload_flow.src, upload_flow.src_port) == (CLIENT, 55639)  # the client spoke first
    assert upload_flow.first_packet == 1
    assert backend.list_flows(limit=0).flows == []


@needs_tshark
def test_tcp_handshake(backend, upload_flow):
    hs = backend.tcp_handshake(upload_flow.flow_id)
    assert (hs.client, hs.client_port, hs.server, hs.server_port) == (CLIENT, 55639, SERVER, 80)
    # tcp-syn-01
    assert hs.syn.number == 1 and hs.syn.flags == "SYN" and hs.syn.ack is None
    assert hs.syn.seq == 4236649187
    assert hs.syn.options.sack_permitted
    # tcp-synack-01
    assert hs.syn_ack.number == 2 and hs.syn_ack.flags == "SYN,ACK"
    assert hs.syn_ack.seq == 1068969752
    assert hs.syn_ack.ack == 4236649188
    assert hs.syn_ack.options.sack_permitted
    # tcp-rwnd-01: 28960 unscaled in the SYN-ACK, scale 7
    assert hs.syn_ack.window == 28960
    assert hs.syn_ack.options.window_scale == 7
    assert hs.ack.number == 3 and hs.ack.flags == "ACK"
    assert hs.complete
    assert 0 < hs.rtt < 0.1


@needs_tshark
def test_packet_detail_post_segment(backend):
    # tcp-post-seq-01 and tcp-segment-length-01: frame 4
    p = backend.packet_detail(4)
    assert p.number == 4
    assert p.length == 1514
    assert p.rel_ts == pytest.approx(0.024047, abs=1e-6)
    tcp = next(layer for layer in p.layers if layer.name == "tcp").fields
    assert tcp["tcp.seq_raw"] == "4236649188"
    assert tcp["tcp.len"] == "1448"
    assert tcp["tcp.hdr_len"] == "32"
    assert all(len(layer.fields) <= 80 for layer in p.layers)


@needs_tshark
def test_first_data_segments(backend):
    # tcp-segment-length-01 and tcp-post-seq-01: frames 4, 5, 6, 9; 106 data segments in all
    r = backend.apply_filter(f"ip.src == {CLIENT} && tcp.len > 0", limit=4)
    assert [p.number for p in r.packets] == [4, 5, 6, 9]
    assert all(p.length == 1514 and p.src == CLIENT and p.dst == SERVER for p in r.packets)
    assert r.total == 106 and r.truncated


@needs_tshark
def test_no_retransmissions(backend):
    # tcp-retransmissions-01
    r = backend.apply_filter("tcp.analysis.retransmission")
    assert r.total == 0 and r.packets == [] and not r.truncated


@needs_tshark
def test_rtt_sample_frames(backend):
    # tcp-rtt-01: frame 7 acknowledges frame 4 at t = 0.052671 s
    r = backend.apply_filter("frame.number == 7")
    assert r.packets[0].rel_ts == pytest.approx(0.052671, abs=1e-6)


@needs_tshark
def test_errors_are_readable(backend):
    with pytest.raises(TsharkError):
        backend.apply_filter("tcp.this_field_does_not_exist == 1")
    with pytest.raises(TsharkError, match="no frame"):
        backend.packet_detail(999999)
    with pytest.raises(TsharkError, match="no TCP stream"):
        backend.tcp_handshake(999999)
