"""tcp_analysis on small hand-made connections: no tshark needed.

Client 10.0.0.1:1000 sends 100-byte segments to server 10.0.0.2:80. Helpers take RELATIVE
seq/ack numbers (first data byte = 1) and turn them into raw ones, so the tests read like a trace.
"""

import pytest

from netllm.pcap.tcp_analysis import ACK, SEQ_MOD, SYN, Pkt, TcpStream, flag_names

C, S = ("10.0.0.1", 1000), ("10.0.0.2", 80)
C_ISN, S_ISN = 1000, 5000


def c(n, t, seq, length=0, ack=1, flags=ACK, window=100, isn=C_ISN, **kw):
    return Pkt(number=n, t=t, src=C[0], sport=C[1], dst=S[0], dport=S[1], seq=(isn + seq) % SEQ_MOD,
               ack=None if ack is None else S_ISN + ack, flags=flags, length=length, window=window, **kw)


def s(n, t, ack, seq=1, length=0, flags=ACK, window=100, c_isn=C_ISN, **kw):
    return Pkt(number=n, t=t, src=S[0], sport=S[1], dst=C[0], dport=C[1], seq=S_ISN + seq,
               ack=(c_isn + ack) % SEQ_MOD, flags=flags, length=length, window=window, **kw)


def handshake(ws_c=2, ws_s=3, isn=C_ISN):
    return [c(1, 0.000, 0, ack=None, flags=SYN, window=1000, mss=1460, wscale=ws_c, sack_perm=True, isn=isn),
            s(2, 0.010, 1, seq=0, flags=SYN | ACK, window=2000, mss=1400, wscale=ws_s, c_isn=isn),
            c(3, 0.011, 1, isn=isn)]


# Three segments; the first ACKed alone, the next two by one delayed ACK.
DELAYED = handshake() + [c(4, 0.020, 1, 100), c(5, 0.021, 101, 100), c(6, 0.022, 201, 100),
                         s(7, 0.030, 101), s(8, 0.040, 301)]


def test_flag_names():
    assert flag_names(SYN) == "SYN"
    assert flag_names(SYN | ACK) == "SYN,ACK"
    assert flag_names(0x11) == "FIN,ACK"


def test_empty_stream():
    with pytest.raises(ValueError, match="no TCP stream 7"):
        TcpStream(7, [])


def test_handshake():
    hs = TcpStream(0, DELAYED).handshake()
    assert (hs.client, hs.client_port, hs.server, hs.server_port) == (*C, *S)
    assert [hs.syn.number, hs.syn_ack.number, hs.ack.number] == [1, 2, 3]
    assert hs.syn.flags == "SYN" and hs.syn.ack is None and hs.syn_ack.flags == "SYN,ACK"
    assert hs.complete
    assert hs.rtt == pytest.approx(0.010)


def test_without_handshake_the_first_sender_is_the_client():
    t = TcpStream(0, [c(10, 1.0, 1, 100), s(11, 1.1, 101)])
    assert t.client == C and t.window_scaling is None and t.rtt is None
    rows = t.segment_rows(C)
    assert rows[0].seq == 1 and rows[0].acked_by == 11


def test_segments_rtt_and_delayed_ack():
    r = TcpStream(0, DELAYED).segments("client")
    assert [x.number for x in r.segments] == [4, 5, 6]
    assert [x.seq for x in r.segments] == [1, 101, 201]
    assert [x.acked_by for x in r.segments] == [7, 8, 8]
    assert [x.ack_advance for x in r.segments] == [100, 200, 200]  # 200 = two segments: delayed ACK
    assert [x.sample_rtt for x in r.segments] == pytest.approx([0.010, 0.019, 0.018])
    assert r.total == 3 and not r.truncated
    assert TcpStream(0, DELAYED).segments("client", limit=1).truncated


def test_retransmission_has_no_rtt_sample():
    pkts = handshake() + [c(4, 0.020, 1, 100), c(5, 0.050, 1, 100), s(6, 0.060, 101)]
    rows = TcpStream(0, pkts).segment_rows(C)
    assert [x.retransmission for x in rows] == [False, True]
    assert [x.acked_by for x in rows] == [6, 6]
    assert [x.sample_rtt for x in rows] == [None, None]  # Karn: either copy could be the one ACKed


def test_sequence_numbers_wrap_around():
    isn = SEQ_MOD - 50  # data crosses 2**32
    pkts = handshake(isn=isn) + [c(4, 0.02, 1, 100, isn=isn), c(5, 0.021, 101, 100, isn=isn),
                                 s(6, 0.03, 201, c_isn=isn)]
    rows = TcpStream(0, pkts).segment_rows(C)
    assert [x.seq for x in rows] == [1, 101]
    assert [x.acked_by for x in rows] == [6, 6]


def test_stats():
    st = TcpStream(0, DELAYED).stats()
    up, down = st.client_to_server, st.server_to_client
    assert (up.payload_bytes, up.bytes_sent, up.data_segments) == (300, 300, 3)
    assert up.first_data_rel_ts == 0.020 and up.last_byte_acked and up.last_byte_ack_rel_ts == 0.040
    assert up.transfer_duration == pytest.approx(0.020)
    assert up.throughput_bytes_per_s == pytest.approx(15000)
    assert up.throughput_mbit_per_s == pytest.approx(0.12)
    assert (up.mss, down.mss) == (1460, 1400)
    # Scaling on: client x4 (shift 2), server x8 (shift 3); SYN windows are never scaled.
    assert st.window_scaling is True
    assert (up.window_min, up.window_min_packet, up.window_max) == (400, 3, 1000)
    assert (down.window_min, down.window_min_packet, down.window_max) == (800, 7, 2000)
    assert up.retransmissions == 0 and down.duplicate_acks == 0
    assert down.payload_bytes == 0 and down.throughput_bytes_per_s is None


def test_window_not_scaled_unless_both_sides_offer_it():
    st = TcpStream(0, handshake(ws_s=None) + [s(4, 0.02, 1)]).stats()
    assert st.window_scaling is False
    assert st.server_to_client.window_min == 100


def test_duplicate_acks():
    pkts = handshake() + [c(4, 0.020, 1, 100), c(5, 0.021, 101, 100), c(6, 0.022, 201, 100),
                          s(7, 0.030, 101), s(8, 0.031, 101), s(9, 0.032, 101)]
    assert TcpStream(0, pkts).stats().server_to_client.duplicate_acks == 2


def test_fleets():
    # Handshake RTT 10 ms -> a pause over 3.33 ms starts a new fleet.
    times = [0.0200, 0.0201, 0.0202, 0.0300, 0.0301, 0.0400]
    pkts = handshake() + [c(4 + i, t, 1 + 100 * i, 100) for i, t in enumerate(times)]
    f = TcpStream(0, pkts).fleets()
    assert (f.rtt_used, f.rtt_source) == (0.010, "handshake")
    assert f.gap_threshold == pytest.approx(0.010 / 3, abs=1e-6)
    assert [x.segments for x in f.fleets] == [3, 2, 1]
    assert [x.first_packet for x in f.fleets] == [4, 7, 9]
    assert [x.bytes for x in f.fleets] == [300, 200, 100]
    assert f.start_intervals == pytest.approx([0.010, 0.010])
    assert f.median_period == pytest.approx(0.010)


def test_direction():
    pkts = handshake() + [c(4, 0.02, 1, 10), s(5, 0.03, 11, seq=1, length=500)]
    t = TcpStream(0, pkts)
    assert t.sender_for("auto") == S  # the server sent more data
    assert t.segments("auto").sender == S[0]
    with pytest.raises(ValueError, match="direction must be"):
        t.segments("upload")
