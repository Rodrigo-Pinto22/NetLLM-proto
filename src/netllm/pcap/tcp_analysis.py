"""TCP analysis of one stream, in plain Python (ADR 0008: the code computes, the model explains).

The backend reads the packets of a stream (tshark) into `Pkt`s; everything here works on those, so
it is unit-tested on hand-made packets and checked against the real trace separately.

Definitions (also stated in the schema field descriptions, because the model reads them):
- Client = the side that sent the SYN. Without a SYN, the receiver of the SYN-ACK, else the sender
  of the first packet.
- Relative sequence/ack numbers count from each side's ISN, so the first data byte is 1 (as in
  Wireshark). Without a SYN, the first byte seen from a side is 1.
- Windows are scaled (value << shift) only when both SYN and SYN-ACK carried the window-scale
  option, and never in SYN segments.
- Retransmission = a data segment that starts below the highest byte already sent.
- Sample RTT = first ACK that covers the whole segment, minus the send time. None for any segment
  whose bytes were retransmitted (Karn's rule: the ACK could be for either copy).
- Throughput = unique payload bytes / (first data segment -> first ACK of the last byte).
- Fleet = consecutive data segments from one side with no pause longer than a third of the RTT.
  Pauses inside a burst are short, pauses between bursts close to a round trip; but once the
  window is large the sender is nearly continuous (in the Kurose-Ross trace: 5.1 ms inside a
  burst, 10.6 ms between bursts, RTT 22.4 ms), so the threshold sits well below RTT/2.
"""

from __future__ import annotations

from bisect import bisect_left, bisect_right
from dataclasses import dataclass, field
from itertools import pairwise
from statistics import median

from .schemas import (
    HandshakeSegment,
    TcpDirectionStats,
    TcpFleet,
    TcpFleetList,
    TcpHandshake,
    TcpOptions,
    TcpSegment,
    TcpSegmentList,
    TcpStreamStats,
)

FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
# Order in which flags are written: 'SYN,ACK', 'FIN,ACK', 'PSH,ACK'.
FLAG_ORDER = [("SYN", SYN), ("FIN", FIN), ("RST", RST), ("PSH", PSH), ("URG", URG), ("ACK", ACK)]
SEQ_MOD = 2**32          # sequence numbers wrap around
DEFAULT_FLEET_GAP = 0.010  # seconds, when no RTT is known

Endpoint = tuple[str, int]


def flag_names(bits: int) -> str:
    return ",".join(name for name, bit in FLAG_ORDER if bits & bit)


@dataclass(frozen=True)
class Pkt:
    """One TCP segment, as read from the capture. seq/ack are raw (absolute) numbers."""

    number: int
    t: float                 # seconds since the first packet of the capture
    src: str
    sport: int
    dst: str
    dport: int
    seq: int
    ack: int | None          # None when the ACK flag is clear
    flags: int
    length: int              # TCP payload bytes
    window: int              # window field as sent (not scaled)
    mss: int | None = None
    wscale: int | None = None
    sack_perm: bool = False
    timestamps: bool = False

    @property
    def sender(self) -> Endpoint:
        return (self.src, self.sport)

    @property
    def receiver(self) -> Endpoint:
        return (self.dst, self.dport)

    def has(self, bit: int) -> bool:
        return bool(self.flags & bit)


@dataclass
class _AckIndex:
    """The ACKs one side sent, with the running highest relative ack after each."""

    acks: list[Pkt] = field(default_factory=list)
    numbers: list[int] = field(default_factory=list)
    highest: list[int] = field(default_factory=list)
    advance: dict[int, int] = field(default_factory=dict)  # frame -> bytes newly acknowledged


class TcpStream:
    def __init__(self, stream: int, pkts: list[Pkt]):
        if not pkts:
            raise ValueError(f"There is no TCP stream {stream} in this capture (use flow_id from list_flows)")
        self.stream = stream
        self.pkts = pkts
        self._orient()
        self.base = {self.client: self._isn(self.client, self.syn),
                     self.server: self._isn(self.server, self.syn_ack)}
        if self.syn is None or self.syn_ack is None:
            self.window_scaling: bool | None = None  # unknown: the handshake was not captured
        else:
            self.window_scaling = self.syn.wscale is not None and self.syn_ack.wscale is not None
        self.shift = {self.client: self.syn.wscale if self.window_scaling else 0,
                      self.server: self.syn_ack.wscale if self.window_scaling else 0}

    # ------------------------------------------------------------------ basics
    def _orient(self) -> None:
        pkts = self.pkts

        def first(pred, after: int = -1) -> int | None:
            return next((i for i, p in enumerate(pkts) if i > after and pred(p)), None)

        i_syn = first(lambda p: p.has(SYN) and not p.has(ACK))
        i_sa = first(lambda p: p.has(SYN) and p.has(ACK), after=-1 if i_syn is None else i_syn)
        if i_syn is not None:
            self.client, self.server = pkts[i_syn].sender, pkts[i_syn].receiver
        elif i_sa is not None:
            self.client, self.server = pkts[i_sa].receiver, pkts[i_sa].sender
        else:
            self.client, self.server = pkts[0].sender, pkts[0].receiver
        i_ack = None
        if i_sa is not None:
            i_ack = first(lambda p: p.sender == self.client and p.has(ACK) and not p.has(SYN), after=i_sa)
        self.syn = pkts[i_syn] if i_syn is not None else None
        self.syn_ack = pkts[i_sa] if i_sa is not None else None
        self.ack3 = pkts[i_ack] if i_ack is not None else None
        syn, sa, ack = self.syn, self.syn_ack, self.ack3
        self.complete = bool(syn and sa and ack
                             and sa.ack == (syn.seq + 1) % SEQ_MOD
                             and ack.seq == (syn.seq + 1) % SEQ_MOD
                             and ack.ack == (sa.seq + 1) % SEQ_MOD)
        self.rtt = round(sa.t - syn.t, 6) if syn and sa else None

    def _isn(self, side: Endpoint, syn: Pkt | None) -> int:
        if syn is not None:
            return syn.seq
        first = next((p for p in self.pkts if p.sender == side), None)
        return (first.seq - 1) % SEQ_MOD if first else 0

    def other(self, side: Endpoint) -> Endpoint:
        return self.server if side == self.client else self.client

    def rel_seq(self, p: Pkt) -> int:
        return (p.seq - self.base[p.sender]) % SEQ_MOD

    def rel_ack(self, p: Pkt) -> int:
        return (p.ack - self.base[p.receiver]) % SEQ_MOD  # acknowledges the other side's bytes

    def scaled_window(self, p: Pkt) -> int:
        return p.window if p.has(SYN) else p.window << self.shift[p.sender]

    def sender_for(self, direction: str) -> Endpoint:
        if direction == "client":
            return self.client
        if direction == "server":
            return self.server
        if direction == "auto":  # the side that sent more payload; the client on a tie
            sent = {side: sum(p.length for p in self.pkts if p.sender == side)
                    for side in (self.client, self.server)}
            return self.server if sent[self.server] > sent[self.client] else self.client
        raise ValueError(f"direction must be 'auto', 'client' or 'server', got {direction!r}")

    # ------------------------------------------------------------------ handshake
    def handshake(self) -> TcpHandshake:
        def seg(p: Pkt | None) -> HandshakeSegment | None:
            if p is None:
                return None
            return HandshakeSegment(
                number=p.number, rel_ts=p.t, seq=p.seq, ack=p.ack, flags=flag_names(p.flags),
                window=p.window, options=TcpOptions(mss=p.mss, window_scale=p.wscale,
                                                    sack_permitted=p.sack_perm, timestamps=p.timestamps))

        return TcpHandshake(stream=self.stream, client=self.client[0], client_port=self.client[1],
                            server=self.server[0], server_port=self.server[1], syn=seg(self.syn),
                            syn_ack=seg(self.syn_ack), ack=seg(self.ack3), complete=self.complete,
                            rtt=self.rtt)

    # ------------------------------------------------------------------ segments (C1)
    def _ack_index(self, side: Endpoint) -> _AckIndex:
        idx, hi = _AckIndex(), 0
        for a in self.pkts:
            if a.sender != side or a.ack is None:
                continue
            r = self.rel_ack(a)
            idx.advance[a.number] = max(r - hi, 0)
            hi = max(hi, r)
            idx.acks.append(a)
            idx.numbers.append(a.number)
            idx.highest.append(hi)
        return idx

    @staticmethod
    def _covering_ack(idx: _AckIndex, after_frame: int, end: int) -> Pkt | None:
        """First ACK sent after `after_frame` whose running highest ack reaches `end`."""
        start = bisect_right(idx.numbers, after_frame)
        i = bisect_left(idx.highest, end, lo=start)  # `highest` never decreases
        return idx.acks[i] if i < len(idx.acks) else None

    def segment_rows(self, sender: Endpoint) -> list[TcpSegment]:
        idx = self._ack_index(self.other(sender))
        spans, retrans, hi = [], set(), None
        for p in self.pkts:
            if p.sender != sender or p.length == 0:
                continue
            s = self.rel_seq(p)
            e = s + p.length
            if hi is not None and s < hi:
                retrans.add(p.number)
            hi = e if hi is None else max(hi, e)
            spans.append((p, s, e))
        resent = [(s, e) for p, s, e in spans if p.number in retrans]

        rows = []
        for p, s, e in spans:
            a = self._covering_ack(idx, p.number, e)
            ambiguous = any(rs < e and s < re for rs, re in resent)  # Karn's rule
            rows.append(TcpSegment(
                number=p.number, rel_ts=p.t, seq=s, len=p.length, retransmission=p.number in retrans,
                acked_by=a.number if a else None, ack_rel_ts=a.t if a else None,
                sample_rtt=round(a.t - p.t, 6) if a and not ambiguous else None,
                ack_advance=idx.advance[a.number] if a else None))
        return rows

    def segments(self, direction: str = "auto", limit: int = 50) -> TcpSegmentList:
        sender = self.sender_for(direction)
        receiver = self.other(sender)
        rows = self.segment_rows(sender)
        return TcpSegmentList(stream=self.stream, sender=sender[0], sender_port=sender[1],
                              receiver=receiver[0], receiver_port=receiver[1],
                              segments=rows[:max(limit, 0)], total=len(rows), truncated=len(rows) > limit)

    # ------------------------------------------------------------------ stats (C2)
    def _direction_stats(self, sender: Endpoint) -> TcpDirectionStats:
        rows = self.segment_rows(sender)
        own = [p for p in self.pkts if p.sender == sender]
        syn = self.syn if sender == self.client else self.syn_ack

        # Duplicate ACK: a pure ACK repeating the previous ack number and window while the other
        # side still has unacknowledged data (Wireshark's rule, simplified).
        dups, prev, other_hi = 0, None, 0
        for p in self.pkts:
            if p.sender != sender:
                if p.length:
                    other_hi = max(other_hi, self.rel_seq(p) + p.length)
                continue
            if p.ack is None:
                continue
            r = self.rel_ack(p)
            pure = p.length == 0 and not p.flags & (SYN | FIN | RST)
            if pure and prev == (r, p.window) and r < other_hi:
                dups += 1
            prev = (r, p.window)

        windows = [(self.scaled_window(p), p.number) for p in own]
        w_min = min(windows) if windows else None
        w_max = max(windows) if windows else None

        payload = first_ts = last_ack_ts = duration = bps = None
        acked = False
        if rows:
            first = min(r.seq for r in rows)
            last = max(rows, key=lambda r: r.seq + r.len)
            payload = last.seq + last.len - first
            first_ts = rows[0].rel_ts
            acked = last.acked_by is not None
            end_ts = last.ack_rel_ts if acked else max(r.rel_ts for r in rows)
            last_ack_ts = last.ack_rel_ts
            duration = round(end_ts - first_ts, 6)
            bps = round(payload / duration, 1) if duration > 0 else None

        return TcpDirectionStats(
            sender=sender[0], sender_port=sender[1], packets=len(own), data_segments=len(rows),
            payload_bytes=payload or 0, bytes_sent=sum(r.len for r in rows),
            retransmissions=sum(r.retransmission for r in rows), duplicate_acks=dups,
            mss=syn.mss if syn else None,
            window_min=w_min[0] if w_min else None, window_min_packet=w_min[1] if w_min else None,
            window_max=w_max[0] if w_max else None,
            first_data_rel_ts=first_ts, last_byte_acked=acked, last_byte_ack_rel_ts=last_ack_ts,
            transfer_duration=duration, throughput_bytes_per_s=bps,
            throughput_mbit_per_s=round(bps * 8 / 1e6, 3) if bps else None)

    def stats(self) -> TcpStreamStats:
        return TcpStreamStats(
            stream=self.stream, client=self.client[0], client_port=self.client[1],
            server=self.server[0], server_port=self.server[1], handshake_rtt=self.rtt,
            window_scaling=self.window_scaling,
            client_to_server=self._direction_stats(self.client),
            server_to_client=self._direction_stats(self.server))

    # ------------------------------------------------------------------ fleets (C3)
    def fleets(self, direction: str = "auto", limit: int = 20) -> TcpFleetList:
        sender = self.sender_for(direction)
        if self.rtt:
            rtt, source = self.rtt, "handshake"
        else:
            samples = [r.sample_rtt for r in self.segment_rows(sender) if r.sample_rtt]
            rtt, source = (round(median(samples), 6), "samples") if samples else (None, "none")
        gap = rtt / 3 if rtt else DEFAULT_FLEET_GAP

        groups: list[list[Pkt]] = []
        for p in self.pkts:
            if p.sender != sender or p.length == 0:
                continue
            if groups and p.t - groups[-1][-1].t <= gap:
                groups[-1].append(p)
            else:
                groups.append([p])
        fleets = [TcpFleet(index=i, first_packet=g[0].number, last_packet=g[-1].number,
                           start_rel_ts=g[0].t, end_rel_ts=g[-1].t, segments=len(g),
                           bytes=sum(p.length for p in g))
                  for i, g in enumerate(groups, start=1)]
        intervals = [round(b.start_rel_ts - a.start_rel_ts, 6) for a, b in pairwise(fleets)]
        return TcpFleetList(
            stream=self.stream, sender=sender[0], sender_port=sender[1], rtt_used=rtt, rtt_source=source,
            gap_threshold=round(gap, 6), fleets=fleets[:max(limit, 0)], total=len(fleets),
            truncated=len(fleets) > limit, start_intervals=intervals[:max(limit, 0)],
            median_period=round(median(intervals), 6) if intervals else None)
