"""PcapBackend over the tshark command line (ADR 0012). Needs `tshark` on PATH.

Every method runs tshark once or twice as a subprocess and builds the schema objects from its
output. Two output modes are used:
  -T fields  one tab-separated line per packet with only the fields we ask for (fast, small);
  -T json    the full decode of one packet, for packet_detail only.
The TCP tools read a stream's packets once (cached) and leave the arithmetic to tcp_analysis.py.

Conventions (see schemas.py): frame numbers are Wireshark's frame.number, sequence numbers are
raw (tcp.seq_raw), windows are the field as sent (tcp.window_size_value, never scaled here).
No name resolution (-n): addresses stay numeric.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from functools import cached_property
from pathlib import Path

from .backend import PcapBackend
from .schemas import (
    FilterResult,
    Flow,
    FlowList,
    Layer,
    PacketDetail,
    PacketSummary,
    TcpFleetList,
    TcpHandshake,
    TcpSegmentList,
    TcpStreamStats,
)
from .tcp_analysis import ACK, Pkt, TcpStream

OPT_SACK_PERM, OPT_TIMESTAMPS = 4, 8  # TCP option kinds
MAX_CACHED_STREAMS = 4

# packet_detail keeps only real field names (e.g. 'tcp.seq_raw'), not tree labels ('Flags'), and
# bounds the output so one packet cannot flood a small model's context.
FIELD_NAME = re.compile(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)+$")
MAX_FIELDS_PER_LAYER = 80
MAX_VALUE_CHARS = 200

SUMMARY_FIELDS = ["frame.number", "frame.time_relative", "frame.len",
                  "ip.src", "ip.dst", "ipv6.src", "ipv6.dst"]
TCP_FIELDS = ["frame.number", "frame.time_relative", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
              "tcp.srcport", "tcp.dstport", "tcp.seq_raw", "tcp.ack_raw", "tcp.flags", "tcp.len",
              "tcp.window_size_value", "tcp.option_kind", "tcp.options.mss_val", "tcp.options.wscale.shift"]


class TsharkError(RuntimeError):
    """tshark failed or the request makes no sense for this capture. The message is meant to be
    read by the model (e.g. an invalid display filter), so it says what went wrong."""


# ---------------------------------------------------------------------------- helpers
def _first(value: str) -> str:
    """Fields are read with occurrence=all, joined by ','. Most callers want the first one
    (e.g. the outer IP header when an ICMP error quotes another IP header)."""
    return value.split(",", 1)[0]


def _int(value: str) -> int | None:
    v = _first(value)
    return int(v) if v else None


def _clip(text: str) -> str:
    return text if len(text) <= MAX_VALUE_CHARS else text[:MAX_VALUE_CHARS] + "…"


def _flatten(tree: dict) -> dict[str, str]:
    """Flatten one protocol layer of `tshark -T json` into {field name: value}."""
    out: dict[str, str] = {}

    def walk(node: dict) -> None:
        for key, value in node.items():
            if len(out) >= MAX_FIELDS_PER_LAYER:
                return
            if isinstance(value, dict):
                walk(value)  # subtree, e.g. 'tcp.flags_tree' or a text label like 'Timestamps'
            elif isinstance(value, list):
                if FIELD_NAME.match(key) and all(isinstance(v, str) for v in value):
                    out.setdefault(key, _clip(", ".join(value)))  # repeated field
                else:
                    for v in value:
                        if isinstance(v, dict):
                            walk(v)
            elif FIELD_NAME.match(key):
                out.setdefault(key, _clip(str(value)))

    walk(tree)
    return out


# ---------------------------------------------------------------------------- backend
class TsharkBackend(PcapBackend):
    def __init__(self, path: str | Path, tshark: str = "tshark", timeout: float = 60.0):
        super().__init__(path)
        exe = shutil.which(tshark)
        if exe is None:
            raise TsharkError(f"tshark not found ({tshark!r}); install Wireshark's tshark or set "
                              "NETLLM_TSHARK_PATH")
        self.tshark = exe
        self.timeout = timeout
        self._streams: dict[int, TcpStream] = {}

    # --------------------------------------------------------------- running tshark
    def _run(self, args: list[str]) -> str:
        # A list of arguments, no shell: a display filter can never inject a command.
        cmd = [self.tshark, "-r", str(self.path), "-n", *args]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout, check=False)
        except subprocess.TimeoutExpired as e:
            raise TsharkError(f"tshark took longer than {self.timeout:.0f} s") from e
        if p.returncode != 0:
            # A capture whose last packet is truncated still gives usable output.
            if p.stdout and "cut short" in p.stderr:
                return p.stdout
            raise TsharkError(p.stderr.strip() or f"tshark exited with code {p.returncode}")
        return p.stdout

    def _fields(self, display_filter: str, fields: list[str]) -> list[dict[str, str]]:
        """One dict per matching packet, {field: value}; '' when the packet lacks the field."""
        args = ["-Y", display_filter] if display_filter else []
        args += ["-T", "fields", "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=,",
                 "-E", "quote=n", "-E", "header=n"]
        for f in fields:
            args += ["-e", f]
        rows = []
        for line in self._run(args).splitlines():
            cols = line.split("\t")
            cols += [""] * (len(fields) - len(cols))
            rows.append(dict(zip(fields, cols)))
        return rows

    @cached_property
    def _columns(self) -> tuple[str, str]:
        """Field names of the Info and Protocol columns. Lowercase since Wireshark 4.2."""
        for info, proto in (("_ws.col.info", "_ws.col.protocol"), ("_ws.col.Info", "_ws.col.Protocol")):
            try:
                self._run(["-c", "1", "-T", "fields", "-e", info, "-e", proto])
                return info, proto
            except TsharkError:
                continue
        raise TsharkError("this tshark version has no Info/Protocol column fields")

    def _summaries(self, display_filter: str) -> list[PacketSummary]:
        info, proto = self._columns
        rows = self._fields(display_filter, [*SUMMARY_FIELDS, proto, info])
        return [
            PacketSummary(
                number=int(r["frame.number"]),
                rel_ts=float(r["frame.time_relative"]),
                src=_first(r["ip.src"]) or _first(r["ipv6.src"]) or None,
                dst=_first(r["ip.dst"]) or _first(r["ipv6.dst"]) or None,
                protocol=r[proto],
                length=int(r["frame.len"]),
                summary=r[info],
            )
            for r in rows
        ]

    # ------------------------------------------------------------------------ tools
    def list_flows(self, limit: int = 50) -> FlowList:
        rows = self._fields("tcp or udp", [
            "frame.number", "frame.time_relative", "frame.len",
            "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
            "tcp.stream", "tcp.srcport", "tcp.dstport", "udp.stream", "udp.srcport", "udp.dstport"])

        flows: dict[tuple[str, int], dict] = {}
        for r in rows:
            proto, p = ("TCP", "tcp") if r["tcp.stream"] else ("UDP", "udp") if r["udp.stream"] else (None, "")
            if proto is None:
                continue
            key = (proto, int(_first(r[f"{p}.stream"])))
            rel = float(r["frame.time_relative"])
            f = flows.get(key)
            if f is None:  # the first packet seen decides src/dst (schemas.py)
                f = flows[key] = {
                    "flow_id": key[1], "protocol": proto,
                    "src": _first(r["ip.src"]) or _first(r["ipv6.src"]), "src_port": _int(r[f"{p}.srcport"]),
                    "dst": _first(r["ip.dst"]) or _first(r["ipv6.dst"]), "dst_port": _int(r[f"{p}.dstport"]),
                    "packets": 0, "bytes": 0, "first_packet": int(r["frame.number"]),
                    "start_rel_ts": rel, "last_rel_ts": rel,
                }
            f["packets"] += 1
            f["bytes"] += int(r["frame.len"])
            f["last_rel_ts"] = max(f["last_rel_ts"], rel)

        out = []
        for f in flows.values():
            last = f.pop("last_rel_ts")
            out.append(Flow(duration=round(last - f["start_rel_ts"], 6), **f))
        out.sort(key=lambda f: f.bytes, reverse=True)  # largest first
        return FlowList(flows=out[:max(limit, 0)], total=len(out), truncated=len(out) > limit)

    def packet_detail(self, number: int) -> PacketDetail:
        where = f"frame.number == {int(number)}"
        head = self._fields(where, ["frame.time_epoch"])
        summary = self._summaries(where)
        if not summary:
            raise TsharkError(f"There is no frame {number} in this capture")
        packets = json.loads(self._run(["-Y", where, "-T", "json"]))
        layers = []
        for name, value in packets[0]["_source"]["layers"].items():
            for tree in value if isinstance(value, list) else [value]:  # a protocol may repeat
                if isinstance(tree, dict):
                    layers.append(Layer(name=name, fields=_flatten(tree)))
        s = summary[0]
        return PacketDetail(number=s.number, ts=float(head[0]["frame.time_epoch"]), rel_ts=s.rel_ts,
                            length=s.length, summary=s.summary, layers=layers)

    def apply_filter(self, display_filter: str, limit: int = 50) -> FilterResult:
        rows = self._summaries(display_filter)  # an invalid filter raises tshark's own message
        return FilterResult(display_filter=display_filter, packets=rows[:max(limit, 0)],
                            total=len(rows), truncated=len(rows) > limit)

    def _tcp(self, stream: int) -> TcpStream:
        """All packets of one TCP stream, parsed once and kept for the next tool call."""
        stream = int(stream)
        if stream not in self._streams:
            pkts = []
            for r in self._fields(f"tcp.stream == {stream}", TCP_FIELDS):
                bits = int(_first(r["tcp.flags"]), 16)
                kinds = {int(k) for k in r["tcp.option_kind"].split(",") if k}
                pkts.append(Pkt(
                    number=int(r["frame.number"]), t=float(r["frame.time_relative"]),
                    src=_first(r["ip.src"]) or _first(r["ipv6.src"]), sport=int(_first(r["tcp.srcport"])),
                    dst=_first(r["ip.dst"]) or _first(r["ipv6.dst"]), dport=int(_first(r["tcp.dstport"])),
                    seq=int(_first(r["tcp.seq_raw"])),
                    ack=int(_first(r["tcp.ack_raw"])) if bits & ACK else None,
                    flags=bits, length=_int(r["tcp.len"]) or 0,
                    window=int(_first(r["tcp.window_size_value"])),
                    mss=_int(r["tcp.options.mss_val"]), wscale=_int(r["tcp.options.wscale.shift"]),
                    sack_perm=OPT_SACK_PERM in kinds, timestamps=OPT_TIMESTAMPS in kinds))
            try:
                tcp = TcpStream(stream, pkts)
            except ValueError as e:  # no such stream
                raise TsharkError(str(e)) from e
            if len(self._streams) >= MAX_CACHED_STREAMS:
                self._streams.clear()
            self._streams[stream] = tcp
        return self._streams[stream]

    def tcp_handshake(self, stream: int) -> TcpHandshake:
        return self._tcp(stream).handshake()

    def tcp_segments(self, stream: int, direction: str = "auto", limit: int = 50) -> TcpSegmentList:
        return self._tcp(stream).segments(direction, limit)

    def tcp_stream_stats(self, stream: int) -> TcpStreamStats:
        return self._tcp(stream).stats()

    def tcp_fleets(self, stream: int, direction: str = "auto", limit: int = 20) -> TcpFleetList:
        return self._tcp(stream).fleets(direction, limit)
