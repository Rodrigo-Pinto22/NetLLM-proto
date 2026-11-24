"""PcapBackend over the tshark command line (ADR 0012). Needs `tshark` on PATH.

Every method runs tshark once or twice as a subprocess and builds the schema objects from its
output. Two output modes are used:
  -T fields  one tab-separated line per packet with only the fields we ask for (fast, small);
  -T json    the full decode of one packet, for packet_detail only.

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
    HandshakeSegment,
    Layer,
    PacketDetail,
    PacketSummary,
    TcpHandshake,
    TcpOptions,
)

# TCP flag bits, in the order they are written in `flags` ('SYN,ACK', 'FIN,ACK', 'PSH,ACK').
FLAGS = [("SYN", 0x02), ("FIN", 0x01), ("RST", 0x04), ("PSH", 0x08), ("URG", 0x20), ("ACK", 0x10)]
SYN, ACK = 0x02, 0x10
OPT_SACK_PERM, OPT_TIMESTAMPS = 4, 8  # TCP option kinds
SEQ_MOD = 2**32                       # sequence numbers wrap around

# packet_detail keeps only real field names (e.g. 'tcp.seq_raw'), not tree labels ('Flags'), and
# bounds the output so one packet cannot flood a small model's context.
FIELD_NAME = re.compile(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)+$")
MAX_FIELDS_PER_LAYER = 80
MAX_VALUE_CHARS = 200

SUMMARY_FIELDS = ["frame.number", "frame.time_relative", "frame.len",
                  "ip.src", "ip.dst", "ipv6.src", "ipv6.dst"]


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


def _flag_names(bits: int) -> str:
    return ",".join(name for name, bit in FLAGS if bits & bit)


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

    def tcp_handshake(self, stream: int) -> TcpHandshake:
        rows = self._fields(f"tcp.stream == {int(stream)}", [
            "frame.number", "frame.time_relative", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
            "tcp.srcport", "tcp.dstport", "tcp.seq_raw", "tcp.ack_raw", "tcp.flags",
            "tcp.window_size_value", "tcp.option_kind", "tcp.options.mss_val", "tcp.options.wscale.shift"])
        if not rows:
            raise TsharkError(f"There is no TCP stream {stream} in this capture (use flow_id from list_flows)")

        segs = []
        for r in rows:
            bits = int(_first(r["tcp.flags"]), 16)
            kinds = {int(k) for k in r["tcp.option_kind"].split(",") if k}
            segs.append({
                "src": _first(r["ip.src"]) or _first(r["ipv6.src"]), "bits": bits,
                "port": int(_first(r["tcp.srcport"])),
                "dst": _first(r["ip.dst"]) or _first(r["ipv6.dst"]), "dport": int(_first(r["tcp.dstport"])),
                "seg": HandshakeSegment(
                    number=int(r["frame.number"]),
                    rel_ts=float(r["frame.time_relative"]),
                    seq=int(_first(r["tcp.seq_raw"])),
                    ack=int(_first(r["tcp.ack_raw"])) if bits & ACK else None,
                    flags=_flag_names(bits),
                    window=int(_first(r["tcp.window_size_value"])),
                    options=TcpOptions(mss=_int(r["tcp.options.mss_val"]),
                                       window_scale=_int(r["tcp.options.wscale.shift"]),
                                       sack_permitted=OPT_SACK_PERM in kinds,
                                       timestamps=OPT_TIMESTAMPS in kinds)),
            })

        def find(pred, after: int = -1):
            return next((i for i, s in enumerate(segs) if i > after and pred(s)), None)

        i_syn = find(lambda s: s["bits"] & SYN and not s["bits"] & ACK)
        i_synack = find(lambda s: s["bits"] & SYN and s["bits"] & ACK, after=i_syn if i_syn is not None else -1)
        # Client = whoever sent the SYN; without one (capture started late), the SYN-ACK's receiver,
        # else the sender of the first packet.
        if i_syn is not None:
            c = segs[i_syn]
            client, cport, server, sport = c["src"], c["port"], c["dst"], c["dport"]
        elif i_synack is not None:
            c = segs[i_synack]
            client, cport, server, sport = c["dst"], c["dport"], c["src"], c["port"]
        else:
            c = segs[0]
            client, cport, server, sport = c["src"], c["port"], c["dst"], c["dport"]
        i_ack = None
        if i_synack is not None:
            i_ack = find(lambda s: s["src"] == client and s["port"] == cport
                         and s["bits"] & ACK and not s["bits"] & SYN, after=i_synack)

        syn = segs[i_syn]["seg"] if i_syn is not None else None
        syn_ack = segs[i_synack]["seg"] if i_synack is not None else None
        ack = segs[i_ack]["seg"] if i_ack is not None else None
        complete = bool(syn and syn_ack and ack
                        and syn_ack.ack == (syn.seq + 1) % SEQ_MOD
                        and ack.seq == (syn.seq + 1) % SEQ_MOD
                        and ack.ack == (syn_ack.seq + 1) % SEQ_MOD)
        rtt = round(syn_ack.rel_ts - syn.rel_ts, 6) if syn and syn_ack else None
        return TcpHandshake(stream=int(stream), client=client, client_port=cport, server=server,
                            server_port=sport, syn=syn, syn_ack=syn_ack, ack=ack, complete=complete, rtt=rtt)
