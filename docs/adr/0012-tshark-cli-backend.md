# 0012 — PCAP backend calls the tshark CLI, not pyshark

**Status:** accepted · 2026-11-24 · supersedes the pyshark choice in ADR 0002

ADR 0002 named pyshark as the first `PcapBackend`. pyshark wraps tshark but runs its own asyncio
event loop, which conflicts with the async FastMCP server (ADR 0004), and it parses every packet
into Python objects, which is slow for whole-capture questions. `TsharkBackend` instead runs
`tshark` as a subprocess: `-T fields` with only the needed fields for lists and handshakes, and
`-T json` for the one packet `packet_detail` returns. Arguments are passed as a list (no shell), so
a display filter from the model cannot inject a command, and tshark's own error message for an
invalid filter is returned to the model so it can correct itself. The tool signatures and schemas
are unchanged. The cost is a dependency on tshark's output field names, which change slightly
across versions (e.g. `_ws.col.Info` became `_ws.col.info` in 4.2); the backend detects that, and
tests against the Kurose-Ross trace catch other changes. pyshark is no longer a dependency.
