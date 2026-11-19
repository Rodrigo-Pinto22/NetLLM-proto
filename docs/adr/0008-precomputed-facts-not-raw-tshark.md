# 0008 — Tools return pre-computed facts, not raw tshark JSON

**Status:** accepted · 2026-11-19

`tshark -T json` output is large, nested and full of fields that don't matter for a given
question. A small local model handed that output runs out of context, misreads conventions
(relative vs. raw sequence numbers, scaled vs. unscaled windows) and does arithmetic it gets wrong.
Tools therefore compute the facts in code and return small typed results: `tcp_handshake` returns
the three segments with raw seq/ack numbers, options, a `complete` flag and the RTT, rather than
the packets that contain them. Conventions are stated in the schema field descriptions. Lists are
capped with `limit` and report `total` and `truncated`. The model explains facts and doesn't derive
them, which also makes answers checkable against the tool output. `packet_detail` stays as a
bounded escape hatch for one packet. The cost is that each new kind of question needs a new tool or
schema, and the model can only see what a tool exposes.
