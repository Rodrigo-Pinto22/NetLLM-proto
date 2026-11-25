# 0013 — Tools name captures by id, not by path

**Status:** accepted · 2026-11-24

The pcap tools took a `pcap_path` argument written by the model. Small models garble long paths,
and nothing stopped the model from asking tshark to open any file on the machine (ADR 0007 wants
the MCP server to enforce what a client may read). Tools now take a short `capture` id
(`tcp-trace1`), and a new `list_captures` tool tells the model which ids exist. Ids are resolved
on the server, against `configs/captures.yaml`, to files inside `data/traces/` only: relative paths
without `..`, symlinks out of the folder refused. An optional `sha256` pins the exact file, so an
evaluation cannot silently run on a different capture. Descriptions are shown to the model and
must not contain facts the question set asks for. Session uploads will later add a second source of
ids, scoped to the session. The cost is one more file to keep in sync with `data/traces/`.
