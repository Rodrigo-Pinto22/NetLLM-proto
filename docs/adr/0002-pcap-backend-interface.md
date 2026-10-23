# 0002 — PCAP access behind a backend interface, exposed over MCP

**Status:** accepted · 2026-10-21

The LLM never reads raw packets: it calls tools (`list_flows`, `packet_detail`, `apply_filter`) that
return pydantic models with explicit conventions (1-based frame numbers, wire lengths, relative
timestamps). Tools depend only on `PcapBackend`; pyshark (tshark) is the first implementation and can
be replaced without touching the tools or prompts. The same tools are served over MCP so Goose and
our own agent loop share one implementation.
