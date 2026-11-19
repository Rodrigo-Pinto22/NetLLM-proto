# 0007 — MCP is the tool boundary

**Status:** accepted · 2026-11-19

ADR 0002 serves the pcap tools over MCP and ADR 0004 picks FastMCP; this ADR makes MCP the
boundary for every capability the model can use. The agent, our own loop or an external client
like Goose, reaches tools only through an MCP server and never imports tool code directly. Each tool
is a plain function whose signature and docstring are its contract, returning a validated pydantic
model. This keeps one implementation for every client, lets each capability (pcap now, KB retrieval
later) be tested, swapped or run in its own process, and gives a single place to add logging,
limits and access rules, for example ensuring a session can only read its own uploads. The cost
is a protocol hop and serialisation on every call, and tool results limited to what fits in JSON.
