# 0004 — MCP server on FastMCP

**Status:** accepted · 2026-10-27

The pcap tools were served with the official SDK's `MCPServer` (ADR 0002 only fixes _that_ they are served over MCP). We switch to the standalone `fastmcp` framework: the tools are passed as-is
(`FastMCP(..., tools=TOOLS)`), so signatures and docstrings stay the single source for both Ollama and MCP,and its in-memory `Client` lets tests go through the real MCP protocol without spawning a process. It also brings middleware and HTTP transport for when Goose or the agent loop needs more than stdio. `mcp` stays only as a transitive dependency of `fastmcp`.
