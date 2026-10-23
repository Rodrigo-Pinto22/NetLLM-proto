"""Exposes the pcap tools over MCP (stdio), for Goose and for the own agent loop."""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from .pcap.tools import TOOLS

server = MCPServer("netllm-pcap", instructions="Inspect PCAP files. Packet numbers are 1-based frame numbers.")
for fn in TOOLS:
    server.tool()(fn)


def main() -> None:
    server.run("stdio")


if __name__ == "__main__":
    main()
