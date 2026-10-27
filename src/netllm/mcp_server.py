"""Exposes the pcap tools over MCP (stdio), for Goose and for the own agent loop."""

from __future__ import annotations

from fastmcp import FastMCP

from netllm.pcap.tools import TOOLS
server = FastMCP(
    "netllm-pcap",
    instructions="Inspect PCAP files. Packet numbers are 1-based frame numbers.",
    tools=TOOLS,
)


def main() -> None:
    server.run("stdio")


if __name__ == "__main__":
    main()
