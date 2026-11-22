"""Exposes the pcap tools over MCP, for Goose and for the own agent loop.

Transport comes from settings: stdio (default, a client spawns the process) or http (the `mcp`
compose service; clients connect to NETLLM_MCP_URL, i.e. http://<host>:<port>/mcp).
"""

from __future__ import annotations

from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import PlainTextResponse

from netllm.config import get_settings
from netllm.pcap.tools import TOOLS

server = FastMCP(
    "netllm-pcap",
    instructions="Inspect PCAP files. Packet numbers are 1-based frame numbers.",
    tools=TOOLS,
)


@server.custom_route("/health", methods=["GET"])
async def health(request: Request) -> PlainTextResponse:
    """Plain HTTP liveness check for the compose healthcheck (only served with the http transport)."""
    return PlainTextResponse("ok")


def main() -> None:
    s = get_settings()
    if s.mcp_transport == "http":
        server.run("http", host=s.mcp_bind_host, port=s.mcp_port)
    else:
        server.run("stdio")


if __name__ == "__main__":
    main()
