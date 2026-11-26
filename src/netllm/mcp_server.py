"""Exposes the pcap and knowledge-base tools over MCP, for Goose and for the own agent loop.

Transport comes from settings: stdio (default, a client spawns the process) or http (the `mcp`
compose service; clients connect to NETLLM_MCP_URL, i.e. http://<host>:<port>/mcp).
"""

from __future__ import annotations

from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import PlainTextResponse

from netllm.config import get_settings
from netllm.kb.tools import KB_TOOLS
from netllm.pcap import tools as pcap_tools

ALL_TOOLS = [*pcap_tools.TOOLS, *KB_TOOLS]

server = FastMCP(
    "netllm",
    instructions="Inspect packet captures (packet numbers are 1-based frame numbers) and search the "
                 "course material.",
    tools=ALL_TOOLS,
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
