from netllm.mcp_server import server
from netllm.pcap import tools


def test_tools_have_docstrings():
    # The docstring is the description the model sees.
    assert all(fn.__doc__ for fn in tools.TOOLS)


def test_mcp_server_builds():
    assert server is not None
