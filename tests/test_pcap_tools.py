import asyncio
import inspect

import pytest
from ollama._utils import convert_function_to_tool

from netllm.mcp_server import server
from netllm.pcap import tools
from netllm.pcap.backend import PcapBackend


def test_tools_have_docstrings():
    # The docstring is the description the model sees.
    assert all(fn.__doc__ for fn in tools.TOOLS)


@pytest.mark.parametrize("fn", tools.TOOLS, ids=lambda fn: fn.__name__)
def test_every_argument_is_described(fn):
    # Ollama takes argument descriptions from the docstring's Args: section.
    params = convert_function_to_tool(fn).function.parameters.properties
    assert set(params) == set(inspect.signature(fn).parameters)
    assert all(p.description.strip() for p in params.values())


@pytest.mark.parametrize("fn", tools.TOOLS, ids=lambda fn: fn.__name__)
def test_tool_matches_backend_method(fn):
    # Each tool is a thin wrapper: same name and arguments as the backend, minus pcap_path.
    method = getattr(PcapBackend, fn.__name__)
    assert fn.__name__ in PcapBackend.__abstractmethods__
    tool_args = list(inspect.signature(fn).parameters)[1:]
    backend_args = list(inspect.signature(method).parameters)[1:]
    assert tool_args == backend_args


def test_mcp_server_builds():
    assert server is not None


def test_mcp_server_exposes_all_tools():
    listed = asyncio.run(server.list_tools())
    assert {t.name for t in listed} == {fn.__name__ for fn in tools.TOOLS}
