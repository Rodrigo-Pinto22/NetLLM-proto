# 0006 — Standalone repo with a src layout

**Status:** accepted · 2026-11-19

NetLLM lives in its own repository (`NetLLM-proto`) so its history, dependencies and decisions
cover only this project. The importable code sits under `src/netllm/` and is built by hatchling;
uv manages the environment from `pyproject.toml` and `uv.lock` (Python 3.14). Because Python can't
import the package from the working directory, tests and scripts run against the installed
package (`uv sync` installs it in editable mode), so packaging mistakes show up locally rather than
later. The code is split into one subpackage per concern (`ingest`, `kb`, `pcap`, `memory`,
`agent`, `eval`), with `config.py` and `mcp_server.py` as the shared settings and the entry point;
subpackages use each other's public interfaces, not their internals. Everything that isn't code
stays outside `src/`: `configs/`, `questions/` and `docs/` are versioned, while `data/` and `runs/`
are local and gitignored, and machine-specific settings live in `.env`. The cost is one extra
directory level and a required `uv sync` before anything can be imported.
