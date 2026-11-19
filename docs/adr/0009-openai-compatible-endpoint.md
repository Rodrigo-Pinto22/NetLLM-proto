# 0009 — Model behind an OpenAI-compatible endpoint

**Status:** accepted · 2026-11-19 · supersedes the client choice in [0001](0001-local-models-via-ollama.md)

ADR 0001 runs all inference locally through Ollama and talks to it with the `ollama` Python client,
which ties the code to one server. Ollama now and vLLM later (on a GPU server) both serve the
OpenAI chat-completions API (`/v1/chat/completions`, with tool calling), so the agent talks to that
API only, through one client configured by a base URL, model name and API key in `.env`. Switching
from Ollama on a laptop to vLLM on a server then becomes a configuration change. The local-only
rule from 0001 still holds: the endpoint must be one we run, never a hosted API. The cost is
migrating the existing `ollama` client code (`scripts/smoke_tool_calling.py`), losing
Ollama-specific options such as `think`, and accepting that tool-calling behaviour can differ
between servers for the same model, so the Phase 0 smoke test is re-run whenever the backend
changes.
