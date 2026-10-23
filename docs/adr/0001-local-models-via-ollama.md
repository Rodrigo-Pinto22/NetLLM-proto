# 0001 — Local models via Ollama

**Status:** accepted · 2026-10-21

Captures and course material may be private, and the project must run on a single workstation, so all
inference goes through a local Ollama server (`OLLAMA_HOST`) and no hosted API is used. Model names
live in `.env`, not in code, so swapping models is a config change. The cost is that tool-calling
quality depends on the local model, which is why Phase 0 (`scripts/smoke_tool_calling.py`) is a
go/no-go gate before building the agent on top of it.
