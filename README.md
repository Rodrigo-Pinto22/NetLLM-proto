# NetLLM

A local networking tutor. It answers questions using a knowledge base (textbooks, RFCs) and by
inspecting packet captures through tool calls, adapting to a learner profile (level, language,
socratic or direct). Everything runs locally via Ollama.

## Requirements

- **Python 3.14** and [uv](https://docs.astral.sh/uv/)
- **tshark** (Wireshark CLI), used by pyshark to decode captures
  - Ubuntu/Debian: `sudo apt install tshark` (answer *yes* to allow non-root capture, or skip if you only read files)
  - macOS: `brew install wireshark`
  - check: `tshark --version`
- **Ollama** running locally ([ollama.com](https://ollama.com)), with a chat model that supports tool calling:
  ```bash
  ollama pull gpt-oss:20b
  ollama serve            # if not already running as a service
  ```

## Setup

```bash
uv sync                  # creates .venv with runtime + dev deps
cp .env.example .env     # adjust OLLAMA_HOST / model names / paths
uv run pytest
```

## Phase 0: tool-calling go/no-go

Before building the agent, check that the local model calls the pcap tools correctly:

```bash
uv run scripts/smoke_tool_calling.py --trials 5 --threshold 0.8
```

Exit code 0 means GO. Try other models with `--model`.

## Usage

```bash
# Build the admin KB chunks from a folder of PDFs/Markdown/RFCs
uv run python -m netllm.ingest.ingestor data/kb_docs --out data/chunks.jsonl --scope admin

# Serve the pcap tools over MCP (stdio), e.g. for Goose
uv run netllm-mcp
```

## Layout

| Path | What |
|---|---|
| `configs/profiles/` | Learner profiles: level, language, mode |
| `questions/` | Versioned question sets (YAML) for eval |
| `docs/adr/` | One-paragraph decision records |
| `src/netllm/config.py` | Settings from `.env` + profile loader |
| `src/netllm/ingest/` | PDF/Markdown/text → cleaned, section-aware chunks, with scope |
| `src/netllm/kb/` | Chroma wrapper, KB manifest/versioning |
| `src/netllm/pcap/` | Backend interface, pyshark backend, output schemas, tools |
| `src/netllm/mcp_server.py` | MCP server exposing the pcap tools |
| `src/netllm/memory/` | Session history, fact store |
| `src/netllm/agent/` | Agent loop, answer contract, claim check, trace |
| `src/netllm/eval/` | Eval harness, metrics, run logging |
| `scripts/` | One-off and gate scripts |
| `tests/fixtures/` | Small PCAPs only |
| `data/`, `runs/` | Git-ignored: traces, KB docs, Chroma, eval outputs |
