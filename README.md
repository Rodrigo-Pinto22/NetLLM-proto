# NetLLM

A local networking tutor. It answers questions using a knowledge base (textbooks, RFCs) and by
inspecting packet captures through tool calls, adapting to a learner profile (level, language,
socratic or direct). Everything runs locally via Ollama.

## Requirements

- **Python 3.14** and [uv](https://docs.astral.sh/uv/)
- **tshark** (Wireshark CLI), used by pyshark to decode captures
  - Ubuntu/Debian: `sudo apt install tshark` (answer _yes_ to allow non-root capture, or skip if you only read files)
  - macOS: `brew install wireshark`
  - check: `tshark --version`
- **Ollama** running locally ([ollama.com](https://ollama.com)), with a chat model that supports tool calling:
  ```bash
  ollama pull gemma4:e4b
  ollama serve            # if not already running as a service
  ```

## Setup

```bash
uv sync                  # creates .venv with runtime + dev deps
cp .env.example .env     # adjust NETLLM_OLLAMA_HOST / model names / paths
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

# Serve the pcap tools over MCP: stdio (default) or HTTP on :8001
uv run netllm-mcp
NETLLM_MCP_TRANSPORT=http uv run netllm-mcp
```

## Local stack (Docker Compose)

Services: `app` (tutor API, :8080), `mcp` (MCP server with the pcap tools, :8001), `postgres`
(:5432), `chroma` (:8000), and optionally `ollama` (:11434, profile `gpu`). All ports bind to
`127.0.0.1`. Config comes from `.env` only. Data lives in named volumes (`pg_data`,
`chroma_data`, `ollama_models`, `kb_docs`, `sessions`, `runs`), never in images.

Needs Docker with Compose ≥ 2.23 (for `sync+restart` watch). For GPU Ollama you also need the
NVIDIA Container Toolkit.

Both modes below use the same `.env`. It holds `localhost` URLs, and `compose.yaml` re-points
hostnames inside containers.

### Mode A: infra in Docker, code on the host (fastest for debugging and pytest)

```bash
docker compose up -d --wait postgres chroma        # add `--profile gpu ... ollama` for GPU Ollama
docker compose run --rm flyway                      # apply migrations/ (Flyway, no Java on the host)
NETLLM_MCP_TRANSPORT=http uv run netllm-mcp         # terminal 1: MCP server on :8001
uv run uvicorn netllm.api.app:app --port 8080 --reload   # terminal 2: API on :8080
curl -X POST localhost:8080/smoke                   # tool call on mcp + trace event + chroma query
```

Ollama runs on the host (`ollama serve`), unless you start the `ollama` service with
`--profile gpu`. In that case stop the host Ollama first, because both use port 11434.

### Mode B: full stack in Docker

```bash
docker compose up -d --build --wait     # all services healthy (or add --profile gpu)
curl -X POST localhost:8080/smoke
docker compose watch                    # sync src/ into app and mcp, restart them on change
```

Edits in `src/` are synced and the service restarts, with no rebuild. Changing `pyproject.toml`
or `uv.lock` triggers a rebuild. The one-shot `flyway` service runs before `app` on every `up`.
After adding a migration, run `docker compose run --rm flyway`.

Migrations are plain SQL in `migrations/`, named `V<n>__<description>.sql`. Never edit one that
has been applied; add the next version instead.

Containers reach Ollama through `OLLAMA_BASE_URL`. By default that is Ollama on the host
(`http://host.docker.internal:11434`), which must listen on all interfaces:
`OLLAMA_HOST=0.0.0.0 ollama serve`. With `--profile gpu`, set
`OLLAMA_BASE_URL=http://ollama:11434` in `.env`. Pull models into the container with
`docker compose exec ollama ollama pull <model>`.

### API contract

The API is code-first: routes and pydantic schemas in `src/netllm/api/` generate the OpenAPI
contract, which is committed as `docs/api/openapi.yaml`. After changing an endpoint or schema:

```bash
uv run python scripts/export_openapi.py   # regenerate the contract, then commit it
```

`tests/test_openapi.py` fails if the committed contract is out of date, so every API change
shows up in the pull-request diff. With the app running, the interactive docs are at
`http://localhost:8080/docs`.

### Goose

Goose connects to the same MCP server over HTTP. Run `goose configure`, choose Add Extension →
Remote Extension (Streamable HTTP), and enter `http://localhost:8001/mcp`. In
`~/.config/goose/config.yaml` this looks like:

```yaml
extensions:
  netllm-pcap:
    enabled: true
    type: streamable_http
    name: netllm-pcap
    uri: http://localhost:8001/mcp
    timeout: 300
```

Tools receive file paths **as the MCP server sees them**. With Mode B these are container paths
under `/data/...`, not paths on your machine.

### Deployment notes (SCRUM-54)

Before deploying, pin every image to a digest (`image@sha256:...`), including the `PYTHON_IMAGE`
and `UV_VERSION` build args in the `Dockerfile`. Set a real `POSTGRES_PASSWORD`. Never bake model
weights, KB documents or student data into images.

## Layout

| Path                       | What                                                          |
| -------------------------- | ------------------------------------------------------------- |
| `configs/profiles/`        | Learner profiles: level, language, mode                       |
| `questions/`               | Versioned question sets (YAML) for eval                       |
| `docs/adr/`                | One-paragraph decision records                                |
| `src/netllm/config.py`     | Settings from `.env` + profile loader                         |
| `src/netllm/ingest/`       | PDF/Markdown/text → cleaned, section-aware chunks, with scope |
| `src/netllm/kb/`           | Chroma wrapper, KB manifest/versioning                        |
| `src/netllm/pcap/`         | Backend interface, pyshark backend, output schemas, tools     |
| `src/netllm/mcp_server.py` | MCP server exposing the pcap tools                            |
| `src/netllm/memory/`       | Session history, fact store                                   |
| `src/netllm/api/`          | Tutor HTTP API (FastAPI): `routes/` (endpoints), `schemas/` (DTOs), `services/` (logic) |
| `docs/api/openapi.yaml`    | API contract, generated from the code (`scripts/export_openapi.py`) |
| `migrations/`              | Flyway SQL migrations (PostgreSQL schemas `core` / `session`) |
| `compose.yaml`, `Dockerfile` | Local stack; base for deployment                            |
| `src/netllm/agent/`        | Agent loop, answer contract, claim check, trace               |
| `src/netllm/eval/`         | Eval harness, metrics, run logging                            |
| `scripts/`                 | One-off and gate scripts                                      |
| `tests/fixtures/`          | Small PCAPs only                                              |
| `data/`, `runs/`           | Git-ignored: traces, KB docs, Chroma, eval outputs            |
