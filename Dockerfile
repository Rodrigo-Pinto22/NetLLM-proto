# syntax=docker/dockerfile:1
# One build, two runtime targets: `app` (API) and `mcp` (MCP server + tshark).
# Database migrations are not in these images: the `flyway` compose service runs migrations/.
# No model weights, KB documents, student data or .env go into the images: those are volumes/env.
#
# Pin before deployment: set UV_VERSION to your local `uv --version` (the lockfile format must be
# readable by it) and replace the tags below with digests (image@sha256:...).
ARG PYTHON_IMAGE=python:3.14-slim-trixie
ARG UV_VERSION=0.9.5

FROM ghcr.io/astral-sh/uv:${UV_VERSION} AS uv

# ---- build: resolve the locked venv into /app/.venv -------------------------------------------
FROM ${PYTHON_IMAGE} AS build
COPY --from=uv /uv /uvx /bin/
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
# Dependencies first (cached until pyproject.toml/uv.lock change), then the project itself.
COPY pyproject.toml uv.lock README.md ./
RUN --mount=type=cache,target=/root/.cache/uv uv sync --locked --no-dev --no-install-project
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv uv sync --locked --no-dev

# ---- shared runtime base -----------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runtime
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1 \
    NETLLM_DATA_DIR=/data NETLLM_RUNS_DIR=/runs
RUN useradd --system --create-home --uid 10001 netllm \
 && mkdir -p /data/kb_docs /data/sessions /runs \
 && chown -R netllm:netllm /data /runs
WORKDIR /app

# ---- app ---------------------------------------------------------------------------------------
FROM runtime AS app
COPY --from=build --chown=netllm:netllm /app /app
COPY --chown=netllm:netllm configs ./configs
USER netllm
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')"
CMD ["uvicorn", "netllm.api.app:app", "--host", "0.0.0.0", "--port", "8080"]

# ---- mcp ---------------------------------------------------------------------------------------
FROM runtime AS mcp
# Non-interactive tshark: preseed the "allow non-root capture?" question (we only read files).
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build --chown=netllm:netllm /app /app
USER netllm
ENV NETLLM_MCP_TRANSPORT=http NETLLM_MCP_BIND_HOST=0.0.0.0 NETLLM_MCP_PORT=8001
EXPOSE 8001
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/health')"
CMD ["netllm-mcp"]
