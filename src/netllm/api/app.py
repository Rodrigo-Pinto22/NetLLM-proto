"""Creates the FastAPI application and plugs in the routers. No endpoints or logic here.

Layers (like controller / DTO / service elsewhere):
  routes/    endpoints: parse the request, call a service, return a schema
  schemas/   request/response models (DTOs); they become the OpenAPI contract
  services/  the actual work; no HTTP concepts in here

The contract is generated from this code and committed as docs/api/openapi.yaml
(regenerate with: uv run python scripts/export_openapi.py; tests fail if it is stale).

Run: uvicorn netllm.api.app:app --port 8080
"""

from __future__ import annotations

from importlib.metadata import version

from fastapi import FastAPI

from .routes import health, smoke


def create_app() -> FastAPI:
    app = FastAPI(
        title="NetLLM",
        version=version("netllm-proto"),
        description="Local networking tutor API.",
    )
    app.include_router(health.router)
    app.include_router(smoke.router)
    return app


app = create_app()
