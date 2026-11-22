"""The committed API contract (docs/api/openapi.yaml) must match what the code generates."""

import yaml
from fastapi.testclient import TestClient

from netllm.api.app import create_app
from netllm.config import ROOT

OPENAPI_PATH = ROOT / "docs" / "api" / "openapi.yaml"


def test_committed_openapi_is_up_to_date():
    assert OPENAPI_PATH.exists(), "Missing contract: run `uv run python scripts/export_openapi.py`"
    committed = yaml.safe_load(OPENAPI_PATH.read_text(encoding="utf-8"))
    assert committed == create_app().openapi(), (
        "docs/api/openapi.yaml is stale: run `uv run python scripts/export_openapi.py` and commit it"
    )


def test_health():
    response = TestClient(create_app()).get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
