"""Write the API contract generated from the code to docs/api/openapi.yaml.

Run after changing any route or schema, and commit the result:
    uv run python scripts/export_openapi.py
tests/test_openapi.py fails while the committed file is out of date.
"""

from __future__ import annotations

import yaml

from netllm.api.app import create_app
from netllm.config import ROOT

OPENAPI_PATH = ROOT / "docs" / "api" / "openapi.yaml"


def render() -> str:
    return yaml.safe_dump(create_app().openapi(), sort_keys=False, allow_unicode=True)


def main() -> None:
    OPENAPI_PATH.parent.mkdir(parents=True, exist_ok=True)
    OPENAPI_PATH.write_text(render(), encoding="utf-8")
    print(f"wrote {OPENAPI_PATH.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
