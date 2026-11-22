from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from netllm.config import Settings, get_settings

from ..schemas.smoke_dto import SmokeResult
from ..services.smoke import run_smoke

router = APIRouter(tags=["ops"])


@router.post("/smoke", response_model=SmokeResult)
async def smoke(settings: Annotated[Settings, Depends(get_settings)]) -> SmokeResult:
    """End-to-end stack check: call a tool on mcp, write a trace event to postgres, query chroma."""
    return await run_smoke(settings)
