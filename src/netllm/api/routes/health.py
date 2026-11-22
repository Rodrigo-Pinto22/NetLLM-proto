from __future__ import annotations

from fastapi import APIRouter

from ..schemas.health import HealthResponse

router = APIRouter(tags=["ops"])


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Liveness only: the process is up. Dependencies are checked by /smoke."""
    return HealthResponse()
