"""Control plane health route."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from ..config import get_settings
from ..database import check_database_health
from ..schemas.health import ApiHealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=ApiHealthResponse)
def get_api_health() -> ApiHealthResponse:
    """Report control plane API and database readiness."""
    settings = get_settings()
    try:
        check_database_health(settings.autoheal_db_path)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail={"status": "unhealthy", "service": "api", "database": str(exc)},
        ) from exc

    return ApiHealthResponse(status="healthy", service="api", database="connected")

