"""Control plane health route."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from ..config import get_settings
from ..database import check_database_health
from ..schemas.health import ApiHealthResponse

router = APIRouter(tags=["health"])
logger = logging.getLogger("control-plane-api")


@router.get("/health", response_model=ApiHealthResponse)
def get_api_health() -> ApiHealthResponse:
    """Report control plane API and database readiness."""
    settings = get_settings()
    try:
        check_database_health(settings.autoheal_db_path)
    except Exception as exc:
        logger.exception(
            "API database readiness check failed",
            extra={"event": "api_db_health_error"},
        )
        raise HTTPException(
            status_code=503,
            detail={"status": "unhealthy", "service": "api", "database": "unavailable"},
        ) from exc

    return ApiHealthResponse(status="healthy", service="api", database="connected")
