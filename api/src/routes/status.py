"""Monitored service status route."""

from __future__ import annotations

from fastapi import APIRouter, Query

from ..config import get_settings
from ..database import ensure_database, get_connection
from ..schemas.status import ServiceStatusResponse

router = APIRouter(prefix="/api/v1", tags=["status"])


@router.get("/status", response_model=ServiceStatusResponse)
def get_service_status(
    service: str | None = Query(default=None, description="Target service name"),
) -> ServiceStatusResponse:
    """Return the latest monitoring status for the configured service."""
    settings = get_settings()
    target_service = (service or settings.monitor_target_service).strip()
    ensure_database(settings.autoheal_db_path)

    conn = get_connection(settings.autoheal_db_path)
    try:
        row = conn.execute(
            "SELECT * FROM service_status WHERE service_name = ?",
            (target_service,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        return ServiceStatusResponse(
            service_name=target_service,
            target_url=settings.monitor_target_url,
            status="unknown",
            monitor_enabled=settings.monitor_enabled,
            consecutive_failures=0,
            consecutive_successes=0,
        )

    return ServiceStatusResponse(
        service_name=row["service_name"],
        target_url=row["target_url"],
        status=row["status"],
        monitor_enabled=settings.monitor_enabled,
        consecutive_failures=int(row["consecutive_failures"]),
        consecutive_successes=int(row["consecutive_successes"]),
        last_checked_at=row["last_checked_at"],
        last_status_change_at=row["last_status_change_at"],
        last_http_status=row["last_http_status"],
        last_response_time_ms=row["last_response_time_ms"],
        last_error=row["last_error"],
        active_incident_id=row["active_incident_id"],
    )

