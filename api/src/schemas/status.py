"""Service status response schemas."""

from __future__ import annotations

from pydantic import BaseModel


class ServiceStatusResponse(BaseModel):
    """Current monitored service status."""

    service_name: str
    target_url: str
    status: str
    monitor_enabled: bool
    consecutive_failures: int
    consecutive_successes: int
    last_checked_at: str | None = None
    last_status_change_at: str | None = None
    last_http_status: int | None = None
    last_response_time_ms: float | None = None
    last_error: str | None = None
    active_incident_id: int | None = None

