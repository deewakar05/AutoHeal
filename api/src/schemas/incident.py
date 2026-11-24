"""Incident response schemas."""

from __future__ import annotations

from pydantic import BaseModel


class IncidentResponse(BaseModel):
    """Single incident record."""

    id: int
    service_name: str
    status: str
    failure_reason: str
    started_at: str
    resolved_at: str | None = None
    last_seen_at: str
    failure_count: int
    source: str = "internal_monitor"
    host_name: str | None = None
    nagios_service_name: str | None = None
    nagios_state: str | None = None
    nagios_alert_count: int = 0
    flapping: bool = False


class IncidentListResponse(BaseModel):
    """Paginated/filtered incident list."""

    total: int
    open_count: int
    incidents: list[IncidentResponse]
