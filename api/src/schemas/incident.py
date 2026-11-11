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


class IncidentListResponse(BaseModel):
    """Paginated/filtered incident list."""

    total: int
    open_count: int
    incidents: list[IncidentResponse]

