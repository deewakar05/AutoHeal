"""Pydantic API response schemas for Nagios webhook ingestion and observability routes."""

from __future__ import annotations

from pydantic import BaseModel

from remediation.src.nagios_models import NagiosProcessingOutcome


class NagiosAlertResponse(BaseModel):
    """Response returned by POST /api/v1/monitoring/nagios/alerts."""

    accepted: bool
    duplicate: bool
    outcome: NagiosProcessingOutcome
    dedup_key: str
    mapped_service: str
    incident_id: int | None = None
    incident_created: bool = False
    incident_resolved: bool = False
    remediation_queued: bool = False
    execution_id: int | None = None
    dry_run: bool | None = None
    policy_reason: str | None = None
    details: str = ""


class NagiosEventItem(BaseModel):
    """Serialized row returned by GET /api/v1/monitoring/nagios/events."""

    id: int
    dedup_key: str
    incident_id: int | None = None
    notification_kind: str
    notification_type: str
    host_name: str
    nagios_service_name: str | None = None
    mapped_service: str
    state: str
    state_type: str
    attempt: int
    output: str | None = None
    nagios_problem_id: str | None = None
    nagios_notification_id: str | None = None
    event_timestamp: str
    received_at: str
    processing_status: str


class NagiosEventListResponse(BaseModel):
    """Collection wrapper for Nagios webhook event history."""

    total: int
    events: list[NagiosEventItem]


class NagiosMonitorProbeStatus(BaseModel):
    """Persisted Nagios Core availability status from periodic monitoring probes."""

    target_name: str
    target_url: str
    up: bool
    http_status: int | None = None
    response_time_ms: float | None = None
    program_running: bool
    last_checked_at: str | None = None
    last_error: str | None = None
    updated_at: str


class NagiosStatusResponse(BaseModel):
    """High-level Nagios integration health and ingestion summary."""

    nagios_enabled: bool
    webhook_auth_configured: bool
    monitor_status: NagiosMonitorProbeStatus | None = None
    total_events: int
    events_by_outcome: dict[str, int]
    open_incidents_by_source: dict[str, int]
