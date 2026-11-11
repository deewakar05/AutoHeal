"""Domain models and enums for monitoring state and incident tracking."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class ServiceState(str, Enum):
    """Lifecycle states of a monitored service."""

    UNKNOWN = "unknown"
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"


class CheckOutcome(str, Enum):
    """Categorized result of a single HTTP health probe."""

    SUCCESS = "success"
    HTTP_ERROR = "http_error"
    CONNECTION_ERROR = "connection_error"
    TIMEOUT = "timeout"
    INVALID_RESPONSE = "invalid_response"


class IncidentStatus(str, Enum):
    """Incident lifecycle status."""

    OPEN = "open"
    RESOLVED = "resolved"


@dataclass(frozen=True)
class HealthCheckResult:
    """Outcome of a single health check probe."""

    service_name: str
    target_url: str
    healthy: bool
    outcome: CheckOutcome
    status_code: int | None
    response_time_ms: float
    error: str | None
    checked_at: datetime


@dataclass(frozen=True)
class ServiceStatusRecord:
    """Persisted status snapshot of a monitored service."""

    service_name: str
    target_url: str
    status: ServiceState
    consecutive_failures: int
    consecutive_successes: int
    last_checked_at: datetime | None
    last_status_change_at: datetime | None
    last_http_status: int | None
    last_response_time_ms: float | None
    last_error: str | None
    active_incident_id: int | None


@dataclass(frozen=True)
class IncidentRecord:
    """Persisted incident record."""

    id: int
    service_name: str
    status: IncidentStatus
    failure_reason: str
    started_at: datetime
    resolved_at: datetime | None
    last_seen_at: datetime
    failure_count: int


@dataclass(frozen=True)
class StateEvaluation:
    """Result of evaluating a health check against thresholds and incident state."""

    previous_state: ServiceState
    current_state: ServiceState
    state_changed: bool
    incident_created: IncidentRecord | None
    incident_resolved: IncidentRecord | None
    active_incident: IncidentRecord | None
    status_record: ServiceStatusRecord

