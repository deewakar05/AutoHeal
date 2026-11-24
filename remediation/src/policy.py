"""Remediation policy engine evaluating safety gates before any recovery execution."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Protocol

from .config import RemediationSettings
from .database import (
    build_state_from_summary,
    ensure_utc,
    get_connection,
    query_incident_snapshot,
    query_remediation_summary,
    utc_now,
)
from .models import (
    IncidentView,
    PolicyReason,
    RemediationDecision,
    RemediationRequest,
    RemediationState,
)


class IncidentProvider(Protocol):
    """Read-only provider returning incident records for policy eligibility checks."""

    def get_incident(self, incident_id: int) -> IncidentView | None:
        """Return incident details by ID, or None if no matching incident exists."""


class RemediationStateProvider(Protocol):
    """State provider exposing prior attempts, timestamps, and active run locks."""

    def get_state(self, incident_id: int, service_name: str) -> RemediationState:
        """Return current remediation state for an incident/service pair."""


class InMemoryIncidentProvider:
    """In-memory incident store suitable for tests and decoupled integration."""

    def __init__(self, incidents: Iterable[IncidentView] = ()) -> None:
        self._incidents: dict[int, IncidentView] = {item.id: item for item in incidents}

    def get_incident(self, incident_id: int) -> IncidentView | None:
        return self._incidents.get(incident_id)


class InMemoryRemediationStateProvider:
    """In-memory remediation state provider used for isolated unit tests."""

    def __init__(self, states: dict[tuple[int, str], RemediationState] | None = None) -> None:
        self._states: dict[tuple[int, str], RemediationState] = {
            (inc_id, svc.strip().lower()): state for (inc_id, svc), state in (states or {}).items()
        }

    def get_state(self, incident_id: int, service_name: str) -> RemediationState:
        return self._states.get((incident_id, service_name.strip().lower()), RemediationState())


class SQLiteIncidentProvider:
    """SQLite-backed provider reading actual incidents from the shared `incidents` table."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path

    def get_incident(self, incident_id: int) -> IncidentView | None:
        if incident_id <= 0 or (self.db_path != ":memory:" and not Path(self.db_path).exists()):
            return None

        conn = get_connection(self.db_path, read_only=True)
        try:
            return query_incident_snapshot(conn, incident_id)
        finally:
            conn.close()


class SQLiteRemediationStateProvider:
    """SQLite-backed read-only provider retrieving attempts, cooldowns, and active run state."""

    def __init__(
        self,
        db_path: str,
        *,
        stale_after_seconds: float | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if stale_after_seconds is not None and stale_after_seconds <= 0:
            raise ValueError("stale_after_seconds must be greater than 0 when configured")
        self.db_path = db_path
        self.stale_after_seconds = stale_after_seconds
        self._clock = clock or utc_now

    def get_state(self, incident_id: int, service_name: str) -> RemediationState:
        _ = service_name
        if incident_id <= 0 or (self.db_path != ":memory:" and not Path(self.db_path).exists()):
            return RemediationState()

        conn = get_connection(self.db_path, read_only=True)
        try:
            attempts, active_execution, latest_execution = query_remediation_summary(
                conn, incident_id
            )
        finally:
            conn.close()

        return build_state_from_summary(
            attempts,
            active_execution,
            latest_execution,
            current_time=ensure_utc(self._clock()),
            stale_after_seconds=self.stale_after_seconds,
        )


def _normalize_text(value: str | Enum) -> str:
    raw = value.value if isinstance(value, Enum) else value
    return str(raw).strip().lower()


def _deny_decision(
    *,
    settings: RemediationSettings,
    incident_id: int,
    service_name: str,
    action: str,
    reason: PolicyReason,
    details: str,
    cooldown_remaining_seconds: float = 0.0,
) -> RemediationDecision:
    return RemediationDecision(
        allowed=False,
        reason=reason,
        dry_run=settings.autoheal_remediation_dry_run,
        service_name=service_name,
        action=action,
        incident_id=incident_id,
        details=details,
        cooldown_remaining_seconds=cooldown_remaining_seconds,
    )


def evaluate_policy_gates(
    *,
    request: RemediationRequest,
    settings: RemediationSettings,
    incident: IncidentView | None,
    state: RemediationState,
    current_time: datetime,
) -> RemediationDecision:
    """Evaluate all safety gates using already-fetched incident and remediation state."""
    service = _normalize_text(request.service_name)
    action = _normalize_text(request.action)

    def deny(
        reason: PolicyReason,
        details: str,
        *,
        incident_id: int = request.incident_id,
        cooldown_remaining_seconds: float = 0.0,
    ) -> RemediationDecision:
        return _deny_decision(
            settings=settings,
            incident_id=incident_id,
            service_name=service,
            action=action,
            reason=reason,
            details=details,
            cooldown_remaining_seconds=cooldown_remaining_seconds,
        )

    if not settings.autoheal_remediation_enabled:
        return deny(
            PolicyReason.REMEDIATION_DISABLED,
            "Automated remediation is disabled by configuration.",
        )

    if request.incident_id <= 0 or incident is None:
        return deny(
            PolicyReason.INCIDENT_NOT_FOUND,
            f"Incident {request.incident_id} was not found.",
        )

    incident_service = _normalize_text(incident.service_name)
    if incident_service != service:
        return deny(
            PolicyReason.INCIDENT_NOT_FOUND,
            f"Incident {request.incident_id} belongs to service {incident_service!r}, not {service!r}.",
        )

    incident_status = _normalize_text(incident.status)
    resolved_at = getattr(incident, "resolved_at", None)
    if incident_status != "open" or resolved_at is not None:
        return deny(
            PolicyReason.INCIDENT_ALREADY_RESOLVED,
            f"Incident {incident.id} is not open (status={incident_status!r}).",
            incident_id=incident.id,
        )

    if not service or service not in settings.autoheal_allowed_services:
        return deny(
            PolicyReason.SERVICE_NOT_ALLOWED,
            f"Service {service!r} is not in AUTOHEAL_ALLOWED_SERVICES.",
            incident_id=incident.id,
        )

    if not action or action not in settings.autoheal_allowed_actions:
        return deny(
            PolicyReason.ACTION_NOT_ALLOWED,
            f"Action {action!r} is not in AUTOHEAL_ALLOWED_ACTIONS.",
            incident_id=incident.id,
        )

    if state.is_running:
        return deny(
            PolicyReason.REMEDIATION_ALREADY_RUNNING,
            f"A remediation for incident {incident.id} ({service}) is already running.",
            incident_id=incident.id,
        )

    if state.attempts >= settings.autoheal_remediation_max_attempts:
        return deny(
            PolicyReason.MAX_ATTEMPTS_REACHED,
            (
                f"Maximum remediation attempts reached ({state.attempts}/"
                f"{settings.autoheal_remediation_max_attempts})."
            ),
            incident_id=incident.id,
        )

    if state.last_attempt_at is not None and settings.autoheal_remediation_cooldown_seconds > 0:
        normalized_now = ensure_utc(current_time)
        last_attempt = ensure_utc(state.last_attempt_at)
        elapsed_seconds = (normalized_now - last_attempt).total_seconds()
        if elapsed_seconds < settings.autoheal_remediation_cooldown_seconds:
            remaining = round(
                float(settings.autoheal_remediation_cooldown_seconds) - elapsed_seconds,
                2,
            )
            return deny(
                PolicyReason.COOLDOWN_ACTIVE,
                f"Cooldown active ({remaining}s remaining before next remediation attempt).",
                incident_id=incident.id,
                cooldown_remaining_seconds=remaining,
            )

    mode = "dry-run" if settings.autoheal_remediation_dry_run else "live"
    return RemediationDecision(
        allowed=True,
        reason=PolicyReason.POLICY_APPROVED,
        dry_run=settings.autoheal_remediation_dry_run,
        service_name=service,
        action=action,
        incident_id=incident.id,
        details=f"All policy checks passed ({mode} mode).",
    )


class RemediationPolicy:
    """Evaluates whether a proposed remediation passes all AutoHeal safety gates.

    This policy engine never executes commands or mutates infrastructure; it strictly
    produces a deterministic `RemediationDecision` with explicit `PolicyReason` codes.
    """

    def __init__(
        self,
        settings: RemediationSettings,
        incident_provider: IncidentProvider | None = None,
        state_provider: RemediationStateProvider | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._settings = settings
        self._incident_provider: IncidentProvider = incident_provider or InMemoryIncidentProvider()
        self._state_provider: RemediationStateProvider = (
            state_provider or InMemoryRemediationStateProvider()
        )
        self._clock = clock or utc_now

    @classmethod
    def from_sqlite(
        cls,
        settings: RemediationSettings,
        *,
        db_path: str | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> RemediationPolicy:
        """Create a policy evaluator wired to shared SQLite incident and remediation state."""
        resolved_db = db_path or settings.autoheal_db_path
        effective_clock = clock or utc_now
        return cls(
            settings=settings,
            incident_provider=SQLiteIncidentProvider(resolved_db),
            state_provider=SQLiteRemediationStateProvider(
                resolved_db,
                stale_after_seconds=settings.autoheal_remediation_stale_timeout_seconds,
                clock=effective_clock,
            ),
            clock=effective_clock,
        )

    def evaluate(
        self,
        request: RemediationRequest,
        *,
        now: datetime | None = None,
    ) -> RemediationDecision:
        """Evaluate all policy gates for the proposed remediation request."""
        current_time = ensure_utc(now if now is not None else self._clock())

        if not self._settings.autoheal_remediation_enabled:
            return evaluate_policy_gates(
                request=request,
                settings=self._settings,
                incident=None,
                state=RemediationState(),
                current_time=current_time,
            )

        incident = self._incident_provider.get_incident(request.incident_id)
        service = _normalize_text(request.service_name)
        state = (
            self._state_provider.get_state(incident.id, service)
            if incident is not None
            else RemediationState()
        )

        return evaluate_policy_gates(
            request=request,
            settings=self._settings,
            incident=incident,
            state=state,
            current_time=current_time,
        )
