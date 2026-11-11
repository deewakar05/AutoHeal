"""Remediation policy engine evaluating safety gates before any recovery execution."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from enum import Enum
from typing import Protocol

from .config import RemediationSettings
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
    """In-memory remediation state provider used until Phase 4.2 SQLite history is added."""

    def __init__(self, states: dict[tuple[int, str], RemediationState] | None = None) -> None:
        self._states: dict[tuple[int, str], RemediationState] = {
            (inc_id, svc.strip().lower()): state for (inc_id, svc), state in (states or {}).items()
        }

    def get_state(self, incident_id: int, service_name: str) -> RemediationState:
        return self._states.get((incident_id, service_name.strip().lower()), RemediationState())


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _normalize_text(value: str | Enum) -> str:
    raw = value.value if isinstance(value, Enum) else value
    return str(raw).strip().lower()


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
        self._clock = clock or _utc_now

    def evaluate(
        self,
        request: RemediationRequest,
        *,
        now: datetime | None = None,
    ) -> RemediationDecision:
        """Evaluate all policy gates for the proposed remediation request."""
        service = _normalize_text(request.service_name)
        action = _normalize_text(request.action)

        if not self._settings.autoheal_remediation_enabled:
            return self._deny(
                request.incident_id,
                service,
                action,
                PolicyReason.REMEDIATION_DISABLED,
                "Automated remediation is disabled by configuration.",
            )

        if request.incident_id <= 0:
            return self._deny(
                request.incident_id,
                service,
                action,
                PolicyReason.INCIDENT_NOT_FOUND,
                f"Incident {request.incident_id} does not exist.",
            )

        incident = self._incident_provider.get_incident(request.incident_id)
        if incident is None:
            return self._deny(
                request.incident_id,
                service,
                action,
                PolicyReason.INCIDENT_NOT_FOUND,
                f"Incident {request.incident_id} was not found.",
            )

        incident_service = _normalize_text(incident.service_name)
        if incident_service != service:
            return self._deny(
                request.incident_id,
                service,
                action,
                PolicyReason.INCIDENT_NOT_FOUND,
                f"Incident {request.incident_id} belongs to service {incident_service!r}, not {service!r}.",
            )

        incident_status = _normalize_text(incident.status)
        resolved_at = getattr(incident, "resolved_at", None)
        if incident_status != "open" or resolved_at is not None:
            return self._deny(
                incident.id,
                service,
                action,
                PolicyReason.INCIDENT_ALREADY_RESOLVED,
                f"Incident {incident.id} is not open (status={incident_status!r}).",
            )

        if not service or service not in self._settings.autoheal_allowed_services:
            return self._deny(
                incident.id,
                service,
                action,
                PolicyReason.SERVICE_NOT_ALLOWED,
                f"Service {service!r} is not in AUTOHEAL_ALLOWED_SERVICES.",
            )

        if not action or action not in self._settings.autoheal_allowed_actions:
            return self._deny(
                incident.id,
                service,
                action,
                PolicyReason.ACTION_NOT_ALLOWED,
                f"Action {action!r} is not in AUTOHEAL_ALLOWED_ACTIONS.",
            )

        state = self._state_provider.get_state(incident.id, service)
        if state.is_running:
            return self._deny(
                incident.id,
                service,
                action,
                PolicyReason.REMEDIATION_ALREADY_RUNNING,
                f"A remediation for incident {incident.id} ({service}) is already running.",
            )

        if state.attempts >= self._settings.autoheal_remediation_max_attempts:
            return self._deny(
                incident.id,
                service,
                action,
                PolicyReason.MAX_ATTEMPTS_REACHED,
                (
                    f"Maximum remediation attempts reached ({state.attempts}/"
                    f"{self._settings.autoheal_remediation_max_attempts})."
                ),
            )

        if state.last_attempt_at is not None and self._settings.autoheal_remediation_cooldown_seconds > 0:
            current_time = _ensure_utc(now if now is not None else self._clock())
            last_attempt = _ensure_utc(state.last_attempt_at)
            elapsed_seconds = (current_time - last_attempt).total_seconds()
            if elapsed_seconds < self._settings.autoheal_remediation_cooldown_seconds:
                remaining = round(
                    float(self._settings.autoheal_remediation_cooldown_seconds) - elapsed_seconds,
                    2,
                )
                return self._deny(
                    incident.id,
                    service,
                    action,
                    PolicyReason.COOLDOWN_ACTIVE,
                    f"Cooldown active ({remaining}s remaining before next remediation attempt).",
                    cooldown_remaining_seconds=remaining,
                )

        mode = "dry-run" if self._settings.autoheal_remediation_dry_run else "live"
        return RemediationDecision(
            allowed=True,
            reason=PolicyReason.POLICY_APPROVED,
            dry_run=self._settings.autoheal_remediation_dry_run,
            service_name=service,
            action=action,
            incident_id=incident.id,
            details=f"All policy checks passed ({mode} mode).",
        )

    def _deny(
        self,
        incident_id: int,
        service_name: str,
        action: str,
        reason: PolicyReason,
        details: str,
        *,
        cooldown_remaining_seconds: float = 0.0,
    ) -> RemediationDecision:
        return RemediationDecision(
            allowed=False,
            reason=reason,
            dry_run=self._settings.autoheal_remediation_dry_run,
            service_name=service_name,
            action=action,
            incident_id=incident_id,
            details=details,
            cooldown_remaining_seconds=cooldown_remaining_seconds,
        )

