"""Automated unit tests for RemediationPolicy decisions and safety gates."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from remediation.src.models import IncidentRecord, IncidentStatus
from remediation.src.config import RemediationSettings
from remediation.src.models import (
    IncidentSnapshot,
    PolicyReason,
    RemediationAction,
    RemediationRequest,
    RemediationState,
)
from remediation.src.policy import (
    InMemoryIncidentProvider,
    InMemoryRemediationStateProvider,
    RemediationPolicy,
)

BASE_TIME = datetime(2026, 11, 11, 12, 0, 0, tzinfo=timezone.utc)


def _settings(**overrides: object) -> RemediationSettings:
    defaults: dict[str, object] = {
        "_env_file": None,
        "autoheal_remediation_enabled": True,
        "autoheal_remediation_dry_run": True,
        "autoheal_remediation_cooldown_seconds": 300,
        "autoheal_remediation_max_attempts": 3,
        "autoheal_allowed_services": ("web",),
        "autoheal_allowed_actions": ("restart",),
    }
    defaults.update(overrides)
    return RemediationSettings(**defaults)


def _open_incident(incident_id: int = 1, service_name: str = "web") -> IncidentSnapshot:
    return IncidentSnapshot(
        id=incident_id,
        service_name=service_name,
        status="open",
        failure_reason="Connection refused",
        failure_count=3,
    )


def _policy(
    *,
    settings: RemediationSettings | None = None,
    incidents: tuple[object, ...] = (),
    states: dict[tuple[int, str], RemediationState] | None = None,
    now: datetime = BASE_TIME,
) -> RemediationPolicy:
    return RemediationPolicy(
        settings=settings or _settings(),
        incident_provider=InMemoryIncidentProvider(incidents),
        state_provider=InMemoryRemediationStateProvider(states),
        clock=lambda: now,
    )


def test_remediation_disabled_denies_with_safe_default() -> None:
    policy = _policy(
        settings=RemediationSettings(_env_file=None),
        incidents=(_open_incident(),),
    )

    decision = policy.evaluate(
        RemediationRequest(incident_id=1, service_name="web", action=RemediationAction.RESTART)
    )

    assert decision.allowed is False
    assert decision.reason == PolicyReason.REMEDIATION_DISABLED
    assert decision.dry_run is True
    assert decision.service_name == "web"
    assert decision.action == "restart"
    assert decision.incident_id == 1


def test_approved_service_and_action_in_dry_run_mode() -> None:
    policy = _policy(
        settings=_settings(autoheal_remediation_enabled=True, autoheal_remediation_dry_run=True),
        incidents=(_open_incident(),),
    )

    decision = policy.evaluate(
        RemediationRequest(incident_id=1, service_name="web", action="restart")
    )

    assert decision.allowed is True
    assert decision.reason == PolicyReason.POLICY_APPROVED
    assert decision.dry_run is True
    assert decision.service_name == "web"
    assert decision.action == "restart"
    assert decision.incident_id == 1


def test_approved_service_and_action_live_mode_when_explicitly_configured() -> None:
    policy = _policy(
        settings=_settings(autoheal_remediation_enabled=True, autoheal_remediation_dry_run=False),
        incidents=(_open_incident(),),
    )

    decision = policy.evaluate(
        RemediationRequest(incident_id=1, service_name="web", action=RemediationAction.RESTART)
    )

    assert decision.allowed is True
    assert decision.reason == PolicyReason.POLICY_APPROVED
    assert decision.dry_run is False


def test_missing_incident_is_rejected() -> None:
    policy = _policy(incidents=())

    decision = policy.evaluate(
        RemediationRequest(incident_id=999, service_name="web", action="restart")
    )

    assert decision.allowed is False
    assert decision.reason == PolicyReason.INCIDENT_NOT_FOUND
    assert decision.incident_id == 999


def test_incident_belonging_to_different_service_is_rejected() -> None:
    policy = _policy(incidents=(_open_incident(incident_id=1, service_name="api"),))

    decision = policy.evaluate(
        RemediationRequest(incident_id=1, service_name="web", action="restart")
    )

    assert decision.allowed is False
    assert decision.reason == PolicyReason.INCIDENT_NOT_FOUND


def test_resolved_incident_is_rejected() -> None:
    resolved = IncidentSnapshot(
        id=2,
        service_name="web",
        status="resolved",
        resolved_at=BASE_TIME - timedelta(minutes=1),
    )
    policy = _policy(incidents=(resolved,))

    decision = policy.evaluate(
        RemediationRequest(incident_id=2, service_name="web", action="restart")
    )

    assert decision.allowed is False
    assert decision.reason == PolicyReason.INCIDENT_ALREADY_RESOLVED
    assert decision.incident_id == 2


def test_rejected_service_including_unsafe_input() -> None:
    unlisted_incident = _open_incident(incident_id=3, service_name="database")
    unsafe_incident = _open_incident(incident_id=4, service_name="web; rm -rf /")
    policy = _policy(incidents=(unlisted_incident, unsafe_incident))

    decision_unlisted = policy.evaluate(
        RemediationRequest(incident_id=3, service_name="database", action="restart")
    )
    decision_unsafe = policy.evaluate(
        RemediationRequest(incident_id=4, service_name="web; rm -rf /", action="restart")
    )

    assert decision_unlisted.allowed is False
    assert decision_unlisted.reason == PolicyReason.SERVICE_NOT_ALLOWED
    assert decision_unsafe.allowed is False
    assert decision_unsafe.reason == PolicyReason.SERVICE_NOT_ALLOWED


def test_rejected_action_including_arbitrary_command() -> None:
    policy = _policy(incidents=(_open_incident(),))

    decision_start = policy.evaluate(
        RemediationRequest(incident_id=1, service_name="web", action=RemediationAction.START)
    )
    decision_shell = policy.evaluate(
        RemediationRequest(incident_id=1, service_name="web", action="/bin/sh -c evil")
    )

    assert decision_start.allowed is False
    assert decision_start.reason == PolicyReason.ACTION_NOT_ALLOWED
    assert decision_shell.allowed is False
    assert decision_shell.reason == PolicyReason.ACTION_NOT_ALLOWED


def test_maximum_attempts_reached_denies_remediation() -> None:
    policy = _policy(
        incidents=(_open_incident(),),
        states={
            (1, "web"): RemediationState(
                attempts=3,
                last_attempt_at=BASE_TIME - timedelta(seconds=10),
                is_running=False,
            )
        },
    )

    decision = policy.evaluate(
        RemediationRequest(incident_id=1, service_name="web", action="restart")
    )

    assert decision.allowed is False
    assert decision.reason == PolicyReason.MAX_ATTEMPTS_REACHED


def test_active_cooldown_and_expiry_boundary() -> None:
    states = {
        (1, "web"): RemediationState(
            attempts=1,
            last_attempt_at=BASE_TIME - timedelta(seconds=120),
            is_running=False,
        )
    }

    active_policy = _policy(incidents=(_open_incident(),), states=states, now=BASE_TIME)
    blocked = active_policy.evaluate(
        RemediationRequest(incident_id=1, service_name="web", action="restart")
    )
    assert blocked.allowed is False
    assert blocked.reason == PolicyReason.COOLDOWN_ACTIVE
    assert blocked.cooldown_remaining_seconds == 180.0

    # At exact cooldown boundary (120 + 180 = 300 seconds elapsed), remediation is approved.
    expired_policy = _policy(
        incidents=(_open_incident(),),
        states=states,
        now=BASE_TIME + timedelta(seconds=180),
    )
    approved = expired_policy.evaluate(
        RemediationRequest(incident_id=1, service_name="web", action="restart")
    )
    assert approved.allowed is True
    assert approved.reason == PolicyReason.POLICY_APPROVED
    assert approved.dry_run is True


def test_duplicate_running_remediation_is_rejected() -> None:
    policy = _policy(
        incidents=(_open_incident(),),
        states={
            (1, "web"): RemediationState(
                attempts=1,
                last_attempt_at=BASE_TIME - timedelta(seconds=5),
                is_running=True,
            )
        },
    )

    decision = policy.evaluate(
        RemediationRequest(incident_id=1, service_name="web", action="restart")
    )

    assert decision.allowed is False
    assert decision.reason == PolicyReason.REMEDIATION_ALREADY_RUNNING


def test_compatibility_with_monitoring_incident_record() -> None:
    record = IncidentRecord(
        id=7,
        service_name="web",
        status=IncidentStatus.OPEN,
        failure_reason="HTTP error status 503",
        started_at=BASE_TIME - timedelta(minutes=2),
        resolved_at=None,
        last_seen_at=BASE_TIME - timedelta(seconds=10),
        failure_count=4,
    )
    policy = _policy(incidents=(record,))

    decision = policy.evaluate(
        RemediationRequest(incident_id=7, service_name="web", action="restart")
    )

    assert decision.allowed is True
    assert decision.reason == PolicyReason.POLICY_APPROVED
    assert decision.incident_id == 7
