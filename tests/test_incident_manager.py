"""Automated tests for threshold state transitions, incident lifecycle, and persistence."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from monitoring.src.incident_manager import IncidentManager
from monitoring.src.metrics import MonitorMetrics
from monitoring.src.models import (
    CheckOutcome,
    HealthCheckResult,
    IncidentStatus,
    ServiceState,
)


def _make_result(healthy: bool, error: str | None = None) -> HealthCheckResult:
    return HealthCheckResult(
        service_name="web",
        target_url="http://web/health",
        healthy=healthy,
        outcome=CheckOutcome.SUCCESS if healthy else CheckOutcome.CONNECTION_ERROR,
        status_code=200 if healthy else None,
        response_time_ms=4.2,
        error=error,
        checked_at=datetime.now(timezone.utc),
    )


def test_failure_threshold_incident_creation_and_deduplication(tmp_path: Path) -> None:
    db_path = str(tmp_path / "autoheal.db")
    manager = IncidentManager(db_path=db_path, failure_threshold=3, recovery_threshold=2)

    # Initial healthy state
    eval_ok = manager.process_check(_make_result(True))
    assert eval_ok.current_state == ServiceState.HEALTHY

    # Failures 1 and 2 must not trigger UNHEALTHY or incident creation
    eval_f1 = manager.process_check(_make_result(False, "Connection refused"))
    eval_f2 = manager.process_check(_make_result(False, "Connection refused"))
    assert eval_f1.current_state == ServiceState.HEALTHY
    assert eval_f2.current_state == ServiceState.HEALTHY
    assert eval_f1.incident_created is None
    assert eval_f2.incident_created is None
    assert manager.list_incidents() == []

    # Failure 3 triggers UNHEALTHY and creates one OPEN incident
    eval_f3 = manager.process_check(_make_result(False, "Connection refused"))
    assert eval_f3.current_state == ServiceState.UNHEALTHY
    assert eval_f3.state_changed is True
    assert eval_f3.incident_created is not None
    assert eval_f3.incident_created.status == IncidentStatus.OPEN
    assert eval_f3.incident_created.failure_count == 3

    # Failures 4 and 5 update existing incident without creating duplicates
    eval_f4 = manager.process_check(_make_result(False, "Timeout"))
    eval_f5 = manager.process_check(_make_result(False, "Timeout"))
    assert eval_f4.incident_created is None
    assert eval_f5.incident_created is None

    incidents = manager.list_incidents()
    assert len(incidents) == 1
    assert incidents[0].status == IncidentStatus.OPEN
    assert incidents[0].failure_count == 5
    assert incidents[0].failure_reason == "Timeout"


def test_recovery_threshold_resolves_incident_and_persists_across_restart(tmp_path: Path) -> None:
    db_path = str(tmp_path / "autoheal.db")
    manager = IncidentManager(db_path=db_path, failure_threshold=2, recovery_threshold=2)

    manager.process_check(_make_result(False, "HTTP 500"))
    eval_down = manager.process_check(_make_result(False, "HTTP 500"))
    assert eval_down.current_state == ServiceState.UNHEALTHY
    assert eval_down.incident_created is not None

    # Simulate container/process restart before recovery
    restarted_manager = IncidentManager(db_path=db_path, failure_threshold=2, recovery_threshold=2)

    # First healthy probe is not enough (recovery_threshold=2)
    eval_s1 = restarted_manager.process_check(_make_result(True))
    assert eval_s1.current_state == ServiceState.UNHEALTHY
    assert eval_s1.incident_resolved is None

    # Second consecutive healthy probe resolves incident and transitions to HEALTHY
    eval_s2 = restarted_manager.process_check(_make_result(True))
    assert eval_s2.current_state == ServiceState.HEALTHY
    assert eval_s2.state_changed is True
    assert eval_s2.incident_resolved is not None
    assert eval_s2.incident_resolved.status == IncidentStatus.RESOLVED
    assert eval_s2.incident_resolved.resolved_at is not None

    # Metrics integration sanity check
    metrics = MonitorMetrics(db_path=db_path)
    metrics.record(_make_result(True), eval_s2)
    prom_text = metrics.render_prometheus()
    assert "autoheal_health_checks_total" in prom_text
    assert "autoheal_service_up" in prom_text

