"""Automated tests for threshold state transitions, incident lifecycle, and persistence."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from remediation.src.incident_manager import IncidentManager
from remediation.src.metrics import MonitorMetrics
from remediation.src.models import (
    CheckOutcome,
    HealthCheckResult,
    IncidentStatus,
    ServiceState,
    StateEvaluation,
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


def test_incident_manager_connection_enforces_foreign_keys(tmp_path: Path) -> None:
    import sqlite3
    db_path = str(tmp_path / "fk.db")
    manager = IncidentManager(db_path=db_path, failure_threshold=2, recovery_threshold=2)

    conn = manager._connect()
    try:
        fk_status = conn.execute("PRAGMA foreign_keys").fetchone()[0]
        assert fk_status == 1

        # Attempting an insert with invalid foreign key reference must fail closed
        with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
            conn.execute(
                """
                INSERT INTO remediation_executions (
                    incident_id, service_name, action, status, attempt_number,
                    dry_run, created_at
                ) VALUES (999999, 'web', 'restart', 'pending', 1, 1, '2026-01-01T00:00:00Z')
                """
            )
    finally:
        conn.close()


def test_metrics_in_memory_state_unmodified_when_sqlite_fails(tmp_path: Path) -> None:
    import sqlite3
    from unittest.mock import patch

    db_path = str(tmp_path / "metrics_fail.db")
    metrics = MonitorMetrics(db_path=db_path)

    initial_checks = metrics.checks_total.labels(service="web", outcome="success")._value.get()
    initial_incidents = metrics.incidents_total.labels(service="web", event="resolved")._value.get()

    # When SQLite persistence fails, in-memory counter must not be incremented
    with patch.object(metrics, "_persist_to_sqlite", side_effect=sqlite3.OperationalError("database is locked")):
        with pytest.raises(sqlite3.OperationalError, match="database is locked"):
            metrics.record(_make_result(True), StateEvaluation(
                previous_state=ServiceState.HEALTHY,
                current_state=ServiceState.HEALTHY,
                state_changed=False,
                consecutive_failures=0,
                consecutive_successes=1,
            ))

    assert metrics.checks_total.labels(service="web", outcome="success")._value.get() == initial_checks

    with patch.object(metrics, "record_incident_resolved_in_tx", side_effect=sqlite3.OperationalError("disk I/O error")):
        with pytest.raises(sqlite3.OperationalError, match="disk I/O error"):
            metrics.record_incident_resolved("web")

    assert metrics.incidents_total.labels(service="web", event="resolved")._value.get() == initial_incidents


def test_concurrent_database_schema_initialization(tmp_path: Path) -> None:
    import concurrent.futures
    from remediation.src.database import ensure_autoheal_database, get_connection

    db_path = str(tmp_path / "concurrent_init.db")
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(ensure_autoheal_database, db_path) for _ in range(5)]
        for f in futures:
            f.result()

    conn = get_connection(db_path)
    try:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert "incidents" in tables
        assert "service_status" in tables
        assert "remediation_executions" in tables
        assert "nagios_events" in tables
    finally:
        conn.close()
