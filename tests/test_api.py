"""Automated tests for the FastAPI control plane endpoints."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.src.config import clear_settings_cache
from api.src.main import create_app
from remediation.src.incident_manager import IncidentManager
from remediation.src.metrics import MonitorMetrics
from remediation.src.models import CheckOutcome, HealthCheckResult


def _probe(healthy: bool, error: str | None = None) -> HealthCheckResult:
    return HealthCheckResult(
        service_name="web",
        target_url="http://web/health",
        healthy=healthy,
        outcome=CheckOutcome.SUCCESS if healthy else CheckOutcome.CONNECTION_ERROR,
        status_code=200 if healthy else None,
        response_time_ms=12.5,
        error=error,
        checked_at=datetime.now(timezone.utc),
    )


@pytest.fixture()
def api_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    db_path = str(tmp_path / "autoheal.db")
    monkeypatch.setenv("AUTOHEAL_DB_PATH", db_path)
    monkeypatch.setenv("MONITOR_TARGET_SERVICE", "web")
    monkeypatch.setenv("MONITOR_TARGET_URL", "http://web/health")
    monkeypatch.setenv("MONITOR_ENABLED", "true")
    clear_settings_cache()
    yield db_path
    clear_settings_cache()


def test_api_health_and_unknown_initial_status(api_env: str) -> None:
    app = create_app()
    with TestClient(app) as client:
        health_resp = client.get("/health")
        assert health_resp.status_code == 200
        assert health_resp.json() == {
            "status": "healthy",
            "service": "api",
            "database": "connected",
        }

        status_resp = client.get("/api/v1/status")
        assert status_resp.status_code == 200
        status_body = status_resp.json()
        assert status_body["service_name"] == "web"
        assert status_body["status"] == "unknown"

        incidents_resp = client.get("/api/v1/incidents")
        assert incidents_resp.status_code == 200
        assert incidents_resp.json() == {"total": 0, "open_count": 0, "incidents": []}


def test_api_status_and_incidents(api_env: str) -> None:
    manager = IncidentManager(db_path=api_env, failure_threshold=2, recovery_threshold=2)
    metrics = MonitorMetrics(db_path=api_env)

    for res in [
        _probe(True),
        _probe(False, "Connection refused"),
        _probe(False, "Connection refused"),
    ]:
        ev = manager.process_check(res)
        metrics.record(res, ev)

    app = create_app()
    with TestClient(app) as client:
        status_resp = client.get("/api/v1/status")
        assert status_resp.status_code == 200
        status_data = status_resp.json()
        assert status_data["status"] == "unhealthy"
        assert status_data["consecutive_failures"] == 2
        assert status_data["active_incident_id"] == 1

        incidents_resp = client.get("/api/v1/incidents?status=open")
        assert incidents_resp.status_code == 200
        incidents_data = incidents_resp.json()
        assert incidents_data["total"] == 1
        assert incidents_data["open_count"] == 1
        assert incidents_data["incidents"][0]["failure_reason"] == "Connection refused"

        single_resp = client.get("/api/v1/incidents/1")
        assert single_resp.status_code == 200
        assert single_resp.json()["status"] == "open"

        missing_resp = client.get("/api/v1/incidents/999")
        assert missing_resp.status_code == 404


def test_api_remediation_routes_filtering_masking_and_metrics(
    api_env: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from datetime import timedelta

    from remediation.src.config import RemediationSettings
    from remediation.src.metrics_store import RemediationMetricsRecorder
    from remediation.src.models import RemediationRequest, RemediationStatus
    from remediation.src.repository import RemediationRepository

    monkeypatch.setenv("AUTOHEAL_REMEDIATION_ENABLED", "true")
    monkeypatch.setenv("AUTOHEAL_REMEDIATION_DRY_RUN", "false")
    monkeypatch.setenv("AUTOHEAL_REMEDIATION_COOLDOWN_SECONDS", "300")
    monkeypatch.setenv("AUTOHEAL_REMEDIATION_MAX_ATTEMPTS", "2")
    monkeypatch.setenv("AUTOHEAL_REMEDIATION_DISPATCH_MODE", "queue")

    manager = IncidentManager(db_path=api_env, failure_threshold=2, recovery_threshold=2)
    manager.process_check(_probe(False, "Connection refused"))
    manager.process_check(_probe(False, "Connection refused"))

    repo = RemediationRepository(api_env)
    metrics_recorder = RemediationMetricsRecorder(api_env)
    live_settings = RemediationSettings(_env_file=None, autoheal_db_path=api_env)

    t0 = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    res1 = repo.reserve_execution(
        RemediationRequest(incident_id=1, service_name="web", action="restart"),
        live_settings,
        initial_status=RemediationStatus.RUNNING,
        now=t0,
    )
    assert res1.reserved and res1.execution is not None
    metrics_recorder.record_attempt(res1.execution)
    # Duplicate record_attempt for same execution must not double-count.
    assert metrics_recorder.record_attempt(res1.execution) is False

    failed_exec = repo.update_status(
        res1.execution.id,
        RemediationStatus.FAILED,
        ansible_exit_code=2,
        execution_output=(
            "Authorization: Bearer super-secret-jwt-value\n"
            "token=my-secret-token\n"
            "-----BEGIN RSA PRIVATE KEY-----\nSECRETKEYDATA\n-----END RSA PRIVATE KEY-----"
        ),
        failure_reason="Ansible failed with password=topsecret",
        completed_at=t0 + timedelta(seconds=4),
        now=t0 + timedelta(seconds=4),
    )
    metrics_recorder.record_terminal(failed_exec, max_attempts=2, failure_outcome="ansible_failed")
    assert (
        metrics_recorder.record_terminal(failed_exec, max_attempts=2, failure_outcome="ansible_failed")
        is False
    )

    monkeypatch.setenv("AUTOHEAL_REMEDIATION_COOLDOWN_SECONDS", "0")
    monkeypatch.setenv("AUTOHEAL_REMEDIATION_DRY_RUN", "true")
    dry_settings = RemediationSettings(_env_file=None, autoheal_db_path=api_env)
    t1 = t0 + timedelta(minutes=10)
    res2 = repo.reserve_execution(
        RemediationRequest(incident_id=1, service_name="web", action="restart"),
        dry_settings,
        initial_status=RemediationStatus.RUNNING,
        now=t1,
    )
    assert res2.reserved and res2.execution is not None
    dry_exec = repo.update_status(
        res2.execution.id,
        RemediationStatus.DRY_RUN,
        ansible_exit_code=0,
        execution_output="Simulated dry-run plan",
        completed_at=t1 + timedelta(seconds=1),
        now=t1 + timedelta(seconds=1),
    )
    metrics_recorder.record_attempt(res2.execution)
    metrics_recorder.record_terminal(dry_exec, max_attempts=2)

    monkeypatch.setenv("AUTOHEAL_REMEDIATION_COOLDOWN_SECONDS", "300")
    monkeypatch.setenv("AUTOHEAL_REMEDIATION_DRY_RUN", "false")

    app = create_app()
    with TestClient(app) as client:
        # Unauthenticated POST manual remediation execution must NOT exist.
        post_resp = client.post("/api/v1/remediations", json={"incident_id": 1})
        assert post_resp.status_code in (404, 405)

        policies_resp = client.get("/api/v1/remediations/policies")
        assert policies_resp.status_code == 200
        policies = policies_resp.json()
        assert policies["remediation_enabled"] is True
        assert policies["max_attempts"] == 2
        assert policies["manual_execution_endpoint_enabled"] is False
        assert "authentication" in policies["manual_execution_policy_note"].lower()

        status_resp = client.get("/api/v1/remediations/status")
        assert status_resp.status_code == 200
        status_body = status_resp.json()
        assert status_body["remediation_enabled"] is True
        assert status_body["dispatch_mode"] == "queue"
        assert status_body["total_attempts"] == 2
        assert status_body["failed_attempts"] == 1
        assert status_body["dry_run_attempts"] == 1
        assert status_body["exhausted_incidents"] == 1

        list_resp = client.get("/api/v1/remediations?limit=1&offset=0")
        assert list_resp.status_code == 200
        list_data = list_resp.json()
        assert list_data["total"] == 2
        assert len(list_data["items"]) == 1
        assert list_data["items"][0]["id"] == dry_exec.id

        failed_only = client.get("/api/v1/remediations?status=failed&dry_run=false&service_name=web")
        assert failed_only.status_code == 200
        assert failed_only.json()["total"] == 1
        assert failed_only.json()["items"][0]["id"] == failed_exec.id

        windowed = client.get(
            "/api/v1/remediations",
            params={
                "incident_id": 1,
                "started_after": "2026-06-01T12:05:00Z",
                "started_before": "2026-06-01T12:15:00Z",
            },
        )
        assert windowed.status_code == 200
        assert windowed.json()["total"] == 1
        assert windowed.json()["items"][0]["id"] == dry_exec.id

        bad_range = client.get(
            "/api/v1/remediations",
            params={
                "started_after": "2026-06-01T13:00:00Z",
                "started_before": "2026-06-01T12:00:00Z",
            },
        )
        assert bad_range.status_code == 422

        detail_resp = client.get(f"/api/v1/remediations/{failed_exec.id}")
        assert detail_resp.status_code == 200
        detail = detail_resp.json()
        assert "super-secret-jwt-value" not in detail["execution_output"]
        assert "my-secret-token" not in detail["execution_output"]
        assert "SECRETKEYDATA" not in detail["execution_output"]
        assert "topsecret" not in detail["failure_reason"]
        assert "[REDACTED_PRIVATE_KEY]" in detail["execution_output"]

        assert client.get("/api/v1/remediations/9999").status_code == 404
        assert client.get("/api/v1/remediations/0").status_code == 422
        assert client.get("/api/v1/incidents/0").status_code == 422


def test_api_health_503_redacts_internal_exception_details(
    api_env: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _ = api_env
    monkeypatch.setattr(
        "api.src.routes.health.check_database_health",
        lambda *_a, **_kw: (_ for _ in ()).throw(
            RuntimeError("sqlite path /secret/internal/autoheal.db error")
        ),
    )
    app = create_app()
    with TestClient(app) as client:
        resp = client.get("/health")
    assert resp.status_code == 503
    body = resp.json()
    assert body["detail"] == {
        "status": "unhealthy",
        "service": "api",
        "database": "unavailable",
    }
    assert "/secret/internal" not in resp.text
