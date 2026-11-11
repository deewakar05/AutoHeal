"""Automated tests for the FastAPI control plane endpoints."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.src.config import clear_settings_cache
from api.src.main import create_app
from monitoring.src.incident_manager import IncidentManager
from monitoring.src.metrics import MonitorMetrics
from monitoring.src.models import CheckOutcome, HealthCheckResult


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


def test_api_status_incidents_and_prometheus_metrics(api_env: str) -> None:
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

        metrics_resp = client.get("/api/v1/metrics")
        assert metrics_resp.status_code == 200
        body = metrics_resp.text
        assert 'autoheal_health_checks_total{outcome="success",service="web"} 1.0' in body
        assert 'autoheal_health_checks_total{outcome="connection_error",service="web"} 2.0' in body
        assert 'autoheal_incidents_total{event="created",service="web"} 1.0' in body
        assert 'autoheal_service_up{service="web"} 0.0' in body
        assert 'autoheal_open_incidents{service="web"} 1.0' in body
        assert 'autoheal_health_check_duration_seconds_count{service="web"} 3.0' in body
        assert "autoheal_api_requests_total" in body

