"""Comprehensive unit, security, concurrency, and end-to-end tests for Nagios + Ansible integration."""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from api.src.config import clear_settings_cache
from api.src.main import create_app
from nagios.nrpe import check_mem
from nagios.scripts import nagios_notify
from remediation.src.config import RemediationSettings
from remediation.src.execution_manager import ExecutionManager
from remediation.src.execution_models import AnsibleRunResult
from remediation.src.executor import RemediationExecutor
from remediation.src.incident_manager import IncidentManager
from remediation.src.models import CheckOutcome, HealthCheckResult, RemediationStatus
from remediation.src.nagios_probe import NagiosStatusProber
from remediation.src.nagios_models import (
    NagiosAlertEvent,
    NagiosProcessingOutcome,
    parse_nagios_service_map,
    resolve_mapped_service,
)
from remediation.src.nagios_service import NagiosAlertService
from remediation.src.repository import RemediationRepository
from remediation.src.verifier import RecoveryVerifier
from remediation.src.worker import ExecutorWorker


def _setup_api_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    webhook_secret: str | None = "test-nagios-secret-value",
    enabled: bool = False,
    dry_run: bool = True,
    dispatch_mode: str = "queue",
) -> str:
    db_path = str(tmp_path / "autoheal.db")
    monkeypatch.setenv("AUTOHEAL_DB_PATH", db_path)
    monkeypatch.setenv("AUTOHEAL_NAGIOS_ENABLED", "true")
    monkeypatch.setenv("AUTOHEAL_NAGIOS_WEBHOOK_SECRET", webhook_secret or "")
    monkeypatch.setenv("AUTOHEAL_NAGIOS_SERVICE_MAP", "")
    monkeypatch.setenv("AUTOHEAL_REMEDIATION_ENABLED", "true" if enabled else "false")
    monkeypatch.setenv("AUTOHEAL_REMEDIATION_DRY_RUN", "true" if dry_run else "false")
    monkeypatch.setenv("AUTOHEAL_REMEDIATION_DISPATCH_MODE", dispatch_mode)
    monkeypatch.setenv("AUTOHEAL_ALLOWED_SERVICES", "web")
    monkeypatch.setenv("AUTOHEAL_ALLOWED_ACTIONS", "restart")
    monkeypatch.setenv("AUTOHEAL_REMEDIATION_COOLDOWN_SECONDS", "300")
    monkeypatch.setenv("AUTOHEAL_REMEDIATION_MAX_ATTEMPTS", "3")
    clear_settings_cache()
    return db_path


def _problem_payload(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "notification_kind": "service",
        "notification_type": "PROBLEM",
        "host_name": "autoheal-web",
        "service_name": "Web HTTP Health",
        "state": "CRITICAL",
        "state_type": "HARD",
        "attempt": 3,
        "max_attempts": 3,
        "output": "CRITICAL - Socket timeout after 3 seconds",
        "event_timestamp": "2026-11-11T12:00:00Z",
        "nagios_problem_id": "101",
        "nagios_notification_id": "501",
    }
    base.update(overrides)
    return base


def test_nagios_payload_validation_and_secret_sanitization() -> None:
    event = NagiosAlertEvent(
        notification_kind="service",
        notification_type="problem",
        host_name="AutoHeal-Web",
        service_name="Web HTTP Health",
        state="critical",
        state_type="hard",
        attempt=3,
        max_attempts=3,
        output="CRITICAL Bearer abcdef12345 token=topsecret\x00\x07",
        event_timestamp=1762862400,
    )
    assert event.host_name == "autoheal-web"
    assert event.notification_type == "PROBLEM"
    assert event.state == "CRITICAL"
    assert event.state_type == "HARD"
    assert "abcdef12345" not in event.output
    assert "topsecret" not in event.output

    svc_map = parse_nagios_service_map("custom-host:*=customsvc")
    assert resolve_mapped_service(event, svc_map) == "web"

    # Spoofed target_service cannot override explicitly mapped host.
    spoof = NagiosAlertEvent(
        **_problem_payload(target_service="api"),
    )
    assert resolve_mapped_service(spoof, svc_map) == "web"

    # Invalid hostnames / mismatched host vs service states / boolean timestamps are rejected.
    with pytest.raises(ValidationError):
        NagiosAlertEvent(**_problem_payload(host_name="web;rm -rf /"))
    with pytest.raises(ValidationError):
        NagiosAlertEvent(**_problem_payload(notification_kind="host", state="CRITICAL"))
    with pytest.raises(ValidationError):
        NagiosAlertEvent(**_problem_payload(notification_kind="service", state="DOWN"))
    with pytest.raises(ValidationError):
        NagiosAlertEvent(**_problem_payload(event_timestamp=True))
    with pytest.raises(ValidationError):
        NagiosAlertEvent(**_problem_payload(state_type="INVALID"))


def test_nagios_webhook_authentication_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _setup_api_env(monkeypatch, tmp_path, webhook_secret=None)
    app = create_app()
    with TestClient(app) as client:
        unconf = client.post(
            "/api/v1/monitoring/nagios/alerts",
            json=_problem_payload(),
            headers={"X-Nagios-Token": "anything"},
        )
        assert unconf.status_code == 503
        with sqlite3.connect(tmp_path / "autoheal.db") as db_conn:
            row = db_conn.execute("SELECT * FROM nagios_counters WHERE labels_json LIKE '%auth_unconfigured%'").fetchone()
            assert row is not None

    _setup_api_env(monkeypatch, tmp_path / "with_secret", webhook_secret="strong-shared-secret")
    app2 = create_app()
    with TestClient(app2) as client:
        missing = client.post("/api/v1/monitoring/nagios/alerts", json=_problem_payload())
        assert missing.status_code == 401
        missing_empty = client.post("/api/v1/monitoring/nagios/alerts", json={})
        assert missing_empty.status_code == 401
        wrong = client.post(
            "/api/v1/monitoring/nagios/alerts",
            json={},
            headers={"X-Nagios-Token": "wrong-secret"},
        )
        assert wrong.status_code == 401
        assert "strong-shared-secret" not in wrong.text

        invalid_authed = client.post(
            "/api/v1/monitoring/nagios/alerts",
            json={},
            headers={"X-Nagios-Token": "strong-shared-secret"},
        )
        assert invalid_authed.status_code == 422

        # Both X-Nagios-Token and Authorization: Bearer are supported cleanly.
        ok1 = client.post(
            "/api/v1/monitoring/nagios/alerts",
            json=_problem_payload(event_id="auth-header-x"),
            headers={"X-Nagios-Token": "strong-shared-secret"},
        )
        assert ok1.status_code == 200
        assert ok1.json()["incident_id"] == 1

        ok2 = client.post(
            "/api/v1/monitoring/nagios/alerts",
            json=_problem_payload(
                event_id="auth-header-bearer",
                event_timestamp="2026-11-11T12:00:05Z",
            ),
            headers={"Authorization": "Bearer strong-shared-secret"},
        )
        assert ok2.status_code == 200
        assert ok2.json()["incident_id"] == 1

        # X-AutoHeal-Signature token and singular /alert route alias
        ok3 = client.post(
            "/api/v1/monitoring/nagios/alert",
            json=_problem_payload(
                event_id="auth-header-autoheal-alias",
                event_timestamp="2026-11-11T12:00:10Z",
            ),
            headers={"X-AutoHeal-Signature": "strong-shared-secret"},
        )
        assert ok3.status_code == 200
        assert ok3.json()["incident_id"] == 1

        # HMAC-SHA256 digest signature verification
        body_bytes = json.dumps(_problem_payload(
            event_id="auth-hmac-sha256",
            event_timestamp="2026-11-11T12:00:15Z",
        )).encode("utf-8")
        computed_sig = hmac.new(b"strong-shared-secret", body_bytes, hashlib.sha256).hexdigest()

        # Invalid HMAC signature rejected with 401
        invalid_hmac = client.post(
            "/api/v1/monitoring/nagios/alerts",
            content=body_bytes,
            headers={"Content-Type": "application/json", "X-AutoHeal-Signature": "sha256=invalidhex00000000000000000000000000000000000000000000000000000000"},
        )
        assert invalid_hmac.status_code == 401

        # Valid HMAC signature accepted
        ok4 = client.post(
            "/api/v1/monitoring/nagios/alerts",
            content=body_bytes,
            headers={"Content-Type": "application/json", "X-AutoHeal-Signature": f"sha256={computed_sig}"},
        )
        assert ok4.status_code == 200
        assert ok4.json()["incident_id"] == 1
        with sqlite3.connect(tmp_path / "with_secret" / "autoheal.db") as db_conn:
            row = db_conn.execute("SELECT * FROM nagios_counters WHERE labels_json LIKE '%auth_failed%'").fetchone()
            assert row is not None


def test_nagios_dedup_soft_warning_and_concurrent_retries(tmp_path: Path) -> None:
    db_path = str(tmp_path / "autoheal.db")
    settings = RemediationSettings(
        _env_file=None,
        autoheal_db_path=db_path,
        autoheal_remediation_enabled=True,
        autoheal_remediation_dry_run=False,
        autoheal_remediation_dispatch_mode="queue",
    )
    service = NagiosAlertService(settings)

    # 1. SOFT CRITICAL and WARNING/UNKNOWN must not open incidents or queue remediation.
    soft = service.process_alert(NagiosAlertEvent(**_problem_payload(state_type="SOFT", attempt=1)))
    assert soft.outcome == NagiosProcessingOutcome.IGNORED_SOFT_STATE
    assert soft.incident_id is None
    assert not soft.remediation_queued

    warn = service.process_alert(NagiosAlertEvent(**_problem_payload(state="WARNING", event_id="w1")))
    assert warn.outcome == NagiosProcessingOutcome.IGNORED_NON_CRITICAL
    assert not warn.remediation_queued

    # 2. Concurrent delivery of identical HARD CRITICAL dedupes strictly to 1 incident + 1 queued job.
    event = NagiosAlertEvent(**_problem_payload(event_id="same-hard-1"))
    with ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = list(pool.map(lambda _: service.process_alert(event), range(4)))

    queued = [o for o in outcomes if not o.duplicate]
    dups = [o for o in outcomes if o.duplicate]
    assert len(queued) == 1
    assert len(dups) == 3
    assert queued[0].outcome == NagiosProcessingOutcome.REMEDIATION_QUEUED
    assert queued[0].incident_id == 1
    assert queued[0].execution_id == 1

    repo = RemediationRepository(db_path)
    assert len(repo.list_executions()) == 1


def test_nagios_coexists_with_internal_monitor_without_duplicate_incidents(tmp_path: Path) -> None:
    db_path = str(tmp_path / "autoheal.db")
    manager = IncidentManager(db_path=db_path, failure_threshold=2, recovery_threshold=2)
    settings = RemediationSettings(
        _env_file=None,
        autoheal_db_path=db_path,
        autoheal_remediation_enabled=False,
        autoheal_remediation_dry_run=True,
    )
    nagios_svc = NagiosAlertService(settings)

    # Case A: Internal monitor opens incident -> Nagios merges without creating a 2nd open incident.
    t0 = datetime(2026, 11, 11, 12, 0, 0, tzinfo=timezone.utc)
    for idx in range(2):
        manager.process_check(
            HealthCheckResult(
                service_name="web",
                target_url="http://web/health",
                healthy=False,
                outcome=CheckOutcome.CONNECTION_ERROR,
                status_code=None,
                response_time_ms=5.0,
                error="Connection refused",
                checked_at=t0 + timedelta(seconds=idx * 5),
            )
        )

    nagios_res = nagios_svc.process_alert(
        NagiosAlertEvent(**_problem_payload(event_timestamp=t0 + timedelta(seconds=10)))
    )
    assert nagios_res.outcome == NagiosProcessingOutcome.INCIDENT_UPDATED
    assert nagios_res.incident_created is False
    assert nagios_res.incident_id == 1

    incidents = manager.list_incidents("web")
    assert len(incidents) == 1
    assert incidents[0].source == "internal_monitor+nagios"
    assert incidents[0].nagios_alert_count == 1
    assert incidents[0].nagios_state == "CRITICAL"

    # Case B: Nagios opens incident -> Internal monitor fails -> upgrades same row cleanly.
    db2 = str(tmp_path / "nagios_first.db")
    mgr2 = IncidentManager(db_path=db2, failure_threshold=2, recovery_threshold=2)
    rem2 = RemediationSettings(_env_file=None, autoheal_db_path=db2, autoheal_remediation_enabled=False)
    nag2 = NagiosAlertService(rem2)
    out2 = nag2.process_alert(NagiosAlertEvent(**_problem_payload(event_timestamp=t0)))
    assert out2.incident_created is True
    mgr2.process_check(
        HealthCheckResult(
            service_name="web",
            target_url="http://web/health",
            healthy=False,
            outcome=CheckOutcome.TIMEOUT,
            status_code=None,
            response_time_ms=3000.0,
            error="Timed out",
            checked_at=t0 + timedelta(seconds=5),
        )
    )
    inc2 = mgr2.list_incidents("web")
    assert len(inc2) == 1
    assert inc2[0].source == "internal_monitor+nagios"


def test_nagios_recovery_ordering_flapping_and_active_remediation_deferral(tmp_path: Path) -> None:
    db_path = str(tmp_path / "autoheal.db")
    settings = RemediationSettings(
        _env_file=None,
        autoheal_db_path=db_path,
        autoheal_remediation_enabled=True,
        autoheal_remediation_dry_run=False,
        autoheal_remediation_dispatch_mode="queue",
    )
    svc = NagiosAlertService(settings)
    repo = RemediationRepository(db_path)

    # 1. Recovery when no open incident exists -> ignored cleanly.
    no_open = svc.process_alert(
        NagiosAlertEvent(
            **_problem_payload(
                notification_type="RECOVERY",
                state="OK",
                event_timestamp="2026-11-11T12:00:00Z",
                event_id="rec-none",
            )
        )
    )
    assert no_open.outcome == NagiosProcessingOutcome.IGNORED_NO_OPEN_INCIDENT

    # 2. Flapping marks incident and blocks queuing.
    svc.process_alert(
        NagiosAlertEvent(
            **_problem_payload(
                event_timestamp="2026-11-11T12:01:00Z",
                flapping=True,
                event_id="prob-flap",
            )
        )
    )
    assert len(repo.list_executions()) == 0
    svc.process_alert(
        NagiosAlertEvent(
            **_problem_payload(
                notification_type="FLAPPINGSTOP",
                state="CRITICAL",
                event_timestamp="2026-11-11T12:01:10Z",
                event_id="flap-stop",
            )
        )
    )

    # 3. Stale recovery older than last_problem_at -> rejected without resolving.
    stale = svc.process_alert(
        NagiosAlertEvent(
            **_problem_payload(
                notification_type="RECOVERY",
                state="OK",
                event_timestamp="2026-11-11T11:59:00Z",
                event_id="rec-stale",
            )
        )
    )
    assert stale.outcome == NagiosProcessingOutcome.IGNORED_STALE_RECOVERY

    # 4. Active RUNNING remediation -> recovery defers resolution to RecoveryVerifier.
    queued = svc.process_alert(
        NagiosAlertEvent(
            **_problem_payload(
                event_timestamp="2026-11-11T12:01:20Z",
                event_id="prob-after-flap",
            )
        )
    )
    assert queued.remediation_queued is True
    assert repo.claim_pending_execution(queued.execution_id) is not None

    deferred = svc.process_alert(
        NagiosAlertEvent(
            **_problem_payload(
                notification_type="RECOVERY",
                state="OK",
                event_timestamp="2026-11-11T12:01:30Z",
                event_id="rec-during-running",
            )
        )
    )
    assert deferred.outcome == NagiosProcessingOutcome.DEFERRED_ACTIVE_REMEDIATION

    # 5. Once no RUNNING remediation is active, valid non-stale RECOVERY resolves cleanly.
    repo.update_status(queued.execution_id, RemediationStatus.FAILED, failure_reason="test-end")
    resolved = svc.process_alert(
        NagiosAlertEvent(
            **_problem_payload(
                notification_type="RECOVERY",
                state="OK",
                event_timestamp="2026-11-11T12:02:00Z",
                event_id="rec-valid",
            )
        )
    )
    assert resolved.outcome == NagiosProcessingOutcome.INCIDENT_RESOLVED
    assert resolved.incident_resolved is True


def test_nagios_policy_gates_block_disallowed_disabled_cooldown_and_max_attempts(
    tmp_path: Path,
) -> None:
    db_path = str(tmp_path / "autoheal.db")

    # Disabled default does not reserve remediation.
    disabled_svc = NagiosAlertService(
        RemediationSettings(_env_file=None, autoheal_db_path=db_path, autoheal_remediation_enabled=False)
    )
    out_dis = disabled_svc.process_alert(NagiosAlertEvent(**_problem_payload(event_id="g-dis")))
    assert out_dis.policy_reason == "REMEDIATION_DISABLED"
    assert not out_dis.remediation_queued

    # Disallowed service rejected even when enabled=True.
    enabled_settings = RemediationSettings(
        _env_file=None,
        autoheal_db_path=db_path,
        autoheal_remediation_enabled=True,
        autoheal_remediation_dry_run=True,
        autoheal_remediation_max_attempts=1,
        autoheal_remediation_cooldown_seconds=300,
    )
    enabled_svc = NagiosAlertService(enabled_settings)
    out_other = enabled_svc.process_alert(
        NagiosAlertEvent(
            **_problem_payload(
                host_name="autoheal-api",
                service_name="API Health",
                event_id="g-api",
            )
        )
    )
    assert out_other.mapped_service == "api"
    assert out_other.policy_reason == "SERVICE_NOT_ALLOWED"
    assert not out_other.remediation_queued

    # Dry-run queues with dry_run=True; second alert within max_attempts/running is blocked.
    out_dry = enabled_svc.process_alert(NagiosAlertEvent(**_problem_payload(event_id="g-dry-1")))
    assert out_dry.outcome == NagiosProcessingOutcome.REMEDIATION_QUEUED
    assert out_dry.dry_run is True

    out_dup_running = enabled_svc.process_alert(
        NagiosAlertEvent(**_problem_payload(event_id="g-dry-2", event_timestamp="2026-11-11T12:00:10Z"))
    )
    assert not out_dup_running.remediation_queued
    assert out_dup_running.policy_reason == "REMEDIATION_ALREADY_RUNNING"

    # Mark attempt 1 terminal -> hit MAX_ATTEMPTS_REACHED on attempt 2.
    repo = RemediationRepository(db_path)
    repo.update_status(out_dry.execution_id, RemediationStatus.FAILED, failure_reason="test")
    out_max = enabled_svc.process_alert(
        NagiosAlertEvent(**_problem_payload(event_id="g-dry-3", event_timestamp="2026-11-11T12:00:20Z"))
    )
    assert not out_max.remediation_queued
    assert out_max.policy_reason == "MAX_ATTEMPTS_REACHED"


@pytest.mark.asyncio
async def test_nagios_end_to_end_automated_recovery_and_failure_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = _setup_api_env(
        monkeypatch,
        tmp_path,
        webhook_secret="e2e-nagios-secret",
        enabled=True,
        dry_run=False,
        dispatch_mode="queue",
    )

    class _FakeAnsibleRunner:
        def __init__(self, exit_code: int = 0) -> None:
            self.exit_code = exit_code
            self.calls: list[tuple[str, str]] = []

        def run(
            self,
            *,
            service_name: str,
            action: str,
            timeout_seconds: float,
            cancel_event=None,
        ) -> AnsibleRunResult:
            _ = (timeout_seconds, cancel_event)
            self.calls.append((service_name, action))
            output = f"PLAY RECAP exit={self.exit_code} secret=never-leak-me"
            return AnsibleRunResult(
                succeeded=(self.exit_code == 0),
                exit_code=self.exit_code,
                timed_out=False,
                duration_seconds=0.25,
                playbook="remediation/recover.yml",
                stdout=output,
                stderr="",
                combined_output=output,
                error=None if self.exit_code == 0 else f"Ansible exited with code {self.exit_code}",
            )

    async def _no_sleep(_seconds: float) -> None:
        return None

    def _make_verifier(*, healthy: bool) -> RecoveryVerifier:
        async def _probe() -> HealthCheckResult:
            return HealthCheckResult(
                service_name="web",
                target_url="http://web/health",
                healthy=healthy,
                outcome=CheckOutcome.SUCCESS if healthy else CheckOutcome.UNEXPECTED_STATUS,
                status_code=200 if healthy else 503,
                response_time_ms=10.5,
                error=None if healthy else "HTTP 503",
                checked_at=datetime.now(timezone.utc),
            )

        return RecoveryVerifier(settings, probe_fn=_probe, sleep_fn=_no_sleep)

    settings = RemediationSettings(
        _env_file=None,
        autoheal_db_path=db_path,
        autoheal_remediation_enabled=True,
        autoheal_remediation_dry_run=False,
        autoheal_remediation_dispatch_mode="queue",
        autoheal_remediation_require_isolation=False,
    )
    runner = _FakeAnsibleRunner(exit_code=0)
    verifier = _make_verifier(healthy=True)
    exec_mgr = ExecutionManager(
        settings,
        executor=RemediationExecutor(settings, runner=runner),
        verifier=verifier,
    )
    worker = ExecutorWorker(settings, execution_manager=exec_mgr)

    app = create_app()
    with TestClient(app) as client:
        # Step 1: Nagios posts CRITICAL -> incident #1 + PENDING remediation #1.
        resp = client.post(
            "/api/v1/monitoring/nagios/alerts",
            json=_problem_payload(event_id="e2e-crit-1"),
            headers={"X-Nagios-Token": "e2e-nagios-secret"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["outcome"] == "remediation_queued"
        assert body["incident_id"] == 1
        assert body["execution_id"] == 1

        # Step 2: Isolated worker drains queue and executes Ansible + RecoveryVerifier.
        scheduled = await worker.run_once()
        assert scheduled == 1
        await worker.drain(timeout=5.0)
        assert len(runner.calls) == 1

        # Step 3: Verify incident resolved, execution succeeded, secret redacted.
        inc_resp = client.get("/api/v1/incidents/1")
        assert inc_resp.status_code == 200
        assert inc_resp.json()["status"] == "resolved"
        assert inc_resp.json()["source"] == "nagios"

        exec_resp = client.get("/api/v1/remediations/1")
        assert exec_resp.status_code == 200
        assert exec_resp.json()["status"] == "succeeded"
        assert "never-leak-me" not in (exec_resp.json()["execution_output"] or "")

        # Step 4: Late Nagios RECOVERY arrives after AutoHeal already resolved incident #1 -> ignored cleanly.
        late = client.post(
            "/api/v1/monitoring/nagios/alerts",
            json=_problem_payload(
                notification_type="RECOVERY",
                state="OK",
                event_timestamp="2026-11-11T12:01:00Z",
                event_id="e2e-rec-late",
            ),
            headers={"X-Nagios-Token": "e2e-nagios-secret"},
        )
        assert late.status_code == 200
        assert late.json()["outcome"] == "ignored_no_open_incident"

        # Step 5: Ansible failure leaves incident OPEN and execution FAILED.
        fail_runner = _FakeAnsibleRunner(exit_code=2)
        fail_worker = ExecutorWorker(
            settings,
            execution_manager=ExecutionManager(
                settings,
                executor=RemediationExecutor(settings, runner=fail_runner),
                verifier=verifier,
            ),
        )
        crit2 = client.post(
            "/api/v1/monitoring/nagios/alerts",
            json=_problem_payload(
                event_id="e2e-crit-2",
                nagios_problem_id="102",
                nagios_notification_id="502",
                event_timestamp="2026-11-11T12:10:00Z",
            ),
            headers={"X-Nagios-Token": "e2e-nagios-secret"},
        )
        assert crit2.status_code == 200
        assert await fail_worker.run_once() == 1
        await fail_worker.drain(timeout=5.0)
        assert client.get("/api/v1/incidents/2").json()["status"] == "open"
        assert client.get("/api/v1/remediations/2").json()["status"] == "failed"

        # Step 6: Verification failure after Ansible exits 0 keeps incident OPEN too.
        verify_fail_settings = settings.model_copy(update={"autoheal_remediation_cooldown_seconds": 0})
        verify_fail_worker = ExecutorWorker(
            verify_fail_settings,
            execution_manager=ExecutionManager(
                verify_fail_settings,
                executor=RemediationExecutor(verify_fail_settings, runner=_FakeAnsibleRunner(exit_code=0)),
                verifier=_make_verifier(healthy=False),
            ),
        )
        # Re-open path via host DOWN notification after resolving incident #2.
        client.post(
            "/api/v1/monitoring/nagios/alerts",
            json=_problem_payload(
                notification_type="RECOVERY",
                state="OK",
                event_timestamp="2026-11-11T12:12:00Z",
                event_id="e2e-rec-2",
            ),
            headers={"X-Nagios-Token": "e2e-nagios-secret"},
        )
        host_down = client.post(
            "/api/v1/monitoring/nagios/alerts",
            json={
                "notification_kind": "host",
                "notification_type": "PROBLEM",
                "host_name": "autoheal-web",
                "state": "DOWN",
                "state_type": "HARD",
                "attempt": 3,
                "max_attempts": 3,
                "output": "CRITICAL - Host TCP port 80 refused",
                "event_timestamp": "2026-11-11T12:20:00Z",
                "event_id": "e2e-host-down-3",
            },
            headers={"X-Nagios-Token": "e2e-nagios-secret"},
        )
        assert host_down.status_code == 200
        assert host_down.json()["incident_id"] == 3
        assert host_down.json()["remediation_queued"] is True
        assert await verify_fail_worker.run_once() == 1
        await verify_fail_worker.drain(timeout=5.0)
        assert client.get("/api/v1/incidents/3").json()["status"] == "open"
        exec3 = client.get("/api/v1/remediations/3").json()
        assert exec3["status"] == "failed"

        # Verify events and status endpoints plus bounded Prometheus telemetry.
        events_resp = client.get("/api/v1/monitoring/nagios/events")
        assert events_resp.status_code == 200
        assert events_resp.json()["total"] == 5
        status_resp = client.get("/api/v1/monitoring/nagios/status")
        assert status_resp.status_code == 200
        assert status_resp.json()["webhook_auth_configured"] is True
        status_json = status_resp.json()
        assert status_json["events_by_outcome"].get("remediation_queued", 0) >= 2
        assert status_json["open_incidents_by_source"].get("nagios", 0) == 1


def test_nagios_notify_script_fail_closed_and_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.delenv("AUTOHEAL_NAGIOS_WEBHOOK_SECRET", raising=False)
    monkeypatch.setenv("AUTOHEAL_NAGIOS_SECRET_FILE", str(tmp_path / "missing.secret"))

    # Fail-closed when secret is missing.
    rc = nagios_notify.main(
        [
            "--kind",
            "service",
            "--notification-type",
            "PROBLEM",
            "--host-name",
            "autoheal-web",
            "--service-name",
            "Web HTTP Health",
            "--state",
            "CRITICAL",
            "--api-url",
            "http://127.0.0.1:9/unused",
        ]
    )
    assert rc == 2

    # Start local HTTP server failing first attempt (503) then returning 200 on retry.
    seen: list[tuple[str | None, dict]] = []

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            seen.append((self.headers.get("X-Nagios-Token"), json.loads(raw.decode("utf-8"))))
            code = 503 if len(seen) == 1 else 200
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"accepted":true}')

        def log_message(self, *_args):
            return

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        secret_file = tmp_path / "webhook.secret"
        secret_file.write_text("retry-secret-token\n", encoding="utf-8")
        caplog.clear()
        with caplog.at_level("INFO"):
            ok = nagios_notify.main(
                [
                    "--kind",
                    "service",
                    "--notification-type",
                    "PROBLEM",
                    "--host-name",
                    "autoheal-web",
                    "--service-name",
                    "Web HTTP Health",
                    "--state",
                    "CRITICAL",
                    "--output",
                    "HTTP CRITICAL",
                    "--timestamp",
                    "1762862400",
                    "--problem-id",
                    "88",
                    "--notification-id",
                    "99",
                    "--secret-file",
                    str(secret_file),
                    "--api-url",
                    f"http://127.0.0.1:{port}/api/v1/monitoring/nagios/alerts",
                ]
            )
        assert ok == 0
        assert len(seen) == 2
        assert seen[0][0] == "retry-secret-token"
        assert seen[0][1]["event_id"] == seen[1][1]["event_id"]
        assert "retry-secret-token" not in caplog.text
    finally:
        server.shutdown()
        server.server_close()


def test_check_mem_plugin_thresholds(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    mem_ok = tmp_path / "mem_ok"
    mem_ok.write_text("MemTotal: 1000000 kB\nMemAvailable: 700000 kB\n", encoding="utf-8")
    assert check_mem.main(["--meminfo", str(mem_ok), "-w", "80", "-c", "90"]) == 0
    assert "MEMORY OK" in capsys.readouterr().out

    mem_warn = tmp_path / "mem_warn"
    mem_warn.write_text("MemTotal: 1000000 kB\nMemAvailable: 150000 kB\n", encoding="utf-8")
    assert check_mem.main(["--meminfo", str(mem_warn), "-w", "80", "-c", "90"]) == 1
    assert "MEMORY WARNING" in capsys.readouterr().out

    mem_crit = tmp_path / "mem_crit"
    mem_crit.write_text("MemTotal: 1000000 kB\nMemAvailable: 50000 kB\n", encoding="utf-8")
    assert check_mem.main(["--meminfo", str(mem_crit), "-w", "80", "-c", "90"]) == 2
    assert "MEMORY CRITICAL" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_nagios_status_prober_persists_health_and_redacts_url(tmp_path: Path) -> None:
    db_path = str(tmp_path / "autoheal.db")

    async def _handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("Authorization") is None:
            return httpx.Response(401, json={"error": "unauthorized"})
        return httpx.Response(
            200,
            json={
                "result": {"type_code": 0, "message": "Success"},
                "data": {"programstatus": {"version": "4.4.6", "enable_notifications": True}},
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(_handler))
    prober = NagiosStatusProber(
        db_path=db_path,
        status_url="http://nagiosadmin:superpass@nagios:8081/nagios4/cgi-bin/statusjson.cgi?query=programstatus",
        username="nagiosadmin",
        password="secret",
        client=client,
    )
    try:
        res = await prober.probe_once()
        assert res.up is True
        assert res.program_running is True
    finally:
        await client.aclose()

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM nagios_monitor_status WHERE target_name = 'nagios'").fetchone()
    conn.close()
    assert row is not None
    assert row["up"] == 1
    assert "superpass" not in row["target_url"]
