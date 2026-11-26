"""Safety, security, isolation, verification, and failure tests for the remediation engine."""

from __future__ import annotations

import asyncio
import os
import sqlite3
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from remediation.src.models import (
    PolicyReason,
    RemediationDecision,
    RemediationRequest,
    RemediationStatus,
)
from remediation.src.incident_manager import IncidentManager
from remediation.src.models import CheckOutcome, HealthCheckResult, IncidentStatus
from remediation.src.ansible_runner import (
    AnsibleRunner,
    check_execution_isolation,
    resolve_approved_workspace_file,
    sanitize_ansible_output,
)
from remediation.src.config import RemediationSettings
from remediation.src.execution_manager import ExecutionManager
from remediation.src.executor import RemediationExecutor
from remediation.src.metrics_store import RemediationMetricsRecorder
from remediation.src.models import (
    PolicyReason,
    RemediationRequest,
    RemediationStatus,
)
from remediation.src.repository import RemediationRepository
from remediation.src.verifier import RecoveryVerifier

REPO_ROOT = Path(__file__).resolve().parent.parent


def _probe(healthy: bool, error: str | None = None) -> HealthCheckResult:
    return HealthCheckResult(
        service_name="web",
        target_url="http://web/health",
        healthy=healthy,
        outcome=CheckOutcome.SUCCESS if healthy else CheckOutcome.CONNECTION_ERROR,
        status_code=200 if healthy else None,
        response_time_ms=8.0,
        error=error,
        checked_at=datetime.now(timezone.utc),
    )


def _open_incident(db_path: str, service_name: str = "web") -> int:
    manager = IncidentManager(db_path=db_path, failure_threshold=2, recovery_threshold=2)
    manager.process_check(
        HealthCheckResult(
            service_name=service_name,
            target_url=f"http://{service_name}/health",
            healthy=False,
            outcome=CheckOutcome.CONNECTION_ERROR,
            status_code=None,
            response_time_ms=5.0,
            error="Connection refused",
            checked_at=datetime.now(timezone.utc),
        )
    )
    ev = manager.process_check(
        HealthCheckResult(
            service_name=service_name,
            target_url=f"http://{service_name}/health",
            healthy=False,
            outcome=CheckOutcome.CONNECTION_ERROR,
            status_code=None,
            response_time_ms=5.0,
            error="Connection refused",
            checked_at=datetime.now(timezone.utc),
        )
    )
    assert ev.active_incident is not None
    return ev.active_incident.id


def _settings(db_path: str, **overrides: object) -> RemediationSettings:
    params: dict[str, object] = {
        "_env_file": None,
        "autoheal_db_path": db_path,
        "autoheal_remediation_workspace_root": str(REPO_ROOT),
        "autoheal_remediation_verify_interval": 0.01,
        "autoheal_remediation_verify_attempts": 3,
        "autoheal_remediation_verify_required_successes": 2,
        "autoheal_remediation_require_isolation": False,
    }
    params.update(overrides)
    return RemediationSettings(**params)


def test_isolation_check_fails_closed(tmp_path: Path) -> None:
    fake_sock = tmp_path / "docker.sock"
    fake_sock.touch()

    ok, msg = check_execution_isolation(
        docker_host="tcp://docker-socket-proxy:2375",
        docker_sock_path=fake_sock,
    )
    assert ok is False
    assert "docker.sock" in msg

    missing_sock = tmp_path / "nonexistent.sock"
    assert check_execution_isolation(docker_host="", docker_sock_path=missing_sock)[0] is False
    assert (
        check_execution_isolation(
            docker_host="unix:///var/run/docker.sock", docker_sock_path=missing_sock
        )[0]
        is False
    )
    assert (
        check_execution_isolation(
            docker_host="http://docker-socket-proxy:2375", docker_sock_path=missing_sock
        )[0]
        is False
    )
    for bad_proxy in (
        "tcp://unexpected-host:2375",
        "tcp://docker-socket-proxy:2376",
        "tcp://user:pass@docker-socket-proxy:2375",
        "tcp://docker-socket-proxy:2375/v1.52",
        "tcp://docker-socket-proxy:2375?size=1",
        "tcp://docker-socket-proxy:notaport",
    ):
        assert (
            check_execution_isolation(docker_host=bad_proxy, docker_sock_path=missing_sock)[0]
            is False
        )

    isolated, reason = check_execution_isolation(
        docker_host="tcp://docker-socket-proxy:2375", docker_sock_path=missing_sock
    )
    assert isolated is True
    assert "docker-socket-proxy:2375" in reason


def test_ansible_runner_rejects_traversal_injection_and_symlink_escape(tmp_path: Path) -> None:
    outside = tmp_path / "outside.yml"
    outside.write_text("- hosts: all\n", encoding="utf-8")
    ws = tmp_path / "workspace"
    (ws / "remediation").mkdir(parents=True)
    symlink_playbook = ws / "remediation" / "escape.yml"
    symlink_playbook.symlink_to(outside)

    with pytest.raises(ValueError):
        resolve_approved_workspace_file(
            ws,
            "remediation/escape.yml",
            allowlist=("remediation/escape.yml",),
            label="Playbook",
        )

    for bad_path in (
        "",
        "/etc/passwd",
        "../outside.yml",
        "remediation/recover.yml;id",
        "remediation/unapproved.yml",
    ):
        with pytest.raises(ValueError):
            resolve_approved_workspace_file(
                REPO_ROOT,
                bad_path,
                allowlist=("remediation/recover.yml",),
                label="Playbook",
            )


def test_ansible_runner_builds_safe_argv_and_curates_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "super-secret-aws-key")
    monkeypatch.setenv("DOCKER_HOST", "tcp://docker-socket-proxy:2375")
    called: list[dict[str, object]] = []

    def fake_run(argv, **kwargs):
        called.append({"argv": argv, "kwargs": kwargs})
        return subprocess.CompletedProcess(
            args=argv,
            returncode=0,
            stdout="Authorization: Bearer leak-me\nok=1\n",
            stderr="",
        )

    settings = _settings(str(tmp_path / "db.sqlite"), autoheal_remediation_require_isolation=True)
    runner = AnsibleRunner(
        settings,
        subprocess_runner=fake_run,
        isolation_checker=lambda: (True, "Isolated"),
    )

    with pytest.raises(ValueError):
        runner.validate_and_build_command(service_name="db", action="restart")
    with pytest.raises(ValueError):
        runner.validate_and_build_command(service_name="web;rm", action="restart")
    with pytest.raises(ValueError):
        runner.validate_and_build_command(service_name="web", action="exec")
    with pytest.raises(ValueError):
        runner.validate_and_build_command(
            service_name="web",
            action="restart",
            extra_vars={"ansible_ssh_pass": "root"},
        )
    with pytest.raises(ValueError):
        runner.validate_and_build_command(
            service_name="web",
            action="restart",
            executable="/bin/sh",
        )

    result = runner.run(service_name="web", action="restart", check_mode=True)
    assert result.succeeded is True
    assert result.exit_code == 0
    assert len(called) == 1
    assert called[0]["kwargs"]["shell"] is False
    assert "--check" in called[0]["argv"]
    child_env = called[0]["kwargs"]["env"]
    assert "AWS_SECRET_ACCESS_KEY" not in child_env
    assert child_env["DOCKER_HOST"] == "tcp://docker-socket-proxy:2375"
    assert "leak-me" not in result.combined_output
    assert "***" in result.combined_output


def test_ansible_runner_failure_modes_and_secret_scrubbing(tmp_path: Path) -> None:
    db_path = str(tmp_path / "fail.db")
    settings = _settings(db_path, autoheal_remediation_require_isolation=True)

    # 1. Fail-closed isolation refusal never invokes subprocess.
    invoked = False

    def should_not_run(*_args, **_kwargs):
        nonlocal invoked
        invoked = True
        raise AssertionError("Subprocess must not run when isolation check fails")

    blocked_runner = AnsibleRunner(
        settings,
        subprocess_runner=should_not_run,
        isolation_checker=lambda: (False, "direct /var/run/docker.sock forbidden"),
    )
    iso_res = blocked_runner.run(service_name="web", action="restart")
    assert invoked is False
    assert iso_res.succeeded is False
    assert "docker.sock" in (iso_res.error or "")

    # 2. Missing executable (FileNotFoundError)
    missing_runner = AnsibleRunner(
        _settings(db_path),
        subprocess_runner=lambda *a, **kw: (_ for _ in ()).throw(FileNotFoundError("no binary")),
    )
    missing_res = missing_runner.run(service_name="web", action="restart")
    assert missing_res.succeeded is False
    assert missing_res.exit_code is None
    assert "not found" in (missing_res.error or "").lower()

    # 3. Subprocess timeout (TimeoutExpired)
    timeout_exc = subprocess.TimeoutExpired(
        cmd=["ansible-playbook"],
        timeout=5,
        output=b"token=abc123timeout",
        stderr=b"timed out",
    )
    timeout_runner = AnsibleRunner(
        _settings(db_path),
        subprocess_runner=lambda *a, **kw: (_ for _ in ()).throw(timeout_exc),
    )
    timeout_res = timeout_runner.run(service_name="web", action="restart")
    assert timeout_res.timed_out is True
    assert timeout_res.succeeded is False
    assert "abc123timeout" not in timeout_res.combined_output

    # 4. OSError failure + PEM private key redaction
    os_runner = AnsibleRunner(
        _settings(db_path),
        subprocess_runner=lambda *a, **kw: (_ for _ in ()).throw(OSError("exec format error")),
    )
    assert os_runner.run(service_name="web", action="restart").succeeded is False

    scrubbed = sanitize_ansible_output(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nTOPSECRET\n-----END OPENSSH PRIVATE KEY-----",
        max_length=200,
    )
    assert "TOPSECRET" not in scrubbed
    assert "[REDACTED_PRIVATE_KEY]" in scrubbed


@pytest.mark.asyncio
async def test_recovery_verifier_consecutive_successes_and_failure_budget(tmp_path: Path) -> None:
    settings = _settings(
        str(tmp_path / "verify.db"),
        autoheal_remediation_verify_attempts=4,
        autoheal_remediation_verify_required_successes=2,
        autoheal_remediation_verify_interval=0.001,
    )

    outcomes = [_probe(False, "down"), _probe(True), _probe(True)]
    idx = 0

    async def probe_recovering():
        nonlocal idx
        item = outcomes[idx]
        idx += 1
        return item

    async def no_sleep(_interval: float) -> None:
        return None

    verifier_ok = RecoveryVerifier(settings, probe_fn=probe_recovering, sleep_fn=no_sleep)
    res_ok = await verifier_ok.verify(service_name="web")
    assert res_ok.verified is True
    assert res_ok.attempts_made == 3
    assert res_ok.consecutive_successes == 2

    # Unstable service: single healthy probe resets on subsequent failure -> never verified.
    flaky = [_probe(True), _probe(False, "503"), _probe(True), _probe(False, "timeout")]
    f_idx = 0

    async def probe_flaky():
        nonlocal f_idx
        item = flaky[f_idx]
        f_idx += 1
        return item

    verifier_fail = RecoveryVerifier(settings, probe_fn=probe_flaky, sleep_fn=no_sleep)
    res_fail = await verifier_fail.verify(service_name="web")
    assert res_fail.verified is False
    assert res_fail.attempts_made == 4


@pytest.mark.asyncio
async def test_execution_manager_dry_run_skips_ansible_and_keeps_incident_open(
    tmp_path: Path,
) -> None:
    db_path = str(tmp_path / "dry.db")
    incident_id = _open_incident(db_path)

    invoked = False

    def fail_if_called(*_a, **_kw):
        nonlocal invoked
        invoked = True
        raise AssertionError("Ansible must NOT execute in dry-run mode")

    settings = _settings(
        db_path,
        autoheal_remediation_enabled=True,
        autoheal_remediation_dry_run=True,
    )
    runner = AnsibleRunner(settings, subprocess_runner=fail_if_called)
    executor = RemediationExecutor(settings, runner=runner)
    manager = ExecutionManager(settings, executor=executor)

    outcome = await manager.execute_incident(
        RemediationRequest(incident_id=incident_id, service_name="web", action="restart")
    )
    assert invoked is False
    assert outcome.executed is True
    assert outcome.dry_run is True
    assert outcome.verified is False
    assert outcome.incident_resolved is False
    assert outcome.execution is not None
    assert outcome.execution.status == RemediationStatus.DRY_RUN

    # Dry-run never populates failures, timeouts, or attempts_exhausted counters.
    with sqlite3.connect(db_path) as conn:
        incident_status = conn.execute(
            "SELECT status FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()[0]
        counters = dict(
            conn.execute(
                "SELECT metric_name, value FROM remediation_counters"
            ).fetchall()
        )
    assert incident_status == IncidentStatus.OPEN.value
    assert counters["autoheal_remediation_attempts_total"] == 1
    assert "autoheal_remediation_failures_total" not in counters
    assert "autoheal_remediation_attempts_exhausted_total" not in counters


@pytest.mark.asyncio
async def test_ansible_rc0_does_not_resolve_incident_when_verification_fails(
    tmp_path: Path,
) -> None:
    db_path = str(tmp_path / "verify_gate.db")
    incident_id = _open_incident(db_path)

    settings = _settings(
        db_path,
        autoheal_remediation_enabled=True,
        autoheal_remediation_dry_run=False,
        autoheal_remediation_verify_attempts=2,
        autoheal_remediation_verify_required_successes=2,
    )

    def ok_ansible(argv, **_kwargs):
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="restarted ok", stderr="")

    async def always_down():
        return _probe(False, "Still connection refused")

    async def no_sleep(_: float) -> None:
        return None

    executor = RemediationExecutor(
        settings,
        runner=AnsibleRunner(settings, subprocess_runner=ok_ansible),
    )
    verifier = RecoveryVerifier(settings, probe_fn=always_down, sleep_fn=no_sleep)
    manager = ExecutionManager(settings, executor=executor, verifier=verifier)

    outcome = await manager.execute_incident(
        RemediationRequest(incident_id=incident_id, service_name="web", action="restart")
    )
    assert outcome.executed is True
    assert outcome.ansible_result is not None and outcome.ansible_result.exit_code == 0
    assert outcome.verified is False
    assert outcome.incident_resolved is False
    assert outcome.execution is not None
    assert outcome.execution.status == RemediationStatus.FAILED
    assert "verification failed" in (outcome.execution.failure_reason or "").lower()

    with sqlite3.connect(db_path) as conn:
        status = conn.execute(
            "SELECT status FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()[0]
    assert status == IncidentStatus.OPEN.value


@pytest.mark.asyncio
async def test_live_recovery_verified_resolves_incident_and_exhaustion_cooldown(
    tmp_path: Path,
) -> None:
    db_path = str(tmp_path / "live_ok.db")
    incident_id = _open_incident(db_path)

    settings = _settings(
        db_path,
        autoheal_remediation_enabled=True,
        autoheal_remediation_dry_run=False,
        autoheal_remediation_verify_attempts=3,
        autoheal_remediation_verify_required_successes=2,
    )

    async def no_sleep(_: float) -> None:
        return None

    executor = RemediationExecutor(
        settings,
        runner=AnsibleRunner(
            settings,
            subprocess_runner=lambda argv, **kw: subprocess.CompletedProcess(
                args=argv, returncode=0, stdout="Container restarted", stderr=""
            ),
        ),
    )
    verifier = RecoveryVerifier(
        settings,
        probe_fn=lambda: asyncio.sleep(0, result=_probe(True)),
        sleep_fn=no_sleep,
    )
    manager = ExecutionManager(settings, executor=executor, verifier=verifier)

    outcome = await manager.execute_incident(
        RemediationRequest(incident_id=incident_id, service_name="web", action="restart")
    )
    assert outcome.executed is True
    assert outcome.verified is True
    assert outcome.incident_resolved is True
    assert outcome.execution is not None
    assert outcome.execution.status == RemediationStatus.SUCCEEDED

    # Cannot remediate already-resolved incident again.
    second = await manager.execute_incident(
        RemediationRequest(incident_id=incident_id, service_name="web", action="restart")
    )
    assert second.executed is False
    assert second.decision.reason == PolicyReason.INCIDENT_ALREADY_RESOLVED

    # Second incident: test cooldown, max_attempts=2, and attempts_exhausted metric.
    incident_2 = _open_incident(db_path)
    limited_settings = _settings(
        db_path,
        autoheal_remediation_enabled=True,
        autoheal_remediation_dry_run=False,
        autoheal_remediation_max_attempts=2,
        autoheal_remediation_cooldown_seconds=120,
    )
    fail_manager = ExecutionManager(
        limited_settings,
        executor=RemediationExecutor(
            limited_settings,
            runner=AnsibleRunner(
                limited_settings,
                subprocess_runner=lambda argv, **kw: subprocess.CompletedProcess(
                    args=argv, returncode=2, stdout="", stderr="docker error"
                ),
            ),
        ),
    )
    t0 = datetime(2026, 7, 1, 10, 0, 0, tzinfo=timezone.utc)
    r1 = await fail_manager.execute_incident(
        RemediationRequest(incident_id=incident_2, service_name="web", action="restart"),
        now=t0,
    )
    assert r1.execution is not None and r1.execution.status == RemediationStatus.FAILED

    # During cooldown window -> blocked.
    r_cd = await fail_manager.execute_incident(
        RemediationRequest(incident_id=incident_2, service_name="web", action="restart"),
        now=t0 + timedelta(seconds=30),
    )
    assert r_cd.executed is False
    assert r_cd.decision.reason == PolicyReason.COOLDOWN_ACTIVE

    # After cooldown -> attempt 2 executes & exhausts budget -> exhausted metric=1.
    r2 = await fail_manager.execute_incident(
        RemediationRequest(incident_id=incident_2, service_name="web", action="restart"),
        now=t0 + timedelta(seconds=150),
    )
    assert r2.execution is not None and r2.execution.attempt_number == 2

    r3 = await fail_manager.execute_incident(
        RemediationRequest(incident_id=incident_2, service_name="web", action="restart"),
        now=t0 + timedelta(seconds=400),
    )
    assert r3.executed is False
    assert r3.decision.reason == PolicyReason.MAX_ATTEMPTS_REACHED

    with sqlite3.connect(db_path) as conn:
        exhausted = conn.execute(
            "SELECT value FROM remediation_counters WHERE metric_name = 'autoheal_remediation_attempts_exhausted_total'"
        ).fetchone()[0]
    assert exhausted == 1


@pytest.mark.asyncio
async def test_stale_recovery_and_concurrent_reservation_protection(tmp_path: Path) -> None:
    db_path = str(tmp_path / "stale.db")
    incident_id = _open_incident(db_path)
    settings = _settings(
        db_path,
        autoheal_remediation_enabled=True,
        autoheal_remediation_dry_run=False,
        autoheal_remediation_stale_timeout_seconds=60.0,
        autoheal_remediation_cooldown_seconds=0,
    )
    manager = ExecutionManager(settings)

    t0 = datetime(2026, 7, 1, 12, 0, 0, tzinfo=timezone.utc)
    res = manager.repository.reserve_execution(
        RemediationRequest(incident_id=incident_id, service_name="web", action="restart"),
        settings,
        initial_status=RemediationStatus.RUNNING,
        now=t0,
    )
    assert res.reserved is True

    # While active & non-stale, concurrent reservation must be rejected.
    dup = manager.repository.reserve_execution(
        RemediationRequest(incident_id=incident_id, service_name="web", action="restart"),
        settings,
        initial_status=RemediationStatus.RUNNING,
        now=t0 + timedelta(seconds=10),
    )
    assert dup.reserved is False
    assert dup.decision.reason == PolicyReason.REMEDIATION_ALREADY_RUNNING

    # After stale timeout, recover_stale marks TIMED_OUT and records metrics once.
    recovered = manager.recover_stale(now=t0 + timedelta(seconds=120))
    assert len(recovered) == 1
    assert recovered[0].status == RemediationStatus.TIMED_OUT
    assert manager.recover_stale(now=t0 + timedelta(seconds=130)) == []

    with sqlite3.connect(db_path) as conn:
        timeouts = conn.execute(
            "SELECT value FROM remediation_counters WHERE metric_name = 'autoheal_remediation_timeouts_total'"
        ).fetchone()[0]
    assert timeouts == 1


def test_metrics_recorder_rolls_back_on_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = str(tmp_path / "rollback.db")
    incident_id = _open_incident(db_path)
    settings = _settings(db_path, autoheal_remediation_enabled=True, autoheal_remediation_dry_run=True)
    manager = ExecutionManager(settings)
    res = manager.repository.reserve_execution(
        RemediationRequest(incident_id=incident_id, service_name="web", action="restart"),
        settings,
    )
    assert res.execution is not None
    recorder = RemediationMetricsRecorder(db_path)

    monkeypatch.setattr(
        recorder,
        "_increment_counter",
        lambda *_a, **_kw: (_ for _ in ()).throw(sqlite3.OperationalError("simulated db error")),
    )
    with pytest.raises(sqlite3.OperationalError):
        recorder.record_attempt(res.execution)

    with sqlite3.connect(db_path) as conn:
        events = conn.execute("SELECT COUNT(*) FROM remediation_metric_events").fetchone()[0]
        counters = conn.execute("SELECT COUNT(*) FROM remediation_counters").fetchone()[0]
    assert events == 0
    assert counters == 0


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


@pytest.mark.asyncio
async def test_real_popen_timeout_and_cancellation_clean_up_process_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    pid_file = tmp_path / "spawned.pids"
    fake_ansible = bin_dir / "ansible-playbook"
    fake_ansible.write_text(
        f"""#!/bin/sh
sleep 30 &
child_pid=$!
printf '%s\\n' "$child_pid" > "{pid_file}"
wait "$child_pid"
""",
        encoding="utf-8",
    )
    fake_ansible.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")

    db_path = str(tmp_path / "popen_pg.db")
    settings = _settings(
        db_path,
        autoheal_remediation_enabled=True,
        autoheal_remediation_dry_run=False,
        autoheal_remediation_timeout_seconds=2.5,
    )
    runner = AnsibleRunner(settings)

    res = runner.run(service_name="web", action="restart")
    assert res.timed_out is True, res.error
    assert res.succeeded is False
    assert pid_file.exists(), f"PID file not created; output={res.combined_output!r}"
    child_pid = int(pid_file.read_text(encoding="utf-8").strip())
    for _ in range(60):
        if not _pid_alive(child_pid):
            break
        await asyncio.sleep(0.05)
    assert not _pid_alive(child_pid)

    # Verify asyncio.CancelledError during executor wait also kills the real process group.
    pid_file.unlink()
    incident_id = _open_incident(db_path)
    long_settings = _settings(
        db_path,
        autoheal_remediation_enabled=True,
        autoheal_remediation_dry_run=False,
        autoheal_remediation_timeout_seconds=15.0,
    )
    executor = RemediationExecutor(long_settings, runner=AnsibleRunner(long_settings))
    reservation = executor.reserve(
        RemediationRequest(incident_id=incident_id, service_name="web", action="restart"),
        initial_status=RemediationStatus.RUNNING,
    )
    assert reservation.reserved and reservation.execution is not None

    task = asyncio.create_task(executor.execute_reserved_ansible(reservation.execution))
    for _ in range(60):
        if pid_file.exists() and pid_file.read_text(encoding="utf-8").strip():
            break
        await asyncio.sleep(0.05)
    assert pid_file.exists()
    cancel_child_pid = int(pid_file.read_text(encoding="utf-8").strip())

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    for _ in range(40):
        if not _pid_alive(cancel_child_pid):
            break
        await asyncio.sleep(0.05)
    assert not _pid_alive(cancel_child_pid)


@pytest.mark.asyncio
async def test_verified_completion_atomic_rollback_and_aborted_skips_failure_metric(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = str(tmp_path / "atomic_rollback.db")
    incident_id = _open_incident(db_path)
    settings = _settings(
        db_path,
        autoheal_remediation_enabled=True,
        autoheal_remediation_dry_run=False,
        autoheal_remediation_verify_attempts=2,
        autoheal_remediation_verify_required_successes=1,
    )

    async def no_sleep(_: float) -> None:
        return None

    repo = RemediationRepository(db_path)
    manager = ExecutionManager(
        settings,
        repository=repo,
        executor=RemediationExecutor(
            settings,
            repository=repo,
            runner=AnsibleRunner(
                settings,
                subprocess_runner=lambda argv, **_kw: subprocess.CompletedProcess(
                    args=argv, returncode=0, stdout="ok", stderr=""
                ),
            ),
        ),
        verifier=RecoveryVerifier(
            settings,
            probe_fn=lambda: asyncio.sleep(0, result=_probe(True)),
            sleep_fn=no_sleep,
        ),
    )

    # Simulate DB error in update_status_in_tx AFTER resolve_open_incident_in_tx inside same TX.
    def _fail_update(*_a, **_kw):
        raise sqlite3.OperationalError("simulated mid-commit failure")

    monkeypatch.setattr(repo, "update_status_in_tx", _fail_update)
    with pytest.raises(sqlite3.OperationalError, match="simulated mid-commit failure"):
        await manager.execute_incident(
            RemediationRequest(incident_id=incident_id, service_name="web", action="restart")
        )

    # Incident must NOT be left RESOLVED when execution update rolled back.
    with sqlite3.connect(db_path) as conn:
        inc_status = conn.execute(
            "SELECT status FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()[0]
        exec_status = conn.execute(
            "SELECT status FROM remediation_executions WHERE incident_id = ?", (incident_id,)
        ).fetchone()[0]
        mon_resolved = conn.execute(
            "SELECT COUNT(*) FROM monitoring_counters WHERE metric_name = 'autoheal_incidents_total' AND labels_json LIKE '%resolved%'"
        ).fetchone()[0]
    assert inc_status == IncidentStatus.OPEN.value
    assert exec_status == RemediationStatus.RUNNING.value
    assert mon_resolved == 0

    # Queued job aborted because incident already resolved must NOT increment failures_total.
    aborted_db = str(tmp_path / "aborted.db")
    inc2 = _open_incident(aborted_db)
    aborted_settings = _settings(
        aborted_db,
        autoheal_remediation_enabled=True,
        autoheal_remediation_dry_run=False,
    )
    aborted_repo = RemediationRepository(aborted_db)
    pending = aborted_repo.create_execution(
        incident_id=inc2,
        service_name="web",
        action="restart",
        status=RemediationStatus.PENDING,
        dry_run=False,
    )
    IncidentManager(db_path=aborted_db).resolve_open_incident(inc2, datetime.now(timezone.utc))
    aborted_mgr = ExecutionManager(aborted_settings, repository=aborted_repo)
    outcome = await aborted_mgr.process_pending_execution(pending.id)
    assert outcome is not None and outcome.executed is False
    assert outcome.decision.reason == PolicyReason.INCIDENT_ALREADY_RESOLVED
    with sqlite3.connect(aborted_db) as conn:
        fail_rows = conn.execute(
            "SELECT COUNT(*) FROM remediation_counters WHERE metric_name = 'autoheal_remediation_failures_total'"
        ).fetchone()[0]
    assert fail_rows == 0
@pytest.mark.asyncio
async def test_pending_execution_respects_current_global_dry_run_setting(
    tmp_path: Path,
) -> None:
    db_path = str(tmp_path / "queued_dry_run.db")
    incident_id = _open_incident(db_path)

    repo = RemediationRepository(db_path)

    # Simulate a job created before global dry-run was enabled.
    pending = repo.create_execution(
        incident_id=incident_id,
        service_name="web",
        action="restart",
        status=RemediationStatus.PENDING,
        dry_run=False,
    )

    invoked = False

    def fail_if_called(*_args, **_kwargs):
        nonlocal invoked
        invoked = True
        raise AssertionError(
            "Ansible must not execute when current global dry-run is enabled"
        )

    current_settings = _settings(
        db_path,
        autoheal_remediation_enabled=True,
        autoheal_remediation_dry_run=True,
    )

    manager = ExecutionManager(
        current_settings,
        repository=repo,
        executor=RemediationExecutor(
            current_settings,
            repository=repo,
            runner=AnsibleRunner(
                current_settings,
                subprocess_runner=fail_if_called,
            ),
        ),
    )

    outcome = await manager.process_pending_execution(pending.id)

    assert invoked is False
    assert outcome is not None
    assert outcome.executed is True
    assert outcome.dry_run is True
    assert outcome.verified is False
    assert outcome.incident_resolved is False
    assert outcome.execution is not None
    assert outcome.execution.status == RemediationStatus.DRY_RUN


@pytest.mark.asyncio
async def test_execution_time_policy_denial_prevents_ansible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path = str(tmp_path / "execution_policy_denial.db")
    incident_id = _open_incident(db_path)
    repo = RemediationRepository(db_path)

    pending = repo.create_execution(
        incident_id=incident_id,
        service_name="web",
        action="restart",
        status=RemediationStatus.PENDING,
        dry_run=False,
    )

    settings = _settings(
        db_path,
        autoheal_remediation_enabled=True,
        autoheal_remediation_dry_run=False,
    )

    manager = ExecutionManager(settings, repository=repo)

    policy_calls = 0
    ansible_invoked = False

    def deny_execution_time_policy(**kwargs):
        nonlocal policy_calls
        policy_calls += 1

        return RemediationDecision(
            allowed=False,
            reason=PolicyReason.REMEDIATION_DISABLED,
            dry_run=False,
            service_name="web",
            action="restart",
            incident_id=incident_id,
            details="Remediation disabled by execution-time policy recheck.",
        )

    async def fail_if_ansible_called(execution):
        nonlocal ansible_invoked
        ansible_invoked = True
        raise AssertionError("Ansible must not run after policy denial")

    monkeypatch.setattr(
        "remediation.src.execution_manager.evaluate_policy_gates",
        deny_execution_time_policy,
    )
    monkeypatch.setattr(
        manager._executor,
        "execute_reserved_ansible",
        fail_if_ansible_called,
    )

    outcome = await manager.process_pending_execution(pending.id)

    assert policy_calls == 1
    assert ansible_invoked is False

    assert outcome is not None
    assert outcome.executed is False
    assert outcome.verified is False
    assert outcome.decision.allowed is False
    assert outcome.decision.reason == PolicyReason.REMEDIATION_DISABLED
    assert outcome.execution is not None
    assert outcome.execution.status == RemediationStatus.FAILED

    # The model does not expose failure_outcome as an attribute.
    # Verify the persisted terminal status and that an abort adds no failure metric.
    with sqlite3.connect(db_path) as conn:
        persisted_status = conn.execute(
            "SELECT status FROM remediation_executions WHERE id = ?",
            (pending.id,),
        ).fetchone()
        failure_rows = conn.execute(
            """
            SELECT COUNT(*)
            FROM remediation_counters
            WHERE metric_name = 'autoheal_remediation_failures_total'
            """
        ).fetchone()[0]

    assert persisted_status is not None
    assert persisted_status[0] == RemediationStatus.FAILED.value
    assert failure_rows == 0
