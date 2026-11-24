"""Integration tests for MonitoringEngine, RemediationCoordinator, and ExecutorWorker."""

from __future__ import annotations

import asyncio
import sqlite3
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from remediation.src.health_checker import AsyncHealthChecker
from remediation.src.incident_manager import IncidentManager
from remediation.src.models import CheckOutcome, HealthCheckResult, IncidentStatus
from remediation.src.monitor import MonitoringEngine
from remediation.src.monitor_config import MonitorSettings
from remediation.src.ansible_runner import AnsibleRunner
from remediation.src.config import RemediationSettings
from remediation.src.coordinator import RemediationCoordinator
from remediation.src.execution_manager import ExecutionManager
from remediation.src.executor import RemediationExecutor
from remediation.src.models import RemediationStatus
from remediation.src.repository import RemediationRepository
from remediation.src.verifier import RecoveryVerifier
from remediation.src.worker import ExecutorWorker

REPO_ROOT = Path(__file__).resolve().parent.parent


def _monitor_settings(db_path: str, hb_path: str) -> MonitorSettings:
    return MonitorSettings(
        _env_file=None,
        monitor_enabled=True,
        monitor_target_url="http://web/health",
        monitor_target_service="web",
        monitor_interval=0.05,
        monitor_timeout=1.0,
        monitor_failure_threshold=2,
        monitor_recovery_threshold=2,
        autoheal_db_path=db_path,
        heartbeat_path=hb_path,
    )


def _rem_settings(db_path: str, hb_path: str, **overrides: object) -> RemediationSettings:
    params: dict[str, object] = {
        "_env_file": None,
        "autoheal_db_path": db_path,
        "autoheal_remediation_workspace_root": str(REPO_ROOT),
        "autoheal_remediation_verify_interval": 0.005,
        "autoheal_remediation_verify_attempts": 3,
        "autoheal_remediation_verify_required_successes": 2,
        "autoheal_remediation_executor_heartbeat_path": hb_path,
        "autoheal_remediation_require_isolation": False,
    }
    params.update(overrides)
    return RemediationSettings(**params)


@pytest.mark.asyncio
async def test_monitoring_coordinator_nonblocking_in_process_and_no_duplicate_tasks(
    tmp_path: Path,
) -> None:
    db_path = str(tmp_path / "inproc.db")
    monitor_hb = str(tmp_path / "monitor.heartbeat")
    exec_hb = str(tmp_path / "exec.heartbeat")

    service_healthy = False

    def handler(_request: httpx.Request) -> httpx.Response:
        if service_healthy:
            return httpx.Response(200, json={"status": "healthy", "service": "web"})
        return httpx.Response(503, text="down")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    checker = AsyncHealthChecker("web", "http://web/health", timeout=1.0, client=client)

    rem_settings = _rem_settings(
        db_path,
        exec_hb,
        autoheal_remediation_enabled=True,
        autoheal_remediation_dry_run=False,
        autoheal_remediation_dispatch_mode="in_process",
    )

    entered_ansible = threading.Event()
    release_ansible = threading.Event()

    def gated_ansible(argv, **_kwargs):
        nonlocal service_healthy
        entered_ansible.set()
        release_ansible.wait(timeout=5.0)
        service_healthy = True
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="restarted", stderr="")

    async def no_sleep(_: float) -> None:
        return None

    async def verify_probe() -> HealthCheckResult:
        return await checker.check()

    exec_manager = ExecutionManager(
        rem_settings,
        executor=RemediationExecutor(
            rem_settings,
            runner=AnsibleRunner(rem_settings, subprocess_runner=gated_ansible),
        ),
        verifier=RecoveryVerifier(rem_settings, probe_fn=verify_probe, sleep_fn=no_sleep),
    )
    coordinator = RemediationCoordinator(rem_settings, execution_manager=exec_manager)
    engine = MonitoringEngine(
        settings=_monitor_settings(db_path, monitor_hb),
        health_checker=checker,
        remediation_coordinator=coordinator,
    )

    # Probe 1 below failure threshold -> no incident and no remediation.
    ev1 = await engine.run_once()
    assert ev1.active_incident is None
    assert coordinator.active_incident_ids == set()

    # Probe 2 crosses failure threshold -> incident opened and non-blocking task launched.
    ev2 = await engine.run_once()
    assert ev2.active_incident is not None
    assert ev2.active_incident.status == IncidentStatus.OPEN
    assert coordinator.active_incident_ids == {ev2.active_incident.id}

    # Wait briefly for worker thread to enter mocked Ansible while task remains active.
    for _ in range(50):
        if entered_ansible.is_set():
            break
        await asyncio.sleep(0.01)
    assert entered_ansible.is_set()

    # Probe 3 while active task is running must run without blocking and NOT spawn duplicate task.
    ev3 = await engine.run_once()
    assert coordinator.active_incident_ids == {ev2.active_incident.id}
    assert ev3.active_incident is not None

    release_ansible.set()
    await coordinator.drain(timeout=5.0)
    assert coordinator.active_incident_ids == set()

    repo = RemediationRepository(db_path)
    items = repo.list_executions(incident_id=ev2.active_incident.id)
    assert len(items) == 1
    assert items[0].status == RemediationStatus.SUCCEEDED

    with sqlite3.connect(db_path) as conn:
        status = conn.execute(
            "SELECT status FROM incidents WHERE id = ?", (ev2.active_incident.id,)
        ).fetchone()[0]
    assert status == IncidentStatus.RESOLVED.value
    await engine.shutdown()


@pytest.mark.asyncio
async def test_monitoring_queue_and_executor_worker_end_to_end_cycle(tmp_path: Path) -> None:
    db_path = str(tmp_path / "queue_e2e.db")
    monitor_hb = str(tmp_path / "monitor.heartbeat")
    exec_hb = str(tmp_path / "executor.heartbeat")

    web_up = False

    def handler(_request: httpx.Request) -> httpx.Response:
        if web_up:
            return httpx.Response(200, json={"status": "healthy", "service": "web"})
        return httpx.Response(503, text="service unavailable")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    checker = AsyncHealthChecker("web", "http://web/health", timeout=1.0, client=client)

    rem_settings = _rem_settings(
        db_path,
        exec_hb,
        autoheal_remediation_enabled=True,
        autoheal_remediation_dry_run=False,
        autoheal_remediation_dispatch_mode="queue",
    )

    coordinator = RemediationCoordinator(rem_settings)
    engine = MonitoringEngine(
        settings=_monitor_settings(db_path, monitor_hb),
        health_checker=checker,
        remediation_coordinator=coordinator,
    )

    await engine.run_once()
    ev = await engine.run_once()
    assert ev.active_incident is not None
    # Another probe must not double-queue while pending execution exists.
    await engine.run_once()

    repo = RemediationRepository(db_path)
    queued = repo.list_pending_executions()
    assert len(queued) == 1

    def fake_ansible(argv, **_kwargs):
        nonlocal web_up
        web_up = True
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="restarted web", stderr="")

    async def no_sleep(_: float) -> None:
        return None

    worker_manager = ExecutionManager(
        rem_settings,
        executor=RemediationExecutor(
            rem_settings,
            runner=AnsibleRunner(rem_settings, subprocess_runner=fake_ansible),
        ),
        verifier=RecoveryVerifier(rem_settings, probe_fn=checker.check, sleep_fn=no_sleep),
    )
    worker = ExecutorWorker(rem_settings, execution_manager=worker_manager)

    scheduled = await worker.run_once()
    assert scheduled == 1
    assert Path(exec_hb).exists()
    await worker.drain(timeout=5.0)

    updated = repo.get_execution(queued[0].id)
    assert updated is not None
    assert updated.status == RemediationStatus.SUCCEEDED

    with sqlite3.connect(db_path) as conn:
        inc_status = conn.execute(
            "SELECT status FROM incidents WHERE id = ?", (ev.active_incident.id,)
        ).fetchone()[0]
    assert inc_status == IncidentStatus.RESOLVED.value

    await worker.shutdown()
    await engine.shutdown()


@pytest.mark.asyncio
async def test_executor_worker_marks_interrupted_on_cancellation(tmp_path: Path) -> None:
    db_path = str(tmp_path / "interrupt.db")
    exec_hb = str(tmp_path / "executor.heartbeat")
    rem_settings = _rem_settings(
        db_path,
        exec_hb,
        autoheal_remediation_enabled=True,
        autoheal_remediation_dry_run=False,
        autoheal_remediation_dispatch_mode="queue",
    )

    manager = IncidentManager(db_path=db_path, failure_threshold=1, recovery_threshold=1)
    ev = manager.process_check(
        HealthCheckResult(
            service_name="web",
            target_url="http://web/health",
            healthy=False,
            outcome=CheckOutcome.CONNECTION_ERROR,
            status_code=None,
            response_time_ms=5.0,
            error="down",
            checked_at=datetime.now(timezone.utc),
        )
    )
    assert ev.active_incident is not None

    started_event = asyncio.Event()

    class BlockingManager(ExecutionManager):
        async def process_pending_execution(self, execution_id: int, *, now=None):
            self.repository.claim_pending_execution(execution_id)
            started_event.set()
            await asyncio.sleep(30)

    coord = RemediationCoordinator(rem_settings)
    coord.handle_evaluation(ev)

    worker_mgr = BlockingManager(rem_settings)
    worker = ExecutorWorker(rem_settings, execution_manager=worker_mgr)
    scheduled = await worker.run_once()
    assert scheduled == 1
    await asyncio.wait_for(started_event.wait(), timeout=2.0)

    await worker.shutdown(timeout=0.05)

    repo = RemediationRepository(db_path)
    items = repo.list_executions(incident_id=ev.active_incident.id)
    assert len(items) == 1
    assert items[0].status == RemediationStatus.FAILED
    assert "interrupted" in (items[0].failure_reason or "").lower()


@pytest.mark.asyncio
async def test_executor_worker_excludes_active_tasks_and_preserves_pending_on_shutdown(
    tmp_path: Path,
) -> None:
    db_path = str(tmp_path / "worker_safety.db")
    exec_hb = str(tmp_path / "executor.heartbeat")
    rem_settings = _rem_settings(
        db_path,
        exec_hb,
        autoheal_remediation_enabled=True,
        autoheal_remediation_dry_run=False,
        autoheal_remediation_stale_timeout_seconds=0.05,
        autoheal_remediation_dispatch_mode="queue",
    )

    inc_mgr = IncidentManager(db_path=db_path, failure_threshold=1, recovery_threshold=1)
    ev = inc_mgr.process_check(
        HealthCheckResult(
            service_name="web",
            target_url="http://web/health",
            healthy=False,
            outcome=CheckOutcome.CONNECTION_ERROR,
            status_code=None,
            response_time_ms=5.0,
            error="down",
            checked_at=datetime.now(timezone.utc),
        )
    )
    assert ev.active_incident is not None

    started_event = asyncio.Event()
    release_event = asyncio.Event()

    class ControlledManager(ExecutionManager):
        async def process_pending_execution(self, execution_id: int, *, now=None):
            self.repository.claim_pending_execution(execution_id)
            started_event.set()
            await release_event.wait()
            return None

    RemediationCoordinator(rem_settings).handle_evaluation(ev)
    worker = ExecutorWorker(rem_settings, execution_manager=ControlledManager(rem_settings))
    assert await worker.run_once() == 1
    await asyncio.wait_for(started_event.wait(), timeout=2.0)

    # Sleep past stale_timeout_seconds (0.05s) while worker's live task owns execution.
    await asyncio.sleep(0.1)
    await worker.run_once()

    repo = RemediationRepository(db_path)
    active = repo.list_executions(incident_id=ev.active_incident.id)[0]
    assert active.status == RemediationStatus.RUNNING

    release_event.set()
    await worker.shutdown(timeout=2.0)

    # Unstarted PENDING execution skipped by mark_interrupted remains PENDING.
    inc2_ev = inc_mgr.process_check(
        HealthCheckResult(
            service_name="web2",
            target_url="http://web2/health",
            healthy=False,
            outcome=CheckOutcome.CONNECTION_ERROR,
            status_code=None,
            response_time_ms=5.0,
            error="down",
            checked_at=datetime.now(timezone.utc),
        )
    )
    assert inc2_ev.active_incident is not None
    pending_exec = repo.create_execution(
        incident_id=inc2_ev.active_incident.id,
        service_name="web",
        action="restart",
        status=RemediationStatus.PENDING,
        dry_run=False,
    )
    assert ExecutionManager(rem_settings, repository=repo).mark_interrupted(pending_exec.id) is None
    assert repo.get_execution(pending_exec.id).status == RemediationStatus.PENDING  # type: ignore[union-attr]
