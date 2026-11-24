"""Unit tests for SQLite remediation history, state providers, and concurrency."""

from __future__ import annotations

import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from remediation.src.incident_manager import IncidentManager
from remediation.src.models import CheckOutcome, HealthCheckResult, IncidentStatus
from remediation.src.config import RemediationSettings
from remediation.src.database import (
    REMEDIATION_SCHEMA_VERSION,
    ensure_remediation_database,
    get_connection,
)
from remediation.src.models import (
    PolicyReason,
    RemediationAction,
    RemediationRequest,
    RemediationStatus,
)
from remediation.src.policy import (
    RemediationPolicy,
    SQLiteIncidentProvider,
    SQLiteRemediationStateProvider,
)
from remediation.src.repository import RemediationRepository


def _make_check(
    *,
    service_name: str = "web",
    healthy: bool,
    checked_at: datetime,
    status_code: int | None = None,
    error: str | None = None,
) -> HealthCheckResult:
    return HealthCheckResult(
        service_name=service_name,
        target_url="http://web/health",
        healthy=healthy,
        outcome=CheckOutcome.SUCCESS if healthy else CheckOutcome.HTTP_ERROR,
        status_code=200 if healthy else (status_code or 503),
        response_time_ms=12.5,
        error=None if healthy else (error or "Service unavailable"),
        checked_at=checked_at,
    )


def _seed_incident_db(
    tmp_path: Path,
    *,
    resolve: bool = False,
    service_name: str = "web",
    base_time: datetime | None = None,
) -> tuple[str, int]:
    """Initialize a temporary monitoring SQLite DB and create one open or resolved incident."""
    db_path = str(tmp_path / "autoheal.db")
    t0 = base_time or datetime(2026, 11, 10, 12, 0, 0, tzinfo=timezone.utc)
    manager = IncidentManager(db_path=db_path, failure_threshold=2, recovery_threshold=2)

    manager.process_check(_make_check(service_name=service_name, healthy=False, checked_at=t0))
    eval_open = manager.process_check(
        _make_check(
            service_name=service_name,
            healthy=False,
            checked_at=t0 + timedelta(seconds=10),
        )
    )
    assert eval_open.incident_created is not None
    incident_id = eval_open.incident_created.id

    if resolve:
        manager.process_check(
            _make_check(
                service_name=service_name,
                healthy=True,
                checked_at=t0 + timedelta(seconds=20),
            )
        )
        eval_resolved = manager.process_check(
            _make_check(
                service_name=service_name,
                healthy=True,
                checked_at=t0 + timedelta(seconds=30),
            )
        )
        assert eval_resolved.incident_resolved is not None

    return db_path, incident_id


def _enabled_settings(**overrides: object) -> RemediationSettings:
    defaults: dict[str, object] = {
        "_env_file": None,
        "autoheal_remediation_enabled": True,
        "autoheal_remediation_dry_run": False,
        "autoheal_remediation_cooldown_seconds": 300,
        "autoheal_remediation_max_attempts": 3,
        "autoheal_remediation_timeout_seconds": 120.0,
        "autoheal_allowed_services": "web",
        "autoheal_allowed_actions": "restart,start",
    }
    defaults.update(overrides)
    return RemediationSettings(**defaults)


def test_remediation_schema_initialization_and_idempotency(tmp_path: Path) -> None:
    db_path, incident_id = _seed_incident_db(tmp_path)

    ensure_remediation_database(db_path)
    repo = RemediationRepository(db_path)
    created = repo.create_execution(
        incident_id=incident_id,
        service_name="web",
        action=RemediationAction.RESTART,
        status=RemediationStatus.DRY_RUN,
        dry_run=True,
    )

    # Second initialization must remain idempotent and keep incidents + remediation rows intact.
    ensure_remediation_database(db_path)

    conn = get_connection(db_path, read_only=True)
    try:
        cols = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(remediation_executions)").fetchall()
        }
        expected_cols = {
            "id",
            "incident_id",
            "service_name",
            "action",
            "status",
            "attempt_number",
            "started_at",
            "completed_at",
            "duration_seconds",
            "ansible_exit_code",
            "execution_output",
            "failure_reason",
            "dry_run",
            "created_at",
        }
        assert cols == expected_cols

        version_row = conn.execute(
            "SELECT version FROM remediation_schema_meta WHERE schema_name = 'remediation'"
        ).fetchone()
        assert version_row is not None
        assert int(version_row["version"]) == REMEDIATION_SCHEMA_VERSION

        incident_row = conn.execute(
            "SELECT id, service_name, status FROM incidents WHERE id = ?",
            (incident_id,),
        ).fetchone()
        assert incident_row is not None
        assert incident_row["service_name"] == "web"
        assert incident_row["status"] == IncidentStatus.OPEN.value

        fetched = repo.get_execution(created.id)
        assert fetched is not None
        assert fetched.id == created.id
        assert fetched.attempt_number == 1
    finally:
        conn.close()


def test_repository_crud_filtering_pagination_and_reconnection_persistence(
    tmp_path: Path,
) -> None:
    db_path, incident_id = _seed_incident_db(tmp_path)
    manager = IncidentManager(db_path=db_path, failure_threshold=1, recovery_threshold=1)
    second_eval = manager.process_check(
        _make_check(
            service_name="api",
            healthy=False,
            checked_at=datetime(2026, 11, 10, 12, 5, 0, tzinfo=timezone.utc),
        )
    )
    assert second_eval.incident_created is not None
    second_incident_id = second_eval.incident_created.id

    repo = RemediationRepository(db_path)
    t1 = datetime(2026, 11, 10, 12, 1, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 11, 10, 12, 6, 0, tzinfo=timezone.utc)
    t3 = datetime(2026, 11, 10, 12, 7, 0, tzinfo=timezone.utc)

    first = repo.create_execution(
        incident_id=incident_id,
        service_name="web",
        action="restart",
        status=RemediationStatus.SUCCEEDED,
        started_at=t1,
        completed_at=t1 + timedelta(seconds=8.5),
        ansible_exit_code=0,
        execution_output="token=super-secret-value\x00 restarted cleanly",
        dry_run=False,
        created_at=t1,
    )
    second = repo.create_execution(
        incident_id=incident_id,
        service_name="web",
        action="start",
        status=RemediationStatus.FAILED,
        started_at=t2,
        completed_at=t2 + timedelta(seconds=4.0),
        ansible_exit_code=2,
        failure_reason="Authorization: Bearer secretJwt12345 caused error",
        dry_run=False,
        created_at=t2,
    )
    third = repo.create_execution(
        incident_id=second_incident_id,
        service_name="api",
        action="restart",
        status=RemediationStatus.DRY_RUN,
        dry_run=True,
        created_at=t3,
    )

    assert first.duration_seconds == pytest.approx(8.5)
    assert first.execution_output == "token=*** restarted cleanly"
    assert second.attempt_number == 2
    assert second.failure_reason == "Authorization: *** *** caused error"
    assert "secretJwt12345" not in second.failure_reason
    assert third.attempt_number == 1

    # Recreate repository instance to verify persistence after database reconnection.
    reconnected_repo = RemediationRepository(db_path)
    assert reconnected_repo.count_attempts(incident_id) == 2
    assert reconnected_repo.count_attempts(second_incident_id) == 1

    latest = reconnected_repo.get_latest_execution(incident_id)
    assert latest is not None
    assert latest.id == second.id
    assert reconnected_repo.get_latest_attempt_at(incident_id) == t2
    assert reconnected_repo.get_active_execution(incident_id) is None

    web_records = reconnected_repo.list_executions(incident_id=incident_id, service_name="web")
    assert [r.id for r in web_records] == [second.id, first.id]

    failed_records = reconnected_repo.list_executions(status=RemediationStatus.FAILED)
    assert [r.id for r in failed_records] == [second.id]

    page_1 = reconnected_repo.list_executions(limit=2, offset=0)
    page_2 = reconnected_repo.list_executions(limit=2, offset=2)
    assert [r.id for r in page_1] == [third.id, second.id]
    assert [r.id for r in page_2] == [first.id]

    assert reconnected_repo.get_execution(999999) is None
    assert reconnected_repo.get_execution(0) is None

    with pytest.raises(ValueError, match="limit"):
        reconnected_repo.list_executions(limit=0)

    with pytest.raises(ValueError, match="offset"):
        reconnected_repo.list_executions(offset=-1)


def test_repository_status_transitions_and_validation_errors(tmp_path: Path) -> None:
    db_path, incident_id = _seed_incident_db(tmp_path)
    repo = RemediationRepository(db_path)
    t0 = datetime(2026, 11, 10, 12, 0, 0, tzinfo=timezone.utc)

    pending = repo.create_execution(
        incident_id=incident_id,
        service_name="web",
        action="restart",
        status=RemediationStatus.PENDING,
        dry_run=False,
        created_at=t0,
    )
    assert repo.get_active_execution(incident_id) == pending

    running = repo.update_status(
        pending.id,
        RemediationStatus.RUNNING,
        now=t0 + timedelta(seconds=2),
    )
    assert running.status == RemediationStatus.RUNNING
    assert running.started_at == t0 + timedelta(seconds=2)

    succeeded = repo.update_status(
        pending.id,
        RemediationStatus.SUCCEEDED,
        ansible_exit_code=0,
        execution_output="ok",
        now=t0 + timedelta(seconds=12),
    )
    assert succeeded.status == RemediationStatus.SUCCEEDED
    assert succeeded.duration_seconds == pytest.approx(10.0)
    assert repo.get_active_execution(incident_id) is None

    # Terminal executions cannot transition back to running or another terminal state.
    with pytest.raises(ValueError, match="terminal status"):
        repo.update_status(pending.id, RemediationStatus.FAILED)

    with pytest.raises(LookupError):
        repo.update_status(999999, RemediationStatus.FAILED)

    with pytest.raises(ValueError):
        repo.update_status(0, RemediationStatus.FAILED)

    with pytest.raises(ValueError):
        repo.update_status(pending.id, RemediationStatus.FAILED, duration_seconds=-1.0)

    # Invalid create inputs & foreign key enforcement.
    with pytest.raises(sqlite3.IntegrityError):
        repo.create_execution(incident_id=9999, service_name="web", action="restart")

    with pytest.raises(ValueError):
        repo.create_execution(incident_id=0, service_name="web", action="restart")

    with pytest.raises(ValueError):
        repo.create_execution(incident_id=incident_id, service_name="web;rm", action="restart")

    with pytest.raises(ValueError):
        repo.create_execution(incident_id=incident_id, service_name="web", action="exec")

    with pytest.raises(ValueError):
        repo.create_execution(incident_id=incident_id, service_name="web", action="restart", status="bogus")

    with pytest.raises(ValueError):
        repo.create_execution(
            incident_id=incident_id,
            service_name="web",
            action="restart",
            duration_seconds=-0.5,
        )

    # Partial unique active index prevents inserting two active executions for the same incident.
    repo.create_execution(
        incident_id=incident_id,
        service_name="web",
        action="restart",
        status=RemediationStatus.RUNNING,
    )
    with pytest.raises(sqlite3.IntegrityError):
        repo.create_execution(
            incident_id=incident_id,
            service_name="web",
            action="restart",
            status=RemediationStatus.PENDING,
        )


def test_sqlite_incident_and_state_providers_and_policy_integration(tmp_path: Path) -> None:
    missing_db = str(tmp_path / "missing.db")
    missing_incident_provider = SQLiteIncidentProvider(missing_db)
    assert missing_incident_provider.get_incident(1) is None
    assert not Path(missing_db).exists()

    open_db, open_id = _seed_incident_db(tmp_path, resolve=False)
    incident_provider = SQLiteIncidentProvider(open_db)
    open_snapshot = incident_provider.get_incident(open_id)
    assert open_snapshot is not None
    assert open_snapshot.status == "open"
    assert incident_provider.get_incident(999999) is None

    # Safety default: even with a real open incident in SQLite, disabled settings still deny.
    disabled_policy = RemediationPolicy.from_sqlite(
        RemediationSettings(_env_file=None),
        db_path=open_db,
    )
    disabled_decision = disabled_policy.evaluate(
        RemediationRequest(incident_id=open_id, service_name="web", action="restart")
    )
    assert disabled_decision.allowed is False
    assert disabled_decision.reason == PolicyReason.REMEDIATION_DISABLED

    # Cooldown and attempt tracking across DB reconnection.
    t0 = datetime(2026, 11, 10, 13, 0, 0, tzinfo=timezone.utc)
    repo = RemediationRepository(open_db)
    repo.create_execution(
        incident_id=open_id,
        service_name="web",
        action="restart",
        status=RemediationStatus.FAILED,
        started_at=t0,
        completed_at=t0 + timedelta(seconds=5),
        dry_run=False,
        created_at=t0,
    )

    # Inside 300s cooldown window.
    during_cooldown_clock = t0 + timedelta(seconds=120)
    settings = _enabled_settings(autoheal_remediation_cooldown_seconds=300)
    policy_in_cooldown = RemediationPolicy.from_sqlite(
        settings,
        db_path=open_db,
        clock=lambda: during_cooldown_clock,
    )
    cooldown_decision = policy_in_cooldown.evaluate(
        RemediationRequest(incident_id=open_id, service_name="web", action="restart")
    )
    assert cooldown_decision.allowed is False
    assert cooldown_decision.reason == PolicyReason.COOLDOWN_ACTIVE
    assert cooldown_decision.cooldown_remaining_seconds == pytest.approx(180.0)

    # After cooldown expires.
    after_cooldown_clock = t0 + timedelta(seconds=301)
    policy_ready = RemediationPolicy.from_sqlite(
        settings,
        db_path=open_db,
        clock=lambda: after_cooldown_clock,
    )
    ready_decision = policy_ready.evaluate(
        RemediationRequest(incident_id=open_id, service_name="web", action="restart")
    )
    assert ready_decision.allowed is True
    assert ready_decision.reason == PolicyReason.POLICY_APPROVED

    # Resolved incident check from SQLite.
    resolved_dir = tmp_path / "resolved_case"
    resolved_dir.mkdir()
    resolved_db, resolved_id = _seed_incident_db(resolved_dir, resolve=True)
    ensure_remediation_database(resolved_db)
    resolved_policy = RemediationPolicy.from_sqlite(settings, db_path=resolved_db)
    resolved_decision = resolved_policy.evaluate(
        RemediationRequest(incident_id=resolved_id, service_name="web", action="restart")
    )
    assert resolved_decision.allowed is False
    assert resolved_decision.reason == PolicyReason.INCIDENT_ALREADY_RESOLVED


def test_stale_running_record_detection_and_recovery(tmp_path: Path) -> None:
    db_path, incident_id = _seed_incident_db(tmp_path)
    repo = RemediationRepository(db_path)
    started = datetime(2026, 11, 10, 14, 0, 0, tzinfo=timezone.utc)

    stale_row = repo.create_execution(
        incident_id=incident_id,
        service_name="web",
        action="restart",
        status=RemediationStatus.RUNNING,
        started_at=started,
        dry_run=False,
        created_at=started,
    )

    # Before timeout -> active running execution blocks new remediation.
    before_timeout = started + timedelta(seconds=60)
    state_provider_active = SQLiteRemediationStateProvider(
        db_path,
        stale_after_seconds=120.0,
        clock=lambda: before_timeout,
    )
    active_state = state_provider_active.get_state(incident_id, "web")
    assert active_state.is_running is True
    assert active_state.current_execution is not None
    assert active_state.current_execution.id == stale_row.id
    assert active_state.stale_execution is None

    # Past timeout -> read-only state provider ignores stale lock without mutating DB.
    after_timeout = started + timedelta(seconds=180)
    state_provider_stale = SQLiteRemediationStateProvider(
        db_path,
        stale_after_seconds=120.0,
        clock=lambda: after_timeout,
    )
    stale_state = state_provider_stale.get_state(incident_id, "web")
    assert stale_state.is_running is False
    assert stale_state.stale_execution is not None
    assert stale_state.stale_execution.id == stale_row.id
    assert repo.get_execution(stale_row.id).status == RemediationStatus.RUNNING  # type: ignore[union-attr]

    # Explicit recovery transitions stale record to TIMED_OUT (never SUCCEEDED) and keeps attempt count.
    recovered = repo.recover_stale_executions(120.0, now=after_timeout)
    assert len(recovered) == 1
    assert recovered[0].id == stale_row.id
    assert recovered[0].status == RemediationStatus.TIMED_OUT
    assert recovered[0].duration_seconds == pytest.approx(180.0)
    assert "timed_out" in (recovered[0].failure_reason or "").lower()
    assert repo.count_attempts(incident_id) == 1
    assert repo.get_active_execution(incident_id) is None

    # Subsequent reserve_execution succeeds as attempt 2 once cooldown passes.
    settings = _enabled_settings(autoheal_remediation_cooldown_seconds=60)
    reserve_after = started + timedelta(seconds=200)
    reservation = repo.reserve_execution(
        RemediationRequest(incident_id=incident_id, service_name="web", action="restart"),
        settings,
        now=reserve_after,
    )
    assert reservation.reserved is True
    assert reservation.execution is not None
    assert reservation.execution.attempt_number == 2
    assert reservation.execution.status == RemediationStatus.RUNNING


def test_atomic_reservation_recovers_stale_row_and_prevents_concurrent_double_execution(
    tmp_path: Path,
) -> None:
    db_path, incident_id = _seed_incident_db(tmp_path)
    repo = RemediationRepository(db_path)
    settings = _enabled_settings(
        autoheal_remediation_cooldown_seconds=0,
        autoheal_remediation_max_attempts=2,
        autoheal_remediation_timeout_seconds=60.0,
        autoheal_remediation_stale_timeout_seconds=60.0,
    )
    t0 = datetime(2026, 11, 10, 15, 0, 0, tzinfo=timezone.utc)

    # First verify atomic stale recovery inside reserve_execution itself.
    orphaned = repo.create_execution(
        incident_id=incident_id,
        service_name="web",
        action="restart",
        status=RemediationStatus.RUNNING,
        started_at=t0,
        dry_run=False,
        created_at=t0,
    )
    recovered_reservation = repo.reserve_execution(
        RemediationRequest(incident_id=incident_id, service_name="web", action="restart"),
        settings,
        now=t0 + timedelta(seconds=90),
    )
    assert recovered_reservation.reserved is True
    assert recovered_reservation.execution is not None
    assert recovered_reservation.execution.attempt_number == 2
    reloaded_orphan = repo.get_execution(orphaned.id)
    assert reloaded_orphan is not None
    assert reloaded_orphan.status == RemediationStatus.TIMED_OUT

    # Complete attempt 2 on a fresh incident and test multi-threaded race protection.
    race_dir = tmp_path / "race_case"
    race_dir.mkdir()
    race_db, race_incident_id = _seed_incident_db(race_dir)
    race_repo = RemediationRepository(race_db)
    race_settings = _enabled_settings(
        autoheal_remediation_cooldown_seconds=0,
        autoheal_remediation_max_attempts=1,
    )
    worker_count = 8
    barrier = threading.Barrier(worker_count)

    def _attempt_reserve() -> tuple[bool, PolicyReason]:
        barrier.wait()
        res = race_repo.reserve_execution(
            RemediationRequest(
                incident_id=race_incident_id,
                service_name="web",
                action="restart",
            ),
            race_settings,
            now=t0,
        )
        return res.reserved, res.decision.reason

    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        outcomes = list(pool.map(lambda _: _attempt_reserve(), range(worker_count)))

    reserved_outcomes = [o for o in outcomes if o[0] is True]
    denied_outcomes = [o for o in outcomes if o[0] is False]

    assert len(reserved_outcomes) == 1
    assert reserved_outcomes[0][1] == PolicyReason.POLICY_APPROVED
    assert len(denied_outcomes) == worker_count - 1
    assert all(reason == PolicyReason.REMEDIATION_ALREADY_RUNNING for _, reason in denied_outcomes)
    assert race_repo.count_attempts(race_incident_id) == 1

    # Once that single execution finishes, further concurrent reservations hit MAX_ATTEMPTS_REACHED.
    active = race_repo.get_active_execution(race_incident_id)
    assert active is not None
    race_repo.update_status(active.id, RemediationStatus.SUCCEEDED, now=t0 + timedelta(seconds=10))

    barrier_2 = threading.Barrier(worker_count)

    def _attempt_after_max() -> tuple[bool, PolicyReason]:
        barrier_2.wait()
        res = race_repo.reserve_execution(
            RemediationRequest(
                incident_id=race_incident_id,
                service_name="web",
                action="restart",
            ),
            race_settings,
            now=t0 + timedelta(seconds=20),
        )
        return res.reserved, res.decision.reason

    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        post_outcomes = list(pool.map(lambda _: _attempt_after_max(), range(worker_count)))

    assert all(reserved is False for reserved, _ in post_outcomes)
    assert all(reason == PolicyReason.MAX_ATTEMPTS_REACHED for _, reason in post_outcomes)
    assert race_repo.count_attempts(race_incident_id) == 1


def test_reserve_execution_rolls_back_cleanly_on_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path, incident_id = _seed_incident_db(tmp_path)
    repo = RemediationRepository(db_path)
    settings = _enabled_settings(autoheal_remediation_cooldown_seconds=0)

    def _boom(_value: datetime) -> str:
        raise RuntimeError("Simulated persistence failure mid-transaction")

    monkeypatch.setattr("remediation.src.repository.format_utc", _boom)

    with pytest.raises(RuntimeError, match="Simulated persistence failure"):
        repo.reserve_execution(
            RemediationRequest(incident_id=incident_id, service_name="web", action="restart"),
            settings,
        )

    assert repo.count_attempts(incident_id) == 0
    assert repo.get_active_execution(incident_id) is None


def test_reserve_execution_denies_cooldown_without_side_effects(tmp_path: Path) -> None:
    db_path, incident_id = _seed_incident_db(tmp_path)
    repo = RemediationRepository(db_path)
    t0 = datetime(2026, 11, 10, 16, 0, 0, tzinfo=timezone.utc)

    repo.create_execution(
        incident_id=incident_id,
        service_name="web",
        action="restart",
        status=RemediationStatus.FAILED,
        started_at=t0,
        completed_at=t0 + timedelta(seconds=5),
        dry_run=False,
        created_at=t0,
    )

    settings = _enabled_settings(
        autoheal_remediation_cooldown_seconds=300,
        autoheal_remediation_max_attempts=3,
    )
    denied = repo.reserve_execution(
        RemediationRequest(incident_id=incident_id, service_name="web", action="restart"),
        settings,
        now=t0 + timedelta(seconds=100),
    )
    assert denied.reserved is False
    assert denied.execution is None
    assert denied.decision.reason == PolicyReason.COOLDOWN_ACTIVE
    assert denied.decision.cooldown_remaining_seconds == pytest.approx(200.0)
    assert repo.count_attempts(incident_id) == 1


def test_status_summary_excludes_recovered_incidents_from_exhausted_and_uses_stale_timeout(
    tmp_path: Path,
) -> None:
    db_path, incident_id = _seed_incident_db(tmp_path)
    repo = RemediationRepository(db_path)
    t0 = datetime(2026, 11, 10, 17, 0, 0, tzinfo=timezone.utc)

    # Attempt 1 failed, attempt 2 succeeded -> reaches max_attempts=2, but incident recovered.
    repo.create_execution(
        incident_id=incident_id,
        service_name="web",
        action="restart",
        status=RemediationStatus.FAILED,
        started_at=t0,
        completed_at=t0 + timedelta(seconds=2),
        dry_run=False,
        created_at=t0,
    )
    repo.create_execution(
        incident_id=incident_id,
        service_name="web",
        action="restart",
        status=RemediationStatus.SUCCEEDED,
        started_at=t0 + timedelta(minutes=1),
        completed_at=t0 + timedelta(minutes=1, seconds=3),
        dry_run=False,
        created_at=t0 + timedelta(minutes=1),
    )
    summary = repo.get_status_summary(max_attempts=2)
    assert summary["exhausted_incidents"] == 0

    # Policy.from_sqlite must use stale_timeout_seconds (180s), not execution timeout (60s).
    inc_dir = tmp_path / "stale_policy"
    inc_dir.mkdir()
    stale_db, stale_incident_id = _seed_incident_db(inc_dir)
    stale_repo = RemediationRepository(stale_db)
    stale_repo.create_execution(
        incident_id=stale_incident_id,
        service_name="web",
        action="restart",
        status=RemediationStatus.RUNNING,
        started_at=t0,
        dry_run=False,
        created_at=t0,
    )
    policy_settings = _enabled_settings(
        autoheal_remediation_timeout_seconds=60.0,
        autoheal_remediation_stale_timeout_seconds=180.0,
    )
    policy = RemediationPolicy.from_sqlite(
        policy_settings,
        db_path=stale_db,
        clock=lambda: t0 + timedelta(seconds=90),
    )
    decision = policy.evaluate(
        RemediationRequest(incident_id=stale_incident_id, service_name="web", action="restart")
    )
    assert decision.allowed is False
    assert decision.reason == PolicyReason.REMEDIATION_ALREADY_RUNNING
