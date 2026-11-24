"""High-level coordinator uniting policy reservation, Ansible execution, verification, and SQLite."""

from __future__ import annotations

import inspect
import logging
from collections.abc import Collection
from datetime import datetime

from .config import RemediationSettings
from .database import get_connection, query_incident_snapshot, utc_now
from .execution_models import ExecutionOutcome
from .executor import RemediationExecutor
from .incident_manager import IncidentManager
from .metrics import MonitorMetrics
from .metrics_store import RemediationMetricsRecorder
from .models import (
    PolicyReason,
    RemediationDecision,
    RemediationExecution,
    RemediationRequest,
    RemediationStatus,
)
from .policy import evaluate_policy_gates
from .repository import RemediationRepository, sanitize_execution_text
from .verifier import RecoveryVerifier

logger = logging.getLogger(__name__)


class ExecutionManager:
    """Coordinates complete remediation lifecycle without resolving unverified incidents."""

    def __init__(
        self,
        settings: RemediationSettings,
        *,
        repository: RemediationRepository | None = None,
        executor: RemediationExecutor | None = None,
        verifier: RecoveryVerifier | None = None,
        incident_manager: IncidentManager | None = None,
        monitor_metrics: MonitorMetrics | None = None,
        metrics_recorder: RemediationMetricsRecorder | None = None,
    ) -> None:
        self._settings = settings
        self._repository = repository or RemediationRepository(settings.autoheal_db_path)
        self._executor = executor or RemediationExecutor(settings, repository=self._repository)
        self._verifier = verifier or RecoveryVerifier(settings)
        self._incident_manager = incident_manager or IncidentManager(
            db_path=settings.autoheal_db_path,
            recovery_threshold=settings.autoheal_remediation_verify_required_successes,
        )
        self._monitor_metrics = monitor_metrics or MonitorMetrics(db_path=settings.autoheal_db_path)
        self._metrics_recorder = metrics_recorder or RemediationMetricsRecorder(
            db_path=settings.autoheal_db_path
        )

    @property
    def repository(self) -> RemediationRepository:
        return self._repository

    def recover_stale(
        self,
        *,
        exclude_execution_ids: Collection[int] | None = None,
        now: datetime | None = None,
    ) -> list[RemediationExecution]:
        """Recover orphaned pending/running executions as timed_out and sync timeout metrics."""
        kwargs: dict[str, object] = {"now": now}
        try:
            sig = inspect.signature(self._repository.recover_stale_executions)
            if "exclude_execution_ids" in sig.parameters or any(
                p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
            ):
                kwargs["exclude_execution_ids"] = exclude_execution_ids
        except (TypeError, ValueError):
            pass

        recovered = self._repository.recover_stale_executions(
            self._settings.autoheal_remediation_stale_timeout_seconds,
            **kwargs,
        )
        for item in recovered:
            self._metrics_recorder.record_terminal(
                item,
                max_attempts=self._settings.autoheal_remediation_max_attempts,
                failure_outcome="timed_out",
            )
            logger.warning(
                "Recovered stale remediation execution as timed_out",
                extra={
                    "event": "remediation_stale_recovered",
                    "execution_id": item.id,
                    "incident_id": item.incident_id,
                    "service_name": item.service_name,
                    "attempt_number": item.attempt_number,
                },
            )
        return recovered

    def _uses_atomic_metrics_store(self) -> bool:
        return (
            type(self._repository) is RemediationRepository
            and type(self._metrics_recorder) is RemediationMetricsRecorder
            and self._repository.db_path == self._metrics_recorder.db_path
        )

    def _can_commit_verified_atomically(self) -> bool:
        return (
            self._uses_atomic_metrics_store()
            and type(self._incident_manager) is IncidentManager
            and type(self._monitor_metrics) is MonitorMetrics
            and self._repository.db_path == self._incident_manager.db_path
            and self._repository.db_path == self._monitor_metrics.db_path
        )

    def _persist_terminal(
        self,
        execution_id: int,
        status: RemediationStatus,
        *,
        failure_outcome: str | None = None,
        record_failure_metric: bool = True,
        completed_at: datetime | None = None,
        ansible_exit_code: int | None = None,
        execution_output: str | None = None,
        failure_reason: str | None = None,
        now: datetime | None = None,
    ) -> RemediationExecution:
        """Persist terminal status and terminal remediation metrics atomically when sharing SQLite."""
        if self._uses_atomic_metrics_store():
            conn = get_connection(self._repository.db_path, manual_transactions=True)
            try:
                conn.execute("BEGIN IMMEDIATE")
                updated = self._repository.update_status_in_tx(
                    conn,
                    execution_id,
                    status,
                    completed_at=completed_at,
                    ansible_exit_code=ansible_exit_code,
                    execution_output=execution_output,
                    failure_reason=failure_reason,
                    now=now,
                )
                self._metrics_recorder.record_terminal_in_tx(
                    conn,
                    updated,
                    max_attempts=self._settings.autoheal_remediation_max_attempts,
                    failure_outcome=failure_outcome,
                    record_failure_metric=record_failure_metric,
                )
                conn.execute("COMMIT")
                return updated
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()

        updated = self._repository.update_status(
            execution_id,
            status,
            completed_at=completed_at,
            ansible_exit_code=ansible_exit_code,
            execution_output=execution_output,
            failure_reason=failure_reason,
            now=now,
        )
        self._metrics_recorder.record_terminal(
            updated,
            max_attempts=self._settings.autoheal_remediation_max_attempts,
            failure_outcome=failure_outcome,
            record_failure_metric=record_failure_metric,
        )
        return updated

    def _complete_verified_success(
        self,
        execution: RemediationExecution,
        *,
        verified_at: datetime,
        ansible_exit_code: int | None,
        combined_output: str,
    ) -> tuple[RemediationExecution, bool]:
        """Resolve open incident, mark execution SUCCEEDED, and persist metrics atomically."""
        if self._can_commit_verified_atomically():
            conn = get_connection(self._repository.db_path, manual_transactions=True)
            try:
                conn.execute("BEGIN IMMEDIATE")
                _, resolved_now = self._incident_manager.resolve_open_incident_in_tx(
                    conn,
                    execution.incident_id,
                    verified_at,
                )
                if resolved_now:
                    MonitorMetrics.record_incident_resolved_in_tx(conn, execution.service_name)
                succeeded = self._repository.update_status_in_tx(
                    conn,
                    execution.id,
                    RemediationStatus.SUCCEEDED,
                    completed_at=verified_at,
                    ansible_exit_code=ansible_exit_code,
                    execution_output=combined_output,
                    failure_reason=None,
                    now=verified_at,
                )
                self._metrics_recorder.record_terminal_in_tx(
                    conn,
                    succeeded,
                    max_attempts=self._settings.autoheal_remediation_max_attempts,
                )
                conn.execute("COMMIT")
            except Exception:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()

            if resolved_now:
                self._monitor_metrics.incidents_total.labels(
                    service=execution.service_name,
                    event="resolved",
                ).inc()
            return succeeded, resolved_now

        _, resolved_now = self._incident_manager.resolve_open_incident(
            execution.incident_id,
            verified_at,
        )
        if resolved_now:
            self._monitor_metrics.record_incident_resolved(execution.service_name)

        succeeded = self._repository.update_status(
            execution.id,
            RemediationStatus.SUCCEEDED,
            completed_at=verified_at,
            ansible_exit_code=ansible_exit_code,
            execution_output=combined_output,
            failure_reason=None,
            now=verified_at,
        )
        self._metrics_recorder.record_terminal(
            succeeded,
            max_attempts=self._settings.autoheal_remediation_max_attempts,
        )
        return succeeded, resolved_now

    def mark_interrupted(
        self,
        execution_id: int,
        reason: str = "Remediation execution interrupted by executor shutdown signal.",
    ) -> RemediationExecution | None:
        """Mark an active RUNNING execution failed cleanly on shutdown; leave PENDING queued."""
        current = self._repository.get_execution(execution_id)
        if current is None or current.status != RemediationStatus.RUNNING:
            return None
        return self._persist_terminal(
            execution_id,
            RemediationStatus.FAILED,
            failure_outcome="interrupted",
            failure_reason=reason,
        )

    async def execute_incident(
        self,
        request: RemediationRequest,
        *,
        now: datetime | None = None,
    ) -> ExecutionOutcome:
        """Evaluate policy, atomically reserve, run dry-run/Ansible, verify, and persist."""
        reservation = self._executor.reserve(
            request,
            initial_status=RemediationStatus.RUNNING,
            now=now,
        )
        if not reservation.reserved or reservation.execution is None:
            return ExecutionOutcome(
                executed=False,
                verified=False,
                dry_run=reservation.decision.dry_run,
                decision=reservation.decision,
                execution=None,
                error=reservation.decision.details,
            )

        return await self._execute_claimed(reservation.execution, reservation.decision)

    async def process_pending_execution(
        self,
        execution_id: int,
        *,
        now: datetime | None = None,
    ) -> ExecutionOutcome | None:
        """Claim a queued `pending` execution and execute it inside isolated worker."""
        claimed = self._repository.claim_pending_execution(execution_id, now=now)
        if claimed is None:
            return None

        if not self._settings.autoheal_remediation_enabled:
            decision = RemediationDecision(
                allowed=False,
                reason=PolicyReason.REMEDIATION_DISABLED,
                dry_run=claimed.dry_run,
                service_name=claimed.service_name,
                action=claimed.action,
                incident_id=claimed.incident_id,
                details="Remediation disabled before queued execution started.",
            )
            failed = self._persist_terminal(
                claimed.id,
                RemediationStatus.FAILED,
                failure_outcome="policy_disabled",
                record_failure_metric=False,
                failure_reason=decision.details,
            )
            return ExecutionOutcome(
                executed=False,
                verified=False,
                dry_run=claimed.dry_run,
                decision=decision,
                execution=failed,
                error=decision.details,
            )

        decision = RemediationDecision(
            allowed=True,
            reason=PolicyReason.POLICY_APPROVED,
            dry_run=claimed.dry_run,
            service_name=claimed.service_name,
            action=claimed.action,
            incident_id=claimed.incident_id,
            details="Queued reservation claimed by isolated executor.",
        )
        return await self._execute_claimed(claimed, decision)

    async def _execute_claimed(
        self,
        execution: RemediationExecution,
        decision: RemediationDecision,
    ) -> ExecutionOutcome:
        """Execute a claimed RUNNING execution record cleanly and verify real recovery."""
        self._metrics_recorder.record_attempt(execution)

        if decision.dry_run or execution.dry_run:
            completed = self._executor.complete_dry_run(execution, decision)
            self._metrics_recorder.record_terminal(
                completed,
                max_attempts=self._settings.autoheal_remediation_max_attempts,
            )
            logger.info(
                "Remediation dry-run recorded",
                extra={
                    "event": "remediation_dry_run",
                    "execution_id": completed.id,
                    "incident_id": completed.incident_id,
                    "service_name": completed.service_name,
                    "action": completed.action,
                    "attempt_number": completed.attempt_number,
                },
            )
            return ExecutionOutcome(
                executed=True,
                verified=False,
                dry_run=True,
                decision=decision,
                execution=completed,
                ansible_result=None,
                verification=None,
                incident_resolved=False,
            )

        # Fail closed if global or incident conditions changed before live Ansible invocation.
        conn = get_connection(self._settings.autoheal_db_path, read_only=True)
        try:
            current_incident = query_incident_snapshot(conn, execution.incident_id)
        finally:
            conn.close()

        gate_check = evaluate_policy_gates(
            request=RemediationRequest(
                incident_id=execution.incident_id,
                service_name=execution.service_name,
                action=execution.action,
            ),
            settings=self._settings,
            incident=current_incident,
            state=self._empty_allowable_state(execution),
            current_time=utc_now(),
        )
        if not gate_check.allowed and gate_check.reason in {
            PolicyReason.INCIDENT_ALREADY_RESOLVED,
            PolicyReason.INCIDENT_NOT_FOUND,
            PolicyReason.SERVICE_NOT_ALLOWED,
            PolicyReason.ACTION_NOT_ALLOWED,
            PolicyReason.REMEDIATION_DISABLED,
        }:
            failed = self._persist_terminal(
                execution.id,
                RemediationStatus.FAILED,
                failure_outcome="aborted",
                record_failure_metric=False,
                failure_reason=gate_check.details,
            )
            return ExecutionOutcome(
                executed=False,
                verified=False,
                dry_run=False,
                decision=gate_check,
                execution=failed,
                error=gate_check.details,
            )

        try:
            ansible_result = await self._executor.execute_reserved_ansible(execution)
        except Exception as exc:  # noqa: BLE001
            err = sanitize_execution_text(f"Remediation execution error: {exc}", max_length=1000)
            failed = self._persist_terminal(
                execution.id,
                RemediationStatus.FAILED,
                failure_outcome="error",
                failure_reason=err,
            )
            return ExecutionOutcome(
                executed=True,
                verified=False,
                dry_run=False,
                decision=decision,
                execution=failed,
                error=err,
            )

        if ansible_result.timed_out:
            timed_out = self._persist_terminal(
                execution.id,
                RemediationStatus.TIMED_OUT,
                failure_outcome="timed_out",
                ansible_exit_code=ansible_result.exit_code,
                execution_output=ansible_result.combined_output,
                failure_reason=ansible_result.error or "Ansible execution timed out.",
            )
            return ExecutionOutcome(
                executed=True,
                verified=False,
                dry_run=False,
                decision=decision,
                execution=timed_out,
                ansible_result=ansible_result,
                incident_resolved=False,
                error=timed_out.failure_reason,
            )

        if not ansible_result.succeeded:
            failed = self._persist_terminal(
                execution.id,
                RemediationStatus.FAILED,
                failure_outcome="ansible_failed",
                ansible_exit_code=ansible_result.exit_code,
                execution_output=ansible_result.combined_output,
                failure_reason=ansible_result.error or "Ansible playbook execution failed.",
            )
            return ExecutionOutcome(
                executed=True,
                verified=False,
                dry_run=False,
                decision=decision,
                execution=failed,
                ansible_result=ansible_result,
                incident_resolved=False,
                error=failed.failure_reason,
            )

        # Ansible exit code 0 NEVER proves recovery: run independent health verification first.
        verification = await self._verifier.verify(service_name=execution.service_name)
        combined_output = "\n".join(
            part
            for part in (ansible_result.combined_output, f"[verification] {verification.details}")
            if part
        )

        if not verification.verified:
            failure_reason = (
                "Ansible completed (exit_code=0) but independent health verification failed: "
                f"{verification.details}"
            )
            failed = self._persist_terminal(
                execution.id,
                RemediationStatus.FAILED,
                failure_outcome="verification_failed",
                ansible_exit_code=ansible_result.exit_code,
                execution_output=combined_output,
                failure_reason=failure_reason,
            )
            return ExecutionOutcome(
                executed=True,
                verified=False,
                dry_run=False,
                decision=decision,
                execution=failed,
                ansible_result=ansible_result,
                verification=verification,
                incident_resolved=False,
                error=failure_reason,
            )

        verified_at = utc_now()
        succeeded, resolved_now = self._complete_verified_success(
            execution,
            verified_at=verified_at,
            ansible_exit_code=ansible_result.exit_code,
            combined_output=combined_output,
        )
        logger.info(
            "Remediation executed and verified healthy",
            extra={
                "event": "remediation_succeeded",
                "execution_id": succeeded.id,
                "incident_id": succeeded.incident_id,
                "service_name": succeeded.service_name,
                "action": succeeded.action,
                "attempt_number": succeeded.attempt_number,
                "incident_resolved": resolved_now,
            },
        )
        return ExecutionOutcome(
            executed=True,
            verified=True,
            dry_run=False,
            decision=decision,
            execution=succeeded,
            ansible_result=ansible_result,
            verification=verification,
            incident_resolved=resolved_now,
        )

    @staticmethod
    def _empty_allowable_state(_execution: RemediationExecution):
        from .models import RemediationState

        # Already reserved in SQLite; pass zeroed counters for service/action/open re-validation.
        return RemediationState(attempts=0, last_attempt_at=None, is_running=False)
