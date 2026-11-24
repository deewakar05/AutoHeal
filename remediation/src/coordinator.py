"""Async-safe remediation coordinator integrating monitoring evaluations with execution."""

from __future__ import annotations

import asyncio
import logging

from .config import RemediationSettings
from .execution_manager import ExecutionManager
from .execution_models import ExecutionOutcome
from .models import (
    IncidentStatus,
    PolicyReason,
    RemediationAction,
    RemediationDecision,
    RemediationRequest,
    RemediationStatus,
    StateEvaluation,
)
from .policy import RemediationPolicy
from .repository import RemediationRepository

logger = logging.getLogger(__name__)


class RemediationCoordinator:
    """Bridges `MonitoringEngine` evaluations to policy checks and background remediation."""

    def __init__(
        self,
        settings: RemediationSettings,
        *,
        execution_manager: ExecutionManager | None = None,
        repository: RemediationRepository | None = None,
        action: str | RemediationAction = RemediationAction.RESTART,
    ) -> None:
        self._settings = settings
        self._action = (
            action.value if isinstance(action, RemediationAction) else str(action).strip().lower()
        )
        self._repository = repository
        self._execution_manager = execution_manager
        self._active_tasks: dict[int, asyncio.Task[ExecutionOutcome | None]] = {}

    @property
    def active_incident_ids(self) -> set[int]:
        """Return incident IDs currently tracked by active in-process remediation tasks."""
        return {inc_id for inc_id, task in self._active_tasks.items() if not task.done()}

    def _get_repository(self) -> RemediationRepository:
        if self._repository is None:
            self._repository = RemediationRepository(self._settings.autoheal_db_path)
        return self._repository

    def _get_execution_manager(self) -> ExecutionManager:
        if self._execution_manager is None:
            self._execution_manager = ExecutionManager(
                self._settings,
                repository=self._get_repository(),
            )
        return self._execution_manager

    def evaluate_for_incident(self, incident_id: int, service_name: str) -> RemediationDecision:
        """Evaluate remediation policy gates for an open incident."""
        policy = RemediationPolicy.from_sqlite(self._settings)
        request = RemediationRequest(
            incident_id=incident_id,
            service_name=service_name,
            action=self._action,
        )
        return policy.evaluate(request)

    def handle_evaluation(self, evaluation: StateEvaluation) -> asyncio.Task[ExecutionOutcome | None] | None:
        """Inspect monitoring state evaluation and trigger or queue remediation safely.

        Never triggers on transient failed checks while no open incident exists, and
        never executes Ansible synchronously on the monitoring event loop.
        """
        incident = evaluation.active_incident
        if incident is None or incident.status != IncidentStatus.OPEN:
            return None

        if self._settings.autoheal_remediation_dispatch_mode == "disabled":
            return None

        existing_task = self._active_tasks.get(incident.id)
        if existing_task is not None and not existing_task.done():
            logger.info(
                "Remediation task already active for incident; skipping duplicate trigger",
                extra={
                    "event": "remediation_skipped_active_worker",
                    "incident_id": incident.id,
                    "service_name": incident.service_name,
                },
            )
            return None

        decision = self.evaluate_for_incident(incident.id, incident.service_name)
        if not decision.allowed:
            log_fn = (
                logger.info
                if decision.reason in {PolicyReason.REMEDIATION_DISABLED, PolicyReason.COOLDOWN_ACTIVE}
                else logger.warning
            )
            log_fn(
                "Remediation rejected by policy",
                extra={
                    "event": "remediation_rejected",
                    "incident_id": incident.id,
                    "service_name": incident.service_name,
                    "action": self._action,
                    "reason": decision.reason.value,
                    "details": decision.details,
                    "cooldown_remaining_seconds": decision.cooldown_remaining_seconds,
                },
            )
            return None

        request = RemediationRequest(
            incident_id=incident.id,
            service_name=incident.service_name,
            action=self._action,
        )

        if self._settings.autoheal_remediation_dispatch_mode == "queue":
            repo = self._get_repository()
            reservation = repo.reserve_execution(
                request,
                self._settings,
                initial_status=RemediationStatus.PENDING,
                stale_after_seconds=self._settings.autoheal_remediation_stale_timeout_seconds,
            )
            if not reservation.reserved or reservation.execution is None:
                reserve_log_fn = (
                    logger.info
                    if reservation.decision.reason
                    in {
                        PolicyReason.REMEDIATION_DISABLED,
                        PolicyReason.COOLDOWN_ACTIVE,
                        PolicyReason.REMEDIATION_ALREADY_RUNNING,
                    }
                    else logger.warning
                )
                reserve_log_fn(
                    "Remediation queue reservation rejected",
                    extra={
                        "event": "remediation_rejected",
                        "incident_id": incident.id,
                        "service_name": incident.service_name,
                        "action": self._action,
                        "reason": reservation.decision.reason.value,
                        "details": reservation.decision.details,
                    },
                )
                return None

            logger.info(
                "Remediation execution queued for isolated worker",
                extra={
                    "event": "remediation_queued",
                    "execution_id": reservation.execution.id,
                    "incident_id": reservation.execution.incident_id,
                    "service_name": reservation.execution.service_name,
                    "action": reservation.execution.action,
                    "attempt_number": reservation.execution.attempt_number,
                    "dry_run": reservation.execution.dry_run,
                },
            )
            return None

        # in_process mode: spawn a tracked non-blocking async background task.
        task = asyncio.create_task(
            self._run_in_process(request),
            name=f"remediation-incident-{incident.id}",
        )
        self._active_tasks[incident.id] = task
        task.add_done_callback(lambda done_task, iid=incident.id: self._on_task_done(iid, done_task))
        return task

    async def _run_in_process(self, request: RemediationRequest) -> ExecutionOutcome:
        manager = self._get_execution_manager()
        return await manager.execute_incident(request)

    def _on_task_done(
        self,
        incident_id: int,
        task: asyncio.Task[ExecutionOutcome | None],
    ) -> None:
        current = self._active_tasks.get(incident_id)
        if current is task:
            self._active_tasks.pop(incident_id, None)
        if task.cancelled():
            logger.warning(
                "In-process remediation task cancelled",
                extra={"event": "remediation_task_cancelled", "incident_id": incident_id},
            )
            return
        exc = task.exception()
        if exc is not None:
            logger.error(
                "Unhandled exception in remediation background task",
                extra={
                    "event": "remediation_task_error",
                    "incident_id": incident_id,
                    "error": str(exc),
                },
            )

    async def drain(self, timeout: float = 10.0) -> None:
        """Await currently scheduled in-process remediation tasks without cancelling."""
        pending = [task for task in self._active_tasks.values() if not task.done()]
        if not pending:
            return
        await asyncio.wait_for(asyncio.gather(*pending, return_exceptions=True), timeout=timeout)

    async def shutdown(self, timeout: float = 10.0) -> None:
        """Gracefully wait for or cancel any active in-process remediation tasks."""
        pending = [task for task in self._active_tasks.values() if not task.done()]
        if not pending:
            return
        done, still_pending = await asyncio.wait(pending, timeout=timeout)
        _ = done
        for task in still_pending:
            task.cancel()
        if still_pending:
            await asyncio.gather(*still_pending, return_exceptions=True)
        self._active_tasks.clear()
