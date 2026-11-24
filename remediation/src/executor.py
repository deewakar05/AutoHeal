"""Remediation executor wrapping policy reservation, concurrency limits, and Ansible execution."""

from __future__ import annotations

import asyncio
import inspect
import threading
from contextlib import suppress
from datetime import datetime

from .ansible_runner import AnsibleRunner
from .config import RemediationSettings
from .database import utc_now
from .execution_models import AnsibleRunResult
from .models import (
    RemediationDecision,
    RemediationExecution,
    RemediationRequest,
    RemediationStatus,
    ReservationResult,
)
from .repository import RemediationRepository, sanitize_execution_text


class RemediationExecutor:
    """Validates, reserves, and executes bounded Ansible actions without blocks on event loop."""

    def __init__(
        self,
        settings: RemediationSettings,
        repository: RemediationRepository | None = None,
        runner: AnsibleRunner | None = None,
    ) -> None:
        self._settings = settings
        self._repository = repository or RemediationRepository(settings.autoheal_db_path)
        self._runner = runner or AnsibleRunner(settings)
        self._semaphore = asyncio.Semaphore(settings.autoheal_remediation_max_concurrency)

    @property
    def repository(self) -> RemediationRepository:
        return self._repository

    @property
    def runner(self) -> AnsibleRunner:
        return self._runner

    def reserve(
        self,
        request: RemediationRequest,
        *,
        initial_status: RemediationStatus = RemediationStatus.RUNNING,
        now: datetime | None = None,
    ) -> ReservationResult:
        """Atomically evaluate policy gates and reserve an execution slot in SQLite."""
        return self._repository.reserve_execution(
            request,
            self._settings,
            initial_status=initial_status,
            stale_after_seconds=self._settings.autoheal_remediation_stale_timeout_seconds,
            now=now,
        )

    def _call_runner_run(
        self,
        *,
        service_name: str,
        action: str,
        timeout_seconds: float,
        cancel_event: threading.Event,
    ) -> AnsibleRunResult:
        """Invoke `_runner.run` passing `cancel_event` when supported by the runner."""
        kwargs: dict[str, object] = {
            "service_name": service_name,
            "action": action,
            "timeout_seconds": timeout_seconds,
        }
        try:
            sig = inspect.signature(self._runner.run)
            if "cancel_event" in sig.parameters or any(
                param.kind == inspect.Parameter.VAR_KEYWORD
                for param in sig.parameters.values()
            ):
                kwargs["cancel_event"] = cancel_event
        except (TypeError, ValueError):
            pass
        return self._runner.run(**kwargs)

    async def execute_reserved_ansible(
        self,
        execution: RemediationExecution,
    ) -> AnsibleRunResult:
        """Run allowlisted Ansible playbook for an active non-dry-run execution record."""
        if execution.dry_run:
            raise ValueError("Refusing to invoke Ansible for a dry-run execution")

        async with self._semaphore:
            cancel_event = threading.Event()
            outer_timeout = float(self._settings.autoheal_remediation_timeout_seconds) + 5.0
            task = asyncio.create_task(
                asyncio.to_thread(
                    self._call_runner_run,
                    service_name=execution.service_name,
                    action=execution.action,
                    timeout_seconds=self._settings.autoheal_remediation_timeout_seconds,
                    cancel_event=cancel_event,
                )
            )
            try:
                # Run synchronous subprocess safely off the asyncio event loop.
                return await asyncio.wait_for(asyncio.shield(task), timeout=outer_timeout)
            except asyncio.TimeoutError:
                cancel_event.set()
                with suppress(Exception):
                    await asyncio.wait_for(task, timeout=5.0)
                msg = (
                    f"Executor watchdog timed out after "
                    f"{self._settings.autoheal_remediation_timeout_seconds}s"
                )
                return AnsibleRunResult(
                    succeeded=False,
                    exit_code=None,
                    timed_out=True,
                    duration_seconds=float(self._settings.autoheal_remediation_timeout_seconds),
                    playbook=self._settings.autoheal_ansible_playbook_path,
                    stdout="",
                    stderr="",
                    combined_output=msg,
                    error=msg,
                )
            except asyncio.CancelledError:
                cancel_event.set()
                with suppress(Exception):
                    await asyncio.wait_for(asyncio.shield(task), timeout=5.0)
                raise
            except Exception as exc:  # noqa: BLE001
                err = sanitize_execution_text(f"Executor unexpected error: {exc}", max_length=1000)
                return AnsibleRunResult(
                    succeeded=False,
                    exit_code=None,
                    timed_out=False,
                    duration_seconds=0.0,
                    playbook=self._settings.autoheal_ansible_playbook_path,
                    stdout="",
                    stderr="",
                    combined_output=err or "",
                    error=err or "Executor unexpected error",
                )

    def complete_dry_run(
        self,
        execution: RemediationExecution,
        decision: RemediationDecision,
        *,
        now: datetime | None = None,
    ) -> RemediationExecution:
        """Persist a completed dry-run outcome without calling Ansible."""
        effective_now = now or utc_now()
        output = (
            f"Dry-run approved for service={decision.service_name!r}, "
            f"action={decision.action!r} (playbook={self._settings.autoheal_ansible_playbook_path!r}); "
            "skipped Ansible subprocess execution."
        )
        return self._repository.update_status(
            execution.id,
            RemediationStatus.DRY_RUN,
            completed_at=effective_now,
            duration_seconds=0.0,
            ansible_exit_code=None,
            execution_output=output,
            failure_reason=None,
            now=effective_now,
        )
