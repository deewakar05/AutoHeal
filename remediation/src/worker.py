"""Standalone asynchronous worker running in the isolated remediation executor container."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
from pathlib import Path

from .config import RemediationSettings, get_settings
from .execution_manager import ExecutionManager
from .logging_config import configure_logging

logger = logging.getLogger(__name__)


class ExecutorWorker:
    """Polls SQLite for approved `pending` executions and runs isolated remediation."""

    def __init__(
        self,
        settings: RemediationSettings,
        *,
        execution_manager: ExecutionManager | None = None,
    ) -> None:
        self._settings = settings
        self._manager = execution_manager or ExecutionManager(settings)
        self._active_tasks: dict[int, asyncio.Task] = {}

    def touch_heartbeat(self) -> None:
        """Refresh executor heartbeat timestamp for Docker healthcheck monitoring."""
        heartbeat = Path(self._settings.autoheal_remediation_executor_heartbeat_path)
        heartbeat.parent.mkdir(parents=True, exist_ok=True)
        heartbeat.touch()

    async def run_once(self) -> int:
        """Recover stale records and schedule up to max_concurrency queued jobs."""
        # Reap completed background worker tasks cleanly first.
        for exec_id in [k for k, task in self._active_tasks.items() if task.done()]:
            task = self._active_tasks.pop(exec_id)
            if not task.cancelled() and task.exception() is not None:
                logger.error(
                    "Executor worker task failed unexpectedly",
                    extra={
                        "event": "executor_task_error",
                        "execution_id": exec_id,
                        "error": str(task.exception()),
                    },
                )

        active_ids = list(self._active_tasks.keys())
        self._manager.recover_stale(exclude_execution_ids=active_ids)

        available_slots = self._settings.autoheal_remediation_max_concurrency - len(
            self._active_tasks
        )
        scheduled = 0
        if available_slots > 0:
            pending = self._manager.repository.list_pending_executions(limit=available_slots)
            for item in pending:
                if item.id in self._active_tasks:
                    continue
                task = asyncio.create_task(
                    self._process_one(item.id),
                    name=f"executor-job-{item.id}",
                )
                self._active_tasks[item.id] = task
                scheduled += 1

        # Refresh heartbeat after SQLite polling succeeds so degraded DB health surfaces via Docker.
        self.touch_heartbeat()
        return scheduled

    async def _process_one(self, execution_id: int) -> None:
        try:
            await self._manager.process_pending_execution(execution_id)
        except asyncio.CancelledError:
            interrupted = self._manager.mark_interrupted(execution_id)
            if interrupted is not None:
                logger.warning(
                    "Marked interrupted remediation execution failed on shutdown",
                    extra={
                        "event": "executor_execution_interrupted",
                        "execution_id": interrupted.id,
                        "incident_id": interrupted.incident_id,
                    },
                )
            raise

    async def drain(self, timeout: float = 10.0) -> None:
        """Await currently scheduled executor tasks without cancelling them."""
        pending = [task for task in self._active_tasks.values() if not task.done()]
        if not pending:
            return
        await asyncio.wait_for(asyncio.gather(*pending, return_exceptions=True), timeout=timeout)

    async def run_forever(self, stop_event: asyncio.Event) -> None:
        """Continuously poll for queued remediations until stop_event is set."""
        self.touch_heartbeat()
        logger.info(
            "Starting isolated remediation executor worker",
            extra={
                "event": "executor_started",
                "remediation_enabled": self._settings.autoheal_remediation_enabled,
                "dry_run": self._settings.autoheal_remediation_dry_run,
                "allowed_services": list(self._settings.autoheal_allowed_services),
                "allowed_actions": list(self._settings.autoheal_allowed_actions),
                "poll_interval_seconds": self._settings.autoheal_remediation_executor_poll_interval,
                "max_concurrency": self._settings.autoheal_remediation_max_concurrency,
                "require_isolation": self._settings.autoheal_remediation_require_isolation,
            },
        )

        while not stop_event.is_set():
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                logger.exception(
                    "Unexpected exception in remediation executor loop",
                    extra={"event": "executor_loop_error"},
                )

            try:
                await asyncio.wait_for(
                    stop_event.wait(),
                    timeout=self._settings.autoheal_remediation_executor_poll_interval,
                )
            except asyncio.TimeoutError:
                continue

    async def shutdown(self, timeout: float = 15.0) -> None:
        """Wait gracefully for active remediation jobs or mark interrupted cleanly."""
        pending = [task for task in self._active_tasks.values() if not task.done()]
        if pending:
            _, still_running = await asyncio.wait(pending, timeout=timeout)
            for task in still_running:
                task.cancel()
            if still_running:
                await asyncio.gather(*still_running, return_exceptions=True)
        self._active_tasks.clear()
        logger.info("Remediation executor worker stopped", extra={"event": "executor_stopped"})


async def _run() -> None:
    settings = get_settings()
    log_level = os.getenv("LOG_LEVEL", "INFO")
    configure_logging(component="remediation-executor", level=log_level)
    worker = ExecutorWorker(settings=settings)
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def _request_shutdown(sig_name: str) -> None:
        logger.info(
            "Executor received shutdown signal",
            extra={"event": "shutdown_signal", "signal": sig_name},
        )
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _request_shutdown, sig.name)
        except NotImplementedError:
            pass

    try:
        await worker.run_forever(stop_event)
    finally:
        await worker.shutdown()


def main() -> None:
    """Entrypoint for the isolated remediation executor container."""
    asyncio.run(_run())


if __name__ == "__main__":
    main()
