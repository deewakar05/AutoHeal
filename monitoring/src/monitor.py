"""Asynchronous monitoring loop orchestrating health probes, incidents, metrics, and logs."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from .config import MonitorSettings
from .health_checker import AsyncHealthChecker
from .incident_manager import IncidentManager
from .metrics import MonitorMetrics
from .models import StateEvaluation

logger = logging.getLogger(__name__)


class MonitoringEngine:
    """Coordinates periodic health checks, incident state transitions, and metrics."""

    def __init__(
        self,
        settings: MonitorSettings,
        health_checker: AsyncHealthChecker | None = None,
        incident_manager: IncidentManager | None = None,
        metrics: MonitorMetrics | None = None,
    ) -> None:
        self.settings = settings
        self.health_checker = health_checker or AsyncHealthChecker(
            service_name=settings.monitor_target_service,
            target_url=settings.monitor_target_url,
            timeout=settings.monitor_timeout,
        )
        self.incident_manager = incident_manager or IncidentManager(
            db_path=settings.autoheal_db_path,
            failure_threshold=settings.monitor_failure_threshold,
            recovery_threshold=settings.monitor_recovery_threshold,
        )
        self.metrics = metrics or MonitorMetrics(db_path=settings.autoheal_db_path)

    def touch_heartbeat(self) -> None:
        """Update heartbeat file timestamp for Docker container health checks."""
        heartbeat = Path(self.settings.heartbeat_path)
        heartbeat.parent.mkdir(parents=True, exist_ok=True)
        heartbeat.touch()

    async def run_once(self) -> StateEvaluation:
        """Execute a single monitoring cycle and return the resulting evaluation."""
        result = await self.health_checker.check()
        evaluation = self.incident_manager.process_check(result)
        self.metrics.record(result, evaluation)
        self.touch_heartbeat()
        self._log_evaluation(result, evaluation)
        return evaluation

    async def run_forever(self, stop_event: asyncio.Event) -> None:
        """Run periodic health checks until `stop_event` is set."""
        self.incident_manager.ensure_service_initialized(
            self.settings.monitor_target_service,
            self.settings.monitor_target_url,
        )
        self.touch_heartbeat()

        if not self.settings.monitor_enabled:
            logger.warning(
                "Monitoring is disabled via MONITOR_ENABLED=false; idling gracefully",
                extra={"event": "monitor_disabled"},
            )
            while not stop_event.is_set():
                self.touch_heartbeat()
                await self._wait_or_stop(stop_event, self.settings.monitor_interval)
            return

        logger.info(
            "Starting AutoHeal monitoring loop",
            extra={
                "event": "monitor_started",
                "target_url": self.settings.monitor_target_url,
                "service_name": self.settings.monitor_target_service,
                "interval_seconds": self.settings.monitor_interval,
                "timeout_seconds": self.settings.monitor_timeout,
                "failure_threshold": self.settings.monitor_failure_threshold,
                "recovery_threshold": self.settings.monitor_recovery_threshold,
            },
        )

        while not stop_event.is_set():
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                logger.exception(
                    "Unexpected exception during monitoring cycle",
                    extra={"event": "monitor_cycle_error"},
                )
            await self._wait_or_stop(stop_event, self.settings.monitor_interval)

    async def shutdown(self) -> None:
        """Release HTTP resources cleanly."""
        await self.health_checker.close()
        logger.info("AutoHeal monitoring engine shut down", extra={"event": "monitor_stopped"})

    @staticmethod
    async def _wait_or_stop(stop_event: asyncio.Event, delay: float) -> None:
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=delay)
        except asyncio.TimeoutError:
            return

    def _log_evaluation(self, result, evaluation: StateEvaluation) -> None:
        log_method = logger.info if result.healthy else logger.warning
        log_method(
            "Health check completed",
            extra={
                "event": "health_check_result",
                "service_name": result.service_name,
                "target_url": result.target_url,
                "healthy": result.healthy,
                "check_outcome": result.outcome.value,
                "status_code": result.status_code,
                "duration_ms": result.response_time_ms,
                "error": result.error,
                "service_state": evaluation.current_state.value,
                "consecutive_failures": evaluation.status_record.consecutive_failures,
                "consecutive_successes": evaluation.status_record.consecutive_successes,
            },
        )

        if evaluation.state_changed:
            logger.warning(
                "Service state changed",
                extra={
                    "event": "state_transition",
                    "service_name": result.service_name,
                    "from_state": evaluation.previous_state.value,
                    "to_state": evaluation.current_state.value,
                },
            )

        if evaluation.incident_created is not None:
            logger.error(
                "Incident created",
                extra={
                    "event": "incident_created",
                    "incident_id": evaluation.incident_created.id,
                    "service_name": evaluation.incident_created.service_name,
                    "failure_reason": evaluation.incident_created.failure_reason,
                    "started_at": evaluation.incident_created.started_at.isoformat(),
                },
            )

        if evaluation.incident_resolved is not None:
            logger.info(
                "Incident resolved",
                extra={
                    "event": "incident_resolved",
                    "incident_id": evaluation.incident_resolved.id,
                    "service_name": evaluation.incident_resolved.service_name,
                    "resolved_at": (
                        evaluation.incident_resolved.resolved_at.isoformat()
                        if evaluation.incident_resolved.resolved_at
                        else None
                    ),
                    "failure_count": evaluation.incident_resolved.failure_count,
                },
            )

