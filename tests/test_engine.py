"""Automated tests for MonitoringEngine orchestration, shutdown, and JSON logging."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

import httpx
import pytest

from monitoring.src.config import MonitorSettings
from monitoring.src.health_checker import AsyncHealthChecker
from monitoring.src.logging_config import JsonFormatter
from monitoring.src.models import ServiceState
from monitoring.src.monitor import MonitoringEngine


@pytest.mark.asyncio
async def test_monitoring_engine_run_once_and_graceful_shutdown(tmp_path: Path) -> None:
    db_path = str(tmp_path / "engine.db")
    hb_path = str(tmp_path / "monitor.heartbeat")

    settings = MonitorSettings(
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

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "healthy", "service": "web"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    checker = AsyncHealthChecker("web", "http://web/health", timeout=1.0, client=client)
    engine = MonitoringEngine(settings=settings, health_checker=checker)

    evaluation = await engine.run_once()
    assert evaluation.current_state == ServiceState.HEALTHY
    assert Path(hb_path).exists()

    stop_event = asyncio.Event()
    task = asyncio.create_task(engine.run_forever(stop_event))
    await asyncio.sleep(0.08)
    stop_event.set()
    await asyncio.wait_for(task, timeout=2.0)
    await engine.shutdown()


def test_json_formatter_outputs_valid_json() -> None:
    formatter = JsonFormatter(component="monitoring-engine")
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="Check complete",
        args=(),
        exc_info=None,
    )
    record.event = "health_check_result"
    record.duration_ms = 5.4

    parsed = json.loads(formatter.format(record))
    assert parsed["component"] == "monitoring-engine"
    assert parsed["event"] == "health_check_result"
    assert parsed["duration_ms"] == 5.4
    assert parsed["message"] == "Check complete"

