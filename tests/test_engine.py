
"""Automated tests for MonitoringEngine orchestration, shutdown, and JSON logging."""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

import httpx
import pytest

from remediation.src.health_checker import AsyncHealthChecker
from remediation.src.logging_config import JsonFormatter
from remediation.src.models import ServiceState
from remediation.src.monitor import MonitoringEngine
from remediation.src.monitor_config import MonitorSettings


@pytest.mark.asyncio
async def test_monitoring_engine_run_once_and_graceful_shutdown(
    tmp_path: Path,
) -> None:
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
        return httpx.Response(
            200,
            json={"status": "healthy", "service": "web"},
        )

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler)
    )
    checker = AsyncHealthChecker(
        "web",
        "http://web/health",
        timeout=1.0,
        client=client,
    )
    engine = MonitoringEngine(
        settings=settings,
        health_checker=checker,
    )

    evaluation = await engine.run_once()
    assert evaluation.current_state == ServiceState.HEALTHY
    assert Path(hb_path).exists()

    stop_event = asyncio.Event()
    task = asyncio.create_task(engine.run_forever(stop_event))

    await asyncio.sleep(0.08)
    stop_event.set()

    await asyncio.wait_for(task, timeout=2.0)
    await engine.shutdown()

    # The test supplied this client, so it owns cleanup.
    await client.aclose()


@pytest.mark.asyncio
async def test_shutdown_closes_all_resources_when_coordinator_fails(
    tmp_path: Path,
) -> None:
    settings = MonitorSettings(
        _env_file=None,
        autoheal_db_path=str(tmp_path / "shutdown.db"),
        heartbeat_path=str(tmp_path / "monitor.heartbeat"),
    )

    closed = []

    class FakeCoordinator:
        async def shutdown(self):
            closed.append("coordinator")
            raise RuntimeError("Coordinator shutdown failed")

    class FakeHealthChecker:
        async def close(self):
            closed.append("health_checker")

    class FakeNagiosProber:
        async def close(self):
            closed.append("nagios_prober")

    engine = MonitoringEngine(
        settings=settings,
        health_checker=FakeHealthChecker(),
        remediation_coordinator=FakeCoordinator(),
        nagios_prober=FakeNagiosProber(),
    )

    with pytest.raises(
        RuntimeError,
        match="Coordinator shutdown failed",
    ):
        await engine.shutdown()

    assert closed == [
        "coordinator",
        "health_checker",
        "nagios_prober",
    ]


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


@pytest.mark.asyncio
async def test_monitoring_cycle_unhealthy_target_touches_heartbeat_and_records(
    tmp_path: Path,
) -> None:
    db_path = str(tmp_path / "unhealthy.db")
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
        return httpx.Response(500, json={"status": "error", "error": "Internal Error"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    checker = AsyncHealthChecker("web", "http://web/health", timeout=1.0, client=client)
    engine = MonitoringEngine(settings=settings, health_checker=checker)

    evaluation = await engine.run_once()
    assert evaluation.current_state == ServiceState.UNKNOWN
    assert evaluation.consecutive_failures == 1
    assert Path(hb_path).exists()

    await client.aclose()
    await engine.shutdown()


@pytest.mark.asyncio
async def test_monitoring_cycle_unexpected_exception_touches_heartbeat_and_continues(
    tmp_path: Path,
) -> None:
    db_path = str(tmp_path / "exception.db")
    hb_path = str(tmp_path / "monitor.heartbeat")

    settings = MonitorSettings(
        _env_file=None,
        monitor_enabled=True,
        monitor_interval=0.05,
        autoheal_db_path=db_path,
        heartbeat_path=hb_path,
    )

    call_count = 0

    class FailingChecker:
        async def check(self):
            nonlocal call_count
            call_count += 1
            raise RuntimeError("Transient network or socket failure")

        async def close(self):
            pass

    engine = MonitoringEngine(settings=settings, health_checker=FailingChecker())

    # run_once() must touch heartbeat in finally block even when check() raises
    with pytest.raises(RuntimeError, match="Transient network or socket failure"):
        await engine.run_once()

    assert call_count == 1
    assert Path(hb_path).exists()
    first_mtime = Path(hb_path).stat().st_mtime_ns

    # run_forever() must catch the cycle exception, keep running, and update heartbeat
    stop_event = asyncio.Event()
    task = asyncio.create_task(engine.run_forever(stop_event))

    await asyncio.sleep(0.12)
    stop_event.set()
    await asyncio.wait_for(task, timeout=2.0)

    assert call_count >= 2
    assert Path(hb_path).stat().st_mtime_ns >= first_mtime
    await engine.shutdown()


@pytest.mark.asyncio
async def test_repeated_monitoring_cycle_failures_maintains_liveness(
    tmp_path: Path,
) -> None:
    db_path = str(tmp_path / "repeated_fail.db")
    hb_path = str(tmp_path / "monitor.heartbeat")

    settings = MonitorSettings(
        _env_file=None,
        monitor_enabled=True,
        monitor_interval=0.04,
        autoheal_db_path=db_path,
        heartbeat_path=hb_path,
    )

    failures = 0

    class FlakyChecker:
        async def check(self):
            nonlocal failures
            failures += 1
            raise ConnectionResetError("Connection reset by peer")

        async def close(self):
            pass

    engine = MonitoringEngine(settings=settings, health_checker=FlakyChecker())
    stop_event = asyncio.Event()
    task = asyncio.create_task(engine.run_forever(stop_event))

    await asyncio.sleep(0.15)
    stop_event.set()
    await asyncio.wait_for(task, timeout=2.0)

    assert failures >= 3
    assert Path(hb_path).exists()
    await engine.shutdown()


def test_touch_heartbeat_handles_oserror_gracefully(tmp_path: Path) -> None:
    from unittest.mock import patch

    settings = MonitorSettings(
        _env_file=None,
        autoheal_db_path=str(tmp_path / "hb.db"),
        heartbeat_path=str(tmp_path / "hb"),
    )
    engine = MonitoringEngine(settings=settings)

    with patch.object(Path, "touch", side_effect=OSError("Read-only file system")):
        # Must not raise unhandled exception
        engine.touch_heartbeat()
