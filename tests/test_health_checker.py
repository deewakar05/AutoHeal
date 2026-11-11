"""Automated tests for asynchronous HTTP health checks."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from monitoring.src.health_checker import AsyncHealthChecker
from monitoring.src.models import CheckOutcome, HealthCheckResult


async def _run_probe(
    handler: Callable[[httpx.Request], httpx.Response],
    timeout: float = 2.0,
) -> HealthCheckResult:
    """Execute a single health check against a mocked HTTPX transport."""
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        checker = AsyncHealthChecker("web", "http://web/health", timeout=timeout, client=client)
        return await checker.check()


@pytest.mark.asyncio
async def test_health_check_success() -> None:
    result = await _run_probe(
        lambda _request: httpx.Response(200, json={"status": "healthy", "service": "web"})
    )

    assert result.healthy is True
    assert result.outcome == CheckOutcome.SUCCESS
    assert result.status_code == 200
    assert result.error is None
    assert result.response_time_ms >= 0.0


@pytest.mark.asyncio
async def test_health_check_http_error() -> None:
    result = await _run_probe(lambda _request: httpx.Response(503, text="Service Unavailable"))

    assert result.healthy is False
    assert result.outcome == CheckOutcome.HTTP_ERROR
    assert result.status_code == 503
    assert "503" in (result.error or "")


@pytest.mark.asyncio
async def test_health_check_invalid_json_payload() -> None:
    result = await _run_probe(
        lambda _request: httpx.Response(200, json={"status": "degraded", "service": "web"})
    )

    assert result.healthy is False
    assert result.outcome == CheckOutcome.INVALID_RESPONSE
    assert "Unexpected health payload" in (result.error or "")


@pytest.mark.asyncio
async def test_health_check_connection_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused", request=request)

    result = await _run_probe(handler)

    assert result.healthy is False
    assert result.outcome == CheckOutcome.CONNECTION_ERROR
    assert result.status_code is None
    assert "Connection error" in (result.error or "")


@pytest.mark.asyncio
async def test_health_check_timeout() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("Timed out", request=request)

    result = await _run_probe(handler, timeout=1.5)

    assert result.healthy is False
    assert result.outcome == CheckOutcome.TIMEOUT
    assert result.status_code is None
    assert "timed out" in (result.error or "").lower()

