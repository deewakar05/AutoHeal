"""Automated tests for asynchronous HTTP health checks."""

from __future__ import annotations

import httpx
import pytest

from monitoring.src.health_checker import AsyncHealthChecker
from monitoring.src.models import CheckOutcome


@pytest.mark.asyncio
async def test_health_check_success() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "healthy", "service": "web"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    checker = AsyncHealthChecker("web", "http://web/health", timeout=2.0, client=client)

    result = await checker.check()
    await client.aclose()

    assert result.healthy is True
    assert result.outcome == CheckOutcome.SUCCESS
    assert result.status_code == 200
    assert result.error is None
    assert result.response_time_ms >= 0.0


@pytest.mark.asyncio
async def test_health_check_http_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="Service Unavailable")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    checker = AsyncHealthChecker("web", "http://web/health", timeout=2.0, client=client)

    result = await checker.check()
    await client.aclose()

    assert result.healthy is False
    assert result.outcome == CheckOutcome.HTTP_ERROR
    assert result.status_code == 503
    assert "503" in (result.error or "")


@pytest.mark.asyncio
async def test_health_check_invalid_json_payload() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "degraded", "service": "web"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    checker = AsyncHealthChecker("web", "http://web/health", timeout=2.0, client=client)

    result = await checker.check()
    await client.aclose()

    assert result.healthy is False
    assert result.outcome == CheckOutcome.INVALID_RESPONSE
    assert "Unexpected health payload" in (result.error or "")


@pytest.mark.asyncio
async def test_health_check_connection_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused", request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    checker = AsyncHealthChecker("web", "http://web/health", timeout=2.0, client=client)

    result = await checker.check()
    await client.aclose()

    assert result.healthy is False
    assert result.outcome == CheckOutcome.CONNECTION_ERROR
    assert result.status_code is None
    assert "Connection error" in (result.error or "")


@pytest.mark.asyncio
async def test_health_check_timeout() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("Timed out", request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    checker = AsyncHealthChecker("web", "http://web/health", timeout=1.5, client=client)

    result = await checker.check()
    await client.aclose()

    assert result.healthy is False
    assert result.outcome == CheckOutcome.TIMEOUT
    assert result.status_code is None
    assert "timed out" in (result.error or "").lower()

