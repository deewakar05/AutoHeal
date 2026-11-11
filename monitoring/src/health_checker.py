"""Asynchronous HTTP health checker for AutoHeal target services."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone

import httpx

from .models import CheckOutcome, HealthCheckResult


class AsyncHealthChecker:
    """Probes an HTTP JSON health endpoint and classifies the response."""

    def __init__(
        self,
        service_name: str,
        target_url: str,
        timeout: float = 3.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.service_name = service_name
        self.target_url = target_url
        self.timeout = timeout
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=timeout)

    async def close(self) -> None:
        """Close the underlying HTTP client when owned by this instance."""
        if self._owns_client:
            await self._client.aclose()

    async def check(self) -> HealthCheckResult:
        """Execute one asynchronous health check probe."""
        checked_at = datetime.now(timezone.utc)
        started = time.perf_counter()

        try:
            response = await self._client.get(self.target_url, timeout=self.timeout)
            elapsed_ms = round((time.perf_counter() - started) * 1000.0, 2)
            return self._evaluate_response(response, elapsed_ms, checked_at)
        except httpx.TimeoutException as exc:
            elapsed_ms = round((time.perf_counter() - started) * 1000.0, 2)
            return self._failure_result(
                outcome=CheckOutcome.TIMEOUT,
                status_code=None,
                elapsed_ms=elapsed_ms,
                checked_at=checked_at,
                error=f"Health check timed out after {self.timeout}s: {exc}",
            )
        except httpx.RequestError as exc:
            elapsed_ms = round((time.perf_counter() - started) * 1000.0, 2)
            return self._failure_result(
                outcome=CheckOutcome.CONNECTION_ERROR,
                status_code=None,
                elapsed_ms=elapsed_ms,
                checked_at=checked_at,
                error=f"Connection error probing {self.target_url}: {exc}",
            )
        except Exception as exc:  # noqa: BLE001
            elapsed_ms = round((time.perf_counter() - started) * 1000.0, 2)
            return self._failure_result(
                outcome=CheckOutcome.INVALID_RESPONSE,
                status_code=None,
                elapsed_ms=elapsed_ms,
                checked_at=checked_at,
                error=f"Unexpected health check error: {exc}",
            )

    def _evaluate_response(
        self,
        response: httpx.Response,
        elapsed_ms: float,
        checked_at: datetime,
    ) -> HealthCheckResult:
        """Validate HTTP status code and expected JSON payload."""
        if response.status_code != 200:
            return self._failure_result(
                outcome=CheckOutcome.HTTP_ERROR,
                status_code=response.status_code,
                elapsed_ms=elapsed_ms,
                checked_at=checked_at,
                error=f"HTTP error status {response.status_code}",
            )

        try:
            payload = response.json()
        except (json.JSONDecodeError, ValueError) as exc:
            return self._failure_result(
                outcome=CheckOutcome.INVALID_RESPONSE,
                status_code=response.status_code,
                elapsed_ms=elapsed_ms,
                checked_at=checked_at,
                error=f"Invalid JSON payload: {exc}",
            )

        if not isinstance(payload, dict):
            return self._failure_result(
                outcome=CheckOutcome.INVALID_RESPONSE,
                status_code=response.status_code,
                elapsed_ms=elapsed_ms,
                checked_at=checked_at,
                error="Invalid JSON payload: expected JSON object",
            )

        status_val = payload.get("status")
        service_val = payload.get("service")
        if status_val != "healthy" or service_val != self.service_name:
            return self._failure_result(
                outcome=CheckOutcome.INVALID_RESPONSE,
                status_code=response.status_code,
                elapsed_ms=elapsed_ms,
                checked_at=checked_at,
                error=(
                    f"Unexpected health payload: status={status_val!r}, "
                    f"service={service_val!r} (expected 'healthy' and {self.service_name!r})"
                ),
            )

        return HealthCheckResult(
            service_name=self.service_name,
            target_url=self.target_url,
            healthy=True,
            outcome=CheckOutcome.SUCCESS,
            status_code=response.status_code,
            response_time_ms=elapsed_ms,
            error=None,
            checked_at=checked_at,
        )

    def _failure_result(
        self,
        outcome: CheckOutcome,
        status_code: int | None,
        elapsed_ms: float,
        checked_at: datetime,
        error: str,
    ) -> HealthCheckResult:
        return HealthCheckResult(
            service_name=self.service_name,
            target_url=self.target_url,
            healthy=False,
            outcome=outcome,
            status_code=status_code,
            response_time_ms=elapsed_ms,
            error=error,
            checked_at=checked_at,
        )

