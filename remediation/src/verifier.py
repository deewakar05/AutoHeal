"""Independent post-remediation service recovery verification."""

from __future__ import annotations

import asyncio
import math
import time
from collections.abc import Awaitable, Callable

from .execution_models import VerificationResult
from .health_checker import AsyncHealthChecker
from .models import CheckOutcome, HealthCheckResult


class RecoveryVerifier:
    """Verifies real service recovery independently from Ansible exit status."""

    def __init__(
        self,
        settings: RemediationSettings,
        *,
        probe_factory: Callable[[str], AsyncHealthChecker] | None = None,
        probe_fn: Callable[[], Awaitable[HealthCheckResult]] | None = None,
        sleep_fn: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._settings = settings
        self._probe_factory = probe_factory
        self._probe_fn = probe_fn
        self._sleep_fn = sleep_fn

    async def verify(
        self,
        *,
        service_name: str,
        target_url: str | None = None,
        verify_attempts: int | None = None,
        verify_interval: float | None = None,
        required_successes: int | None = None,
    ) -> VerificationResult:
        """Probe service health independently until required consecutive successes or exhaustion."""
        max_attempts = (
            self._settings.autoheal_remediation_verify_attempts
            if verify_attempts is None
            else verify_attempts
        )
        interval = (
            self._settings.autoheal_remediation_verify_interval
            if verify_interval is None
            else verify_interval
        )
        raw_required = (
            self._settings.autoheal_remediation_verify_required_successes
            if required_successes is None
            else required_successes
        )
        if max_attempts < 1:
            raise ValueError("verify_attempts must be >= 1")
        if not math.isfinite(interval) or interval <= 0:
            raise ValueError("verify_interval must be a finite number > 0")
        if raw_required < 1:
            raise ValueError("required_successes must be >= 1")

        # Never require more consecutive successes than the configured verification budget.
        effective_required = min(raw_required, max_attempts)
        resolved_url = target_url or self._settings.autoheal_remediation_verify_target_url
        started = time.monotonic()

        owns_checker = False
        checker: AsyncHealthChecker | None = None
        if self._probe_fn is not None:
            probe_callable = self._probe_fn
        elif self._probe_factory is not None:
            checker = self._probe_factory(service_name)
            owns_checker = True
            probe_callable = checker.check
        else:
            checker = AsyncHealthChecker(
                service_name=service_name,
                target_url=resolved_url,
                timeout=min(interval, 3.0),
            )
            owns_checker = True
            probe_callable = checker.check

        probe_timeout = max(interval + 1.0, 5.0)
        attempts_made = 0
        consecutive_successes = 0
        last_outcome: str | None = None
        last_error: str | None = None

        try:
            for idx in range(max_attempts):
                if idx > 0:
                    await self._sleep_fn(interval)

                attempts_made += 1
                try:
                    result = await asyncio.wait_for(probe_callable(), timeout=probe_timeout)
                    last_outcome = result.outcome.value
                    last_error = result.error
                    probe_healthy = result.healthy
                except asyncio.TimeoutError:
                    last_outcome = CheckOutcome.TIMEOUT.value
                    last_error = f"Verification probe exceeded {probe_timeout:.2f}s bound"
                    probe_healthy = False

                if probe_healthy:
                    consecutive_successes += 1
                    if consecutive_successes >= effective_required:
                        elapsed = max(round(time.monotonic() - started, 3), 0.0)
                        return VerificationResult(
                            verified=True,
                            attempts_made=attempts_made,
                            consecutive_successes=consecutive_successes,
                            duration_seconds=elapsed,
                            last_outcome=last_outcome,
                            details=(
                                f"Verified healthy for {service_name!r} "
                                f"({consecutive_successes}/{effective_required} consecutive checks "
                                f"within {attempts_made} attempt(s))."
                            ),
                        )
                else:
                    consecutive_successes = 0

                remaining_attempts = max_attempts - attempts_made
                needed_more = effective_required - consecutive_successes
                if remaining_attempts < needed_more:
                    # Impossible to meet required consecutive healthy threshold within budget.
                    break
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            elapsed = max(round(time.monotonic() - started, 3), 0.0)
            return VerificationResult(
                verified=False,
                attempts_made=attempts_made,
                consecutive_successes=consecutive_successes,
                duration_seconds=elapsed,
                last_outcome=last_outcome or "verification_error",
                details=f"Health verification aborted with error: {exc}",
            )
        finally:
            if owns_checker and checker is not None:
                await checker.close()

        elapsed = max(round(time.monotonic() - started, 3), 0.0)
        return VerificationResult(
            verified=False,
            attempts_made=attempts_made,
            consecutive_successes=consecutive_successes,
            duration_seconds=elapsed,
            last_outcome=last_outcome,
            details=(
                f"Recovery verification failed for {service_name!r} after {attempts_made} attempt(s): "
                f"last_outcome={last_outcome}, error={last_error}"
            ),
        )
