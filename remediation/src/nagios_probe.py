"""Asynchronous Nagios Core availability prober using statusjson.cgi."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse

import httpx

from remediation.src.database import (
    ensure_autoheal_database,
    format_utc,
    get_connection,
    utc_now,
)
from remediation.src.repository import sanitize_execution_text

logger = logging.getLogger(__name__)


def _strip_url_credentials(url: str) -> str:
    """Remove any embedded username/password from a URL before persistence or logging."""
    parsed = urlparse(url)
    if parsed.username is None and parsed.password is None:
        return url
    host_port = parsed.hostname or ""
    if parsed.port is not None:
        host_port = f"{host_port}:{parsed.port}"
    return urlunparse(
        (
            parsed.scheme,
            host_port,
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )


@dataclass(frozen=True)
class NagiosProbeResult:
    """Result from a single Nagios Core statusjson.cgi probe."""

    up: bool
    program_running: bool
    http_status: int | None
    response_time_ms: float | None
    error: str | None = None


class NagiosStatusProber:
    """Periodically verifies Nagios Core web UI + daemon health via statusjson.cgi."""

    def __init__(
        self,
        *,
        db_path: str,
        status_url: str,
        timeout: float = 3.0,
        username: str | None = None,
        password: str | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.db_path = db_path
        self.status_url = status_url
        self.display_url = _strip_url_credentials(status_url)
        self.timeout = timeout
        self._auth = (
            httpx.BasicAuth(username, password)
            if username is not None and password is not None
            else None
        )
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=timeout, follow_redirects=False)
        ensure_autoheal_database(db_path)

    async def probe_once(self) -> NagiosProbeResult:
        """Probe Nagios statusjson.cgi and persist status into SQLite."""
        started = time.perf_counter()
        up = False
        program_running = False
        http_status: int | None = None
        error_text: str | None = None

        try:
            response = await self._client.get(
                self.status_url,
                auth=self._auth,
                timeout=self.timeout,
            )
            http_status = response.status_code
            if response.status_code != 200:
                error_text = f"Unexpected HTTP status {response.status_code} from Nagios statusjson.cgi"
            else:
                payload = response.json()
                result_block = payload.get("result") if isinstance(payload, dict) else None
                data_block = payload.get("data") if isinstance(payload, dict) else None
                prog_status = (
                    data_block.get("programstatus") if isinstance(data_block, dict) else None
                )
                result_ok = (
                    isinstance(result_block, dict) and int(result_block.get("type_code", -1)) == 0
                )
                if result_ok and isinstance(prog_status, dict) and prog_status:
                    up = True
                    program_running = True
                else:
                    msg = (
                        str(result_block.get("message"))
                        if isinstance(result_block, dict) and result_block.get("message")
                        else "Invalid Nagios statusjson response payload"
                    )
                    error_text = f"Nagios program status check failed: {msg}"
        except Exception as exc:  # noqa: BLE001
            error_text = f"Nagios status probe error: {exc}"

        elapsed_ms = round((time.perf_counter() - started) * 1000.0, 2)
        sanitized_error = sanitize_execution_text(error_text, max_length=500)
        self._persist_status(
            up=up,
            program_running=program_running,
            http_status=http_status,
            response_time_ms=elapsed_ms,
            last_error=sanitized_error,
        )
        if not up:
            logger.warning(
                "Nagios Core availability check failed",
                extra={
                    "event": "nagios_probe_failed",
                    "http_status": http_status,
                    "response_time_ms": elapsed_ms,
                    "error": sanitized_error,
                },
            )
        return NagiosProbeResult(
            up=up,
            program_running=program_running,
            http_status=http_status,
            response_time_ms=elapsed_ms,
            error=sanitized_error,
        )

    def _persist_status(
        self,
        *,
        up: bool,
        program_running: bool,
        http_status: int | None,
        response_time_ms: float | None,
        last_error: str | None,
    ) -> None:
        now_iso = format_utc(utc_now())
        conn = get_connection(self.db_path, manual_transactions=True)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                INSERT INTO nagios_monitor_status (
                    target_name, target_url, up, http_status, response_time_ms,
                    program_running, last_checked_at, last_error, updated_at
                ) VALUES ('nagios', ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(target_name) DO UPDATE SET
                    target_url = excluded.target_url,
                    up = excluded.up,
                    http_status = excluded.http_status,
                    response_time_ms = excluded.response_time_ms,
                    program_running = excluded.program_running,
                    last_checked_at = excluded.last_checked_at,
                    last_error = excluded.last_error,
                    updated_at = excluded.updated_at
                """,
                (
                    self.display_url,
                    1 if up else 0,
                    http_status,
                    response_time_ms,
                    1 if program_running else 0,
                    now_iso,
                    last_error,
                    now_iso,
                ),
            )
            conn.execute("COMMIT")
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    async def close(self) -> None:
        """Close the HTTP client if owned by this prober."""
        if self._owns_client:
            await self._client.aclose()
