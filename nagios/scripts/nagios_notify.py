#!/usr/bin/env python3
"""Authenticated Nagios Core notification dispatcher sending JSON alerts to AutoHeal API.

Reads `AUTOHEAL_NAGIOS_WEBHOOK_SECRET` from environment or a protected 0600 secret
file (never via command-line arguments and never printed to logs). Builds one
idempotent event_id before retrying transient failures with bounded backoff.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_API_URL = "http://api:8000/api/v1/monitoring/nagios/alerts"
DEFAULT_SECRET_FILE = "/tmp/nagios-secrets/webhook.secret"
DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_MAX_ATTEMPTS = 3

logger = logging.getLogger("nagios-notify")


def load_webhook_secret(secret_file: str | None = None) -> str | None:
    """Load webhook shared secret from environment or protected 0600 file."""
    env_secret = os.environ.get("AUTOHEAL_NAGIOS_WEBHOOK_SECRET", "").strip()
    if env_secret:
        return env_secret

    candidate_path = Path(
        secret_file
        or os.environ.get("AUTOHEAL_NAGIOS_SECRET_FILE", DEFAULT_SECRET_FILE)
    )
    if candidate_path.is_file():
        text = candidate_path.read_text(encoding="utf-8").strip()
        if text:
            return text
    return None


def build_alert_payload(args: argparse.Namespace) -> dict[str, object]:
    """Build deterministic JSON payload matching AutoHeal `NagiosAlertEvent` schema."""
    kind = args.kind.strip().lower()
    notification_type = args.notification_type.strip().upper()
    host_name = args.host_name.strip().lower()
    service_name = args.service_name.strip() if args.service_name else None
    state = args.state.strip().upper()
    state_type = args.state_type.strip().upper()
    attempt = max(1, int(args.attempt))
    max_attempts = max(1, int(args.max_attempts))

    raw_ts = (args.timestamp or "").strip()
    event_timestamp: int | str
    if raw_ts.isdigit() and int(raw_ts) > 0:
        event_timestamp = int(raw_ts)
    elif raw_ts:
        event_timestamp = raw_ts
    else:
        event_timestamp = int(time.time())

    # Prefer active problem ID, falling back to last problem ID for RECOVERY events.
    raw_problem_id = (args.problem_id or "").strip()
    if not raw_problem_id or raw_problem_id == "0":
        raw_problem_id = (args.last_problem_id or "").strip()
    problem_id = raw_problem_id if raw_problem_id and raw_problem_id != "0" else None

    raw_notif_id = (args.notification_id or "").strip()
    notification_id = raw_notif_id if raw_notif_id and raw_notif_id != "0" else None

    raw_notif_num = (args.notification_number or "").strip() or "0"
    svc_slug = (
        "".join(ch if ch.isalnum() else "-" for ch in service_name.lower()).strip("-")[:40]
        if service_name
        else "host"
    )
    event_id = (
        f"nagios-{kind}-{notification_type.lower()}-{svc_slug}-"
        f"{problem_id or '0'}-{notification_id or raw_notif_num}-{event_timestamp}"
    )[:128]

    payload: dict[str, object] = {
        "notification_kind": kind,
        "notification_type": notification_type,
        "host_name": host_name,
        "service_name": service_name if kind == "service" else None,
        "target_service": args.target_service.strip().lower() if args.target_service else None,
        "state": state,
        "state_type": state_type,
        "attempt": attempt,
        "max_attempts": max_attempts,
        "output": (args.output or "").strip()[:2000],
        "event_timestamp": event_timestamp,
        "event_id": event_id,
        "nagios_problem_id": problem_id,
        "nagios_notification_id": notification_id,
    }
    return payload


def send_alert_with_retries(
    *,
    api_url: str,
    secret: str,
    payload: dict[str, object],
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    backoff_base: float = 0.5,
) -> tuple[bool, int | None, str]:
    """POST JSON payload with bounded timeout and retries for transient errors."""
    body = json.dumps(payload).encode("utf-8")
    last_status: int | None = None
    last_detail = ""

    for attempt_idx in range(1, max_attempts + 1):
        req = urllib.request.Request(
            api_url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-Nagios-Token": secret,
                "User-Agent": "autoheal-nagios-notify/1.0",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
                last_status = int(resp.status)
                resp_body = resp.read().decode("utf-8", errors="replace")[:500]
                if 200 <= last_status < 300:
                    return True, last_status, resp_body
                last_detail = f"HTTP {last_status}: {resp_body}"
        except urllib.error.HTTPError as exc:
            last_status = int(exc.code)
            err_body = exc.read().decode("utf-8", errors="replace")[:300]
            last_detail = f"HTTP {last_status}: {err_body}"
            # Do not retry client/auth/validation rejections except 429/408.
            if 400 <= last_status < 500 and last_status not in {408, 429}:
                return False, last_status, last_detail
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_detail = f"Transport error: {exc}"

        if attempt_idx < max_attempts:
            delay = min(backoff_base * (2 ** (attempt_idx - 1)), 2.0)
            time.sleep(delay)

    return False, last_status, last_detail


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Dispatch Nagios alert JSON to AutoHeal API")
    parser.add_argument("--kind", required=True, choices=("host", "service"))
    parser.add_argument("--notification-type", required=True)
    parser.add_argument("--host-name", required=True)
    parser.add_argument("--service-name", default="")
    parser.add_argument("--target-service", default="")
    parser.add_argument("--state", required=True)
    parser.add_argument("--state-type", default="HARD")
    parser.add_argument("--attempt", default="1")
    parser.add_argument("--max-attempts", default="3")
    parser.add_argument("--output", default="")
    parser.add_argument("--timestamp", default="")
    parser.add_argument("--problem-id", default="")
    parser.add_argument("--last-problem-id", default="")
    parser.add_argument("--notification-id", default="")
    parser.add_argument("--notification-number", default="")
    parser.add_argument(
        "--api-url",
        default=os.environ.get("AUTOHEAL_API_NAGIOS_URL", DEFAULT_API_URL),
    )
    parser.add_argument("--secret-file", default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    args = parse_args(argv)
    secret = load_webhook_secret(args.secret_file)
    if not secret:
        logger.error(
            "Nagios webhook secret is missing; aborting notification without sending (fail-closed)."
        )
        return 2

    payload = build_alert_payload(args)
    ok, status_code, detail = send_alert_with_retries(
        api_url=args.api_url,
        secret=secret,
        payload=payload,
    )
    if not ok:
        logger.error(
            "Failed to deliver Nagios notification kind=%s host=%s service=%s type=%s state=%s status=%s detail=%s",
            payload["notification_kind"],
            payload["host_name"],
            payload["service_name"] or "-",
            payload["notification_type"],
            payload["state"],
            status_code,
            detail,
        )
        return 1

    logger.info(
        "Delivered Nagios notification event_id=%s kind=%s host=%s service=%s type=%s state=%s status=%s",
        payload["event_id"],
        payload["notification_kind"],
        payload["host_name"],
        payload["service_name"] or "-",
        payload["notification_type"],
        payload["state"],
        status_code,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
