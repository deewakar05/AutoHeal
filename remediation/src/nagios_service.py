"""Atomic SQLite-backed Nagios Core alert ingestion, deduplication, and remediation triggering."""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime

from .config import RemediationSettings, get_settings as get_remediation_settings
from .database import (
    ensure_autoheal_database,
    ensure_utc,
    format_utc,
    get_connection,
    increment_sql_counter,
    parse_optional_dt,
    record_incident_event_in_tx,
    utc_now,
)
from .models import RemediationRequest, RemediationStatus
from .nagios_models import (
    CRITICAL_STATES,
    RECOVERY_STATES,
    NagiosAlertEvent,
    NagiosAlertOutcome,
    NagiosProcessingOutcome,
    parse_nagios_service_map,
    resolve_mapped_service,
)
from .repository import RemediationRepository, sanitize_execution_text

logger = logging.getLogger(__name__)

_NAGIOS_METRIC_NAME = "autoheal_nagios_alerts_total"
_FLAPPING_TYPES = frozenset({"FLAPPINGSTART", "FLAPPINGSTOP", "FLAPPINGDISABLED"})
_IGNORED_TYPES = frozenset(
    {
        "ACKNOWLEDGEMENT",
        "DOWNTIMESTART",
        "DOWNTIMEEND",
        "DOWNTIMECANCELLED",
        "CUSTOM",
    }
)


def _record_nagios_counter_in_tx(
    conn: sqlite3.Connection,
    *,
    kind: str,
    notification_type: str,
    state: str,
    outcome: str,
) -> None:
    labels_json = json.dumps(
        {
            "kind": kind,
            "notification_type": notification_type,
            "outcome": outcome,
            "state": state,
        },
        sort_keys=True,
    )
    increment_sql_counter(conn, "nagios_counters", _NAGIOS_METRIC_NAME, labels_json)


def record_nagios_http_rejection(
    db_path: str,
    *,
    outcome: str,
    kind: str = "unknown",
    notification_type: str = "unknown",
    state: str = "unknown",
) -> None:
    """Persist bounded HTTP auth/ingestion error counters safely into SQLite."""
    ensure_autoheal_database(db_path)
    conn = get_connection(db_path, manual_transactions=True)
    try:
        conn.execute("BEGIN IMMEDIATE")
        _record_nagios_counter_in_tx(
            conn,
            kind=kind,
            notification_type=notification_type,
            state=state,
            outcome=outcome,
        )
        conn.execute("COMMIT")
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def _is_stale_recovery(
    event_ts: datetime,
    started_at_raw: str | None,
    last_problem_at_raw: str | None,
) -> bool:
    """Return True when a recovery event predates the active incident problem window."""
    cutoffs = [
        dt
        for dt in (parse_optional_dt(started_at_raw), parse_optional_dt(last_problem_at_raw))
        if dt is not None
    ]
    if not cutoffs:
        return False

    latest_cutoff = max(cutoffs)
    # Nagios $TIMET$ macros have 1-second integer precision while internal checks use microseconds.
    same_integer_second = (
        event_ts.microsecond == 0
        and int(event_ts.timestamp()) == int(latest_cutoff.timestamp())
    )
    return event_ts < latest_cutoff and not same_integer_second


def _insert_nagios_event(
    conn: sqlite3.Connection,
    event: NagiosAlertEvent,
    *,
    dedup_key: str,
    mapped_service: str,
    incident_id: int | None,
    event_ts_iso: str,
    received_iso: str,
    processing_status: str,
) -> None:
    conn.execute(
        """
        INSERT INTO nagios_events (
            dedup_key, incident_id, notification_kind, notification_type,
            host_name, nagios_service_name, mapped_service, state, state_type,
            attempt, output, nagios_problem_id, nagios_notification_id,
            event_timestamp, received_at, processing_status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            dedup_key,
            incident_id,
            event.notification_kind or "host",
            event.notification_type,
            event.host_name,
            event.service_name,
            mapped_service,
            event.state,
            event.state_type,
            event.attempt,
            event.output,
            event.nagios_problem_id,
            event.nagios_notification_id,
            event_ts_iso,
            received_iso,
            processing_status,
        ),
    )


class NagiosAlertService:
    """Validates, deduplicates, correlates, and persists Nagios alerts in SQLite."""

    def __init__(
        self,
        remediation_settings: RemediationSettings | None = None,
        *,
        db_path: str | None = None,
        service_map: str | dict[str, str] | None = None,
        repository: RemediationRepository | None = None,
    ) -> None:
        settings = remediation_settings or get_remediation_settings()
        if db_path and db_path != settings.autoheal_db_path:
            settings = settings.model_copy(update={"autoheal_db_path": db_path})
        self._settings = settings
        self.db_path = settings.autoheal_db_path
        ensure_autoheal_database(self.db_path)
        self._service_map = parse_nagios_service_map(service_map)
        self._repository = repository or RemediationRepository(self.db_path)

    def process_alert(
        self,
        event: NagiosAlertEvent,
        *,
        now: datetime | None = None,
    ) -> NagiosAlertOutcome:
        """Atomically process one Nagios alert and evaluate automated remediation safely."""
        mapped_service = resolve_mapped_service(event, self._service_map)
        dedup_key = event.compute_dedup_key()
        event_ts = ensure_utc(event.event_timestamp)
        received_at = ensure_utc(now or utc_now())
        event_ts_iso = format_utc(event_ts)
        received_iso = format_utc(received_at)
        kind = event.notification_kind or "host"

        conn = get_connection(self.db_path, manual_transactions=True)
        try:
            conn.execute("BEGIN IMMEDIATE")

            existing = conn.execute(
                "SELECT incident_id, mapped_service, processing_status FROM nagios_events WHERE dedup_key = ?",
                (dedup_key,),
            ).fetchone()
            if existing is not None:
                _record_nagios_counter_in_tx(
                    conn,
                    kind=kind,
                    notification_type=event.notification_type,
                    state=event.state,
                    outcome=NagiosProcessingOutcome.DUPLICATE.value,
                )
                conn.execute("COMMIT")
                logger.info(
                    "Duplicate Nagios alert ignored",
                    extra={
                        "event": "nagios_alert_duplicate",
                        "dedup_key": dedup_key,
                        "mapped_service": str(existing["mapped_service"]),
                        "incident_id": existing["incident_id"],
                    },
                )
                return NagiosAlertOutcome(
                    accepted=True,
                    duplicate=True,
                    outcome=NagiosProcessingOutcome.DUPLICATE,
                    dedup_key=dedup_key,
                    mapped_service=str(existing["mapped_service"]),
                    incident_id=existing["incident_id"],
                    details=(
                        f"Duplicate Nagios event ignored "
                        f"(prior processing_status={existing['processing_status']})."
                    ),
                )

            open_row = conn.execute(
                "SELECT * FROM incidents WHERE service_name = ? AND status = 'open' ORDER BY id DESC LIMIT 1",
                (mapped_service,),
            ).fetchone()

            # 1. Ignore transient SOFT states without creating/resolving incidents or triggering Ansible.
            if event.state_type == "SOFT":
                outcome = NagiosProcessingOutcome.IGNORED_SOFT_STATE
                _insert_nagios_event(
                    conn,
                    event,
                    dedup_key=dedup_key,
                    mapped_service=mapped_service,
                    incident_id=None,
                    event_ts_iso=event_ts_iso,
                    received_iso=received_iso,
                    processing_status=outcome.value,
                )
                _record_nagios_counter_in_tx(
                    conn,
                    kind=kind,
                    notification_type=event.notification_type,
                    state=event.state,
                    outcome=outcome.value,
                )
                conn.execute("COMMIT")
                return NagiosAlertOutcome(
                    outcome=outcome,
                    dedup_key=dedup_key,
                    mapped_service=mapped_service,
                    details="Transient SOFT state alert recorded and ignored for remediation.",
                )

            # 2. Flapping notifications mark or clear the flapping guard on active incidents.
            if event.notification_type in _FLAPPING_TYPES:
                is_flapping = event.notification_type == "FLAPPINGSTART"
                outcome = (
                    NagiosProcessingOutcome.FLAPPING_MARKED
                    if is_flapping
                    else NagiosProcessingOutcome.FLAPPING_CLEARED
                )
                incident_id = int(open_row["id"]) if open_row is not None else None
                if incident_id is not None:
                    conn.execute(
                        """
                        UPDATE incidents
                        SET flapping = ?,
                            last_seen_at = ?,
                            source = CASE
                                WHEN source = 'internal_monitor' THEN 'internal_monitor+nagios'
                                ELSE source
                            END
                        WHERE id = ?
                        """,
                        (1 if is_flapping else 0, received_iso, incident_id),
                    )
                _insert_nagios_event(
                    conn,
                    event,
                    dedup_key=dedup_key,
                    mapped_service=mapped_service,
                    incident_id=incident_id,
                    event_ts_iso=event_ts_iso,
                    received_iso=received_iso,
                    processing_status=outcome.value,
                )
                _record_nagios_counter_in_tx(
                    conn,
                    kind=kind,
                    notification_type=event.notification_type,
                    state=event.state,
                    outcome=outcome.value,
                )
                conn.execute("COMMIT")
                return NagiosAlertOutcome(
                    outcome=outcome,
                    dedup_key=dedup_key,
                    mapped_service=mapped_service,
                    incident_id=incident_id,
                    details=f"Nagios flapping state updated ({event.notification_type}).",
                )

            # 3. Recovery handling.
            if event.notification_type == "RECOVERY" or event.state in RECOVERY_STATES:
                result = self._handle_recovery_in_tx(
                    conn,
                    event,
                    open_row=open_row,
                    dedup_key=dedup_key,
                    mapped_service=mapped_service,
                    event_ts=event_ts,
                    event_ts_iso=event_ts_iso,
                    received_iso=received_iso,
                    kind=kind,
                )
                conn.execute("COMMIT")
                return result

            # 4. Non-critical PROBLEM states (WARNING/UNKNOWN) or admin notifications (ACK/DOWNTIME/CUSTOM).
            is_critical_problem = (
                event.notification_type == "PROBLEM"
                and event.state in CRITICAL_STATES
                and event.state_type == "HARD"
            )
            if event.notification_type in _IGNORED_TYPES or not is_critical_problem:
                outcome = NagiosProcessingOutcome.IGNORED_NON_CRITICAL
                linked_id = int(open_row["id"]) if open_row is not None else None
                _insert_nagios_event(
                    conn,
                    event,
                    dedup_key=dedup_key,
                    mapped_service=mapped_service,
                    incident_id=linked_id,
                    event_ts_iso=event_ts_iso,
                    received_iso=received_iso,
                    processing_status=outcome.value,
                )
                _record_nagios_counter_in_tx(
                    conn,
                    kind=kind,
                    notification_type=event.notification_type,
                    state=event.state,
                    outcome=outcome.value,
                )
                conn.execute("COMMIT")
                return NagiosAlertOutcome(
                    outcome=outcome,
                    dedup_key=dedup_key,
                    mapped_service=mapped_service,
                    incident_id=linked_id,
                    details=f"Non-critical Nagios notification ({event.notification_type}/{event.state}) recorded without remediation.",
                )

            # 5. Critical HARD PROBLEM: create or merge open incident before policy reservation.
            detail_text = event.output or f"{event.service_name or event.host_name} ({event.state})"
            failure_reason = (
                sanitize_execution_text(f"Nagios {event.state}: {detail_text}", max_length=1000)
                or f"Nagios {event.state}"
            )
            if open_row is None:
                cursor = conn.execute(
                    """
                    INSERT INTO incidents (
                        service_name, status, failure_reason, started_at, resolved_at,
                        last_seen_at, failure_count, source, host_name, nagios_service_name,
                        nagios_state, last_problem_at, nagios_alert_count, flapping
                    ) VALUES (?, 'open', ?, ?, NULL, ?, ?, 'nagios', ?, ?, ?, ?, 1, ?)
                    """,
                    (
                        mapped_service,
                        failure_reason,
                        event_ts_iso,
                        received_iso,
                        max(1, event.attempt),
                        event.host_name,
                        event.service_name,
                        event.state,
                        event_ts_iso,
                        1 if event.flapping else 0,
                    ),
                )
                incident_id = int(cursor.lastrowid)
                conn.execute(
                    """
                    UPDATE service_status
                    SET status = 'unhealthy',
                        last_status_change_at = ?,
                        last_error = ?,
                        active_incident_id = ?,
                        updated_at = ?
                    WHERE service_name = ?
                    """,
                    (received_iso, failure_reason, incident_id, received_iso, mapped_service),
                )
                record_incident_event_in_tx(conn, mapped_service, "created")
                initial_outcome = NagiosProcessingOutcome.INCIDENT_CREATED
                incident_created = True
                is_flapping = bool(event.flapping)
            else:
                incident_id = int(open_row["id"])
                existing_problem_dt = parse_optional_dt(open_row["last_problem_at"])
                next_problem_iso = (
                    format_utc(max(existing_problem_dt, event_ts))
                    if existing_problem_dt is not None
                    else event_ts_iso
                )
                conn.execute(
                    """
                    UPDATE incidents
                    SET failure_reason = ?,
                        last_seen_at = ?,
                        last_problem_at = ?,
                        failure_count = failure_count + 1,
                        nagios_alert_count = nagios_alert_count + 1,
                        host_name = ?,
                        nagios_service_name = COALESCE(?, nagios_service_name),
                        nagios_state = ?,
                        flapping = CASE WHEN ? = 1 THEN 1 ELSE flapping END,
                        source = CASE
                            WHEN source = 'internal_monitor' THEN 'internal_monitor+nagios'
                            ELSE source
                        END
                    WHERE id = ?
                    """,
                    (
                        failure_reason,
                        received_iso,
                        next_problem_iso,
                        event.host_name,
                        event.service_name,
                        event.state,
                        1 if event.flapping else 0,
                        incident_id,
                    ),
                )
                initial_outcome = NagiosProcessingOutcome.INCIDENT_UPDATED
                incident_created = False
                is_flapping = bool(open_row["flapping"]) or bool(event.flapping)

            # Keep the event, incident, policy decision, execution reservation,
            # and final event status in ONE transaction. A process crash can no
            # longer leave a deduplicated problem event without its queue slot.
            _insert_nagios_event(
                conn,
                event,
                dedup_key=dedup_key,
                mapped_service=mapped_service,
                incident_id=incident_id,
                event_ts_iso=event_ts_iso,
                received_iso=received_iso,
                processing_status=initial_outcome.value,
            )
            final_outcome = initial_outcome
            remediation_queued = False
            execution_id: int | None = None
            dry_run_val: bool | None = self._settings.autoheal_remediation_dry_run
            policy_reason: str | None = None
            policy_details = ""

            if is_flapping:
                policy_reason = "FLAPPING_ACTIVE"
                policy_details = "Automated remediation suppressed while flapping flag is active."
            elif self._settings.autoheal_remediation_dispatch_mode == "disabled":
                policy_reason = "DISPATCH_DISABLED"
                policy_details = "Remediation dispatch mode is set to 'disabled'."
            else:
                reservation = self._repository.reserve_execution_in_tx(
                    conn,
                    RemediationRequest(
                        incident_id=incident_id,
                        service_name=mapped_service,
                        action="restart",
                    ),
                    self._settings,
                    initial_status=RemediationStatus.PENDING,
                    stale_after_seconds=self._settings.autoheal_remediation_stale_timeout_seconds,
                )
                policy_reason = reservation.decision.reason.value
                policy_details = reservation.decision.details
                dry_run_val = reservation.decision.dry_run
                if reservation.reserved and reservation.execution is not None:
                    remediation_queued = True
                    execution_id = reservation.execution.id
                    final_outcome = NagiosProcessingOutcome.REMEDIATION_QUEUED

            if final_outcome != initial_outcome:
                conn.execute(
                    "UPDATE nagios_events SET processing_status = ? WHERE dedup_key = ?",
                    (final_outcome.value, dedup_key),
                )
            _record_nagios_counter_in_tx(
                conn,
                kind=kind,
                notification_type=event.notification_type,
                state=event.state,
                outcome=final_outcome.value,
            )
            conn.execute("COMMIT")
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

        logger.info(
            "Processed critical Nagios alert",
            extra={
                "event": "nagios_alert_processed",
                "dedup_key": dedup_key,
                "mapped_service": mapped_service,
                "incident_id": incident_id,
                "outcome": final_outcome.value,
                "execution_id": execution_id,
                "policy_reason": policy_reason,
            },
        )
        return NagiosAlertOutcome(
            outcome=final_outcome,
            dedup_key=dedup_key,
            mapped_service=mapped_service,
            incident_id=incident_id,
            incident_created=incident_created,
            remediation_queued=remediation_queued,
            execution_id=execution_id,
            dry_run=dry_run_val,
            policy_reason=policy_reason,
            details=policy_details or f"Nagios {event.state} processed ({final_outcome.value}).",
        )

    def _handle_recovery_in_tx(
        self,
        conn: sqlite3.Connection,
        event: NagiosAlertEvent,
        *,
        open_row: sqlite3.Row | None,
        dedup_key: str,
        mapped_service: str,
        event_ts: datetime,
        event_ts_iso: str,
        received_iso: str,
        kind: str,
    ) -> NagiosAlertOutcome:
        if open_row is None:
            outcome = NagiosProcessingOutcome.IGNORED_NO_OPEN_INCIDENT
            _insert_nagios_event(
                conn,
                event,
                dedup_key=dedup_key,
                mapped_service=mapped_service,
                incident_id=None,
                event_ts_iso=event_ts_iso,
                received_iso=received_iso,
                processing_status=outcome.value,
            )
            _record_nagios_counter_in_tx(
                conn,
                kind=kind,
                notification_type=event.notification_type,
                state=event.state,
                outcome=outcome.value,
            )
            return NagiosAlertOutcome(
                outcome=outcome,
                dedup_key=dedup_key,
                mapped_service=mapped_service,
                details="Nagios recovery ignored because no open incident exists.",
            )

        open_id = int(open_row["id"])
        if _is_stale_recovery(event_ts, open_row["started_at"], open_row["last_problem_at"]):
            outcome = NagiosProcessingOutcome.IGNORED_STALE_RECOVERY
            _insert_nagios_event(
                conn,
                event,
                dedup_key=dedup_key,
                mapped_service=mapped_service,
                incident_id=open_id,
                event_ts_iso=event_ts_iso,
                received_iso=received_iso,
                processing_status=outcome.value,
            )
            _record_nagios_counter_in_tx(
                conn,
                kind=kind,
                notification_type=event.notification_type,
                state=event.state,
                outcome=outcome.value,
            )
            return NagiosAlertOutcome(
                outcome=outcome,
                dedup_key=dedup_key,
                mapped_service=mapped_service,
                incident_id=open_id,
                details="Stale Nagios recovery timestamp predates active problem; incident kept open.",
            )

        active_row = conn.execute(
            """
            SELECT id, status FROM remediation_executions
            WHERE incident_id = ? AND status IN ('pending', 'running')
            ORDER BY id DESC LIMIT 1
            """,
            (open_id,),
        ).fetchone()
        if active_row is not None:
            outcome = NagiosProcessingOutcome.DEFERRED_ACTIVE_REMEDIATION
            conn.execute(
                """
                UPDATE incidents
                SET last_seen_at = ?,
                    nagios_state = ?,
                    nagios_alert_count = nagios_alert_count + 1,
                    source = CASE
                        WHEN source = 'internal_monitor' THEN 'internal_monitor+nagios'
                        ELSE source
                    END
                WHERE id = ?
                """,
                (received_iso, event.state, open_id),
            )
            _insert_nagios_event(
                conn,
                event,
                dedup_key=dedup_key,
                mapped_service=mapped_service,
                incident_id=open_id,
                event_ts_iso=event_ts_iso,
                received_iso=received_iso,
                processing_status=outcome.value,
            )
            _record_nagios_counter_in_tx(
                conn,
                kind=kind,
                notification_type=event.notification_type,
                state=event.state,
                outcome=outcome.value,
            )
            return NagiosAlertOutcome(
                outcome=outcome,
                dedup_key=dedup_key,
                mapped_service=mapped_service,
                incident_id=open_id,
                execution_id=int(active_row["id"]),
                details=(
                    f"Active remediation execution is {str(active_row['status']).upper()}; "
                    "deferring incident resolution until the execution lifecycle and "
                    "RecoveryVerifier complete."
                ),
            )

        started_dt = parse_optional_dt(open_row["started_at"])
        resolved_ts = max(event_ts, started_dt) if started_dt is not None else event_ts
        resolved_iso = format_utc(resolved_ts)

        conn.execute(
            """
            UPDATE incidents
            SET status = 'resolved',
                resolved_at = ?,
                last_seen_at = ?,
                nagios_state = ?,
                nagios_alert_count = nagios_alert_count + 1,
                flapping = 0,
                source = CASE
                    WHEN source = 'internal_monitor' THEN 'internal_monitor+nagios'
                    ELSE source
                END
            WHERE id = ? AND status = 'open'
            """,
            (resolved_iso, received_iso, event.state, open_id),
        )
        conn.execute(
            """
            UPDATE service_status
            SET status = 'healthy',
                consecutive_failures = 0,
                last_checked_at = ?,
                last_status_change_at = ?,
                last_error = NULL,
                active_incident_id = NULL,
                updated_at = ?
            WHERE service_name = ? AND (active_incident_id = ? OR status = 'unhealthy')
            """,
            (received_iso, received_iso, received_iso, mapped_service, open_id),
        )
        record_incident_event_in_tx(conn, mapped_service, "resolved")

        outcome = NagiosProcessingOutcome.INCIDENT_RESOLVED
        _insert_nagios_event(
            conn,
            event,
            dedup_key=dedup_key,
            mapped_service=mapped_service,
            incident_id=open_id,
            event_ts_iso=event_ts_iso,
            received_iso=received_iso,
            processing_status=outcome.value,
        )
        _record_nagios_counter_in_tx(
            conn,
            kind=kind,
            notification_type=event.notification_type,
            state=event.state,
            outcome=outcome.value,
        )
        return NagiosAlertOutcome(
            outcome=outcome,
            dedup_key=dedup_key,
            mapped_service=mapped_service,
            incident_id=open_id,
            incident_resolved=True,
            details="Open incident resolved following verified Nagios RECOVERY notification.",
        )

    def list_events(
        self,
        *,
        limit: int = 50,
        service_name: str | None = None,
        outcome: str | None = None,
    ) -> list[dict[str, object]]:
        """Query recent persisted Nagios notification events newest first."""
        conn = get_connection(self.db_path)
        try:
            clauses: list[str] = []
            params: list[object] = []
            if service_name is not None:
                clauses.append("mapped_service = ?")
                params.append(service_name.strip().lower())
            if outcome is not None:
                clauses.append("processing_status = ?")
                params.append(outcome.strip().lower())
            where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            params.append(max(1, min(int(limit), 200)))
            rows = conn.execute(
                f"""
                SELECT * FROM nagios_events
                {where_sql}
                ORDER BY id DESC
                LIMIT ?
                """,
                tuple(params),
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def get_status_summary(self) -> dict[str, object]:
        """Return Nagios monitor health row and recent event summary counters."""
        conn = get_connection(self.db_path)
        try:
            monitor_row = conn.execute(
                "SELECT * FROM nagios_monitor_status WHERE target_name = 'nagios'"
            ).fetchone()
            total_events_row = conn.execute(
                "SELECT COUNT(*) AS total FROM nagios_events"
            ).fetchone()
            recent_outcomes = conn.execute(
                """
                SELECT processing_status, COUNT(*) AS count
                FROM nagios_events
                GROUP BY processing_status
                """
            ).fetchall()
            open_by_source = conn.execute(
                """
                SELECT source, COUNT(*) AS count
                FROM incidents
                WHERE status = 'open'
                GROUP BY source
                """
            ).fetchall()
            return {
                "monitor_status": dict(monitor_row) if monitor_row is not None else None,
                "total_events": int(total_events_row["total"]) if total_events_row else 0,
                "events_by_outcome": {
                    str(r["processing_status"]): int(r["count"]) for r in recent_outcomes
                },
                "open_incidents_by_source": {
                    str(r["source"]): int(r["count"]) for r in open_by_source
                },
            }
        finally:
            conn.close()
