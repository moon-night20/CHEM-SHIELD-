"""SQLite storage for administrative decisions and audit records."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def connect(database: str | Path) -> sqlite3.Connection:
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    return connection


def initialize(database: str | Path) -> None:
    path = Path(database)
    path.parent.mkdir(parents=True, exist_ok=True)
    with connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS incident_status (
                incident_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                updated_by TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                note TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                action TEXT NOT NULL,
                incident_id TEXT,
                detail TEXT NOT NULL
            );
            """
        )


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def add_audit(
    database: str | Path,
    *,
    username: str,
    role: str,
    source_ip: str,
    action: str,
    incident_id: str | None = None,
    detail: str = "",
    timestamp: str | None = None,
) -> None:
    with connect(database) as connection:
        connection.execute(
            """
            INSERT INTO audit_log
                (timestamp, username, role, source_ip, action, incident_id, detail)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (timestamp or utc_now(), username, role, source_ip, action, incident_id, detail),
        )


def get_statuses(database: str | Path) -> dict[str, dict[str, str]]:
    with connect(database) as connection:
        rows = connection.execute(
            "SELECT incident_id, status, updated_by, updated_at, note FROM incident_status"
        ).fetchall()
    return {
        row["incident_id"]: {
            "status": row["status"],
            "updated_by": row["updated_by"],
            "updated_at": row["updated_at"],
            "note": row["note"],
        }
        for row in rows
    }


def set_status(
    database: str | Path,
    *,
    incident_id: str,
    status: str,
    updated_by: str,
    note: str,
) -> None:
    with connect(database) as connection:
        connection.execute(
            """
            INSERT INTO incident_status (incident_id, status, updated_by, updated_at, note)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(incident_id) DO UPDATE SET
                status=excluded.status,
                updated_by=excluded.updated_by,
                updated_at=excluded.updated_at,
                note=excluded.note
            """,
            (incident_id, status, updated_by, utc_now(), note),
        )


def record_incident_action(
    database: str | Path,
    *,
    incident_id: str,
    status: str,
    updated_by: str,
    note: str,
    role: str,
    source_ip: str,
    action: str,
    detail: str,
) -> None:
    timestamp = utc_now()
    with connect(database) as connection:
        connection.execute(
            """
            INSERT INTO incident_status (incident_id, status, updated_by, updated_at, note)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(incident_id) DO UPDATE SET
                status=excluded.status,
                updated_by=excluded.updated_by,
                updated_at=excluded.updated_at,
                note=excluded.note
            """,
            (incident_id, status, updated_by, timestamp, note),
        )
        connection.execute(
            """
            INSERT INTO audit_log
                (timestamp, username, role, source_ip, action, incident_id, detail)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (timestamp, updated_by, role, source_ip, action, incident_id, detail),
        )


def count_recent_failures(
    database: str | Path,
    *,
    username: str,
    source_ip: str,
    since: str,
) -> int:
    with connect(database) as connection:
        row = connection.execute(
            """
            SELECT COUNT(*) AS failure_count FROM audit_log
            WHERE action = ? AND username = ? AND source_ip = ? AND timestamp >= ?
            """,
            ("login_failure", username, source_ip, since),
        ).fetchone()
    return int(row["failure_count"])


def list_audit(
    database: str | Path, *, username: str = "", action: str = "", limit: int = 500
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    values: list[Any] = []
    if username:
        clauses.append("username = ?")
        values.append(username)
    if action:
        clauses.append("action = ?")
        values.append(action)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    values.append(limit)
    with connect(database) as connection:
        rows = connection.execute(
            f"""
            SELECT id, timestamp, username, role, source_ip, action, incident_id, detail
            FROM audit_log {where} ORDER BY id DESC LIMIT ?
            """,
            values,
        ).fetchall()
    return [dict(row) for row in rows]


def list_ot_audit(database: str | Path, limit: int = 250) -> list[dict[str, Any]]:
    """Read persisted OT Console commands and warning events from the shared lab DB."""
    path = Path(database)
    if not path.is_file():
        return []
    entries: list[dict[str, Any]] = []
    with sqlite3.connect(path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        connection.row_factory = sqlite3.Row
        if "ot_console_commands" in tables:
            rows = connection.execute(
                """
                SELECT id,requested_at,parameter,requested_value,unit,status,
                       validation_result,observed_at,observed_value,warning,
                       incident_status
                FROM ot_console_commands
                ORDER BY requested_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
            for row in rows:
                item = dict(row)
                unit = item["unit"] or ""
                summary = (
                    f"{item['parameter'].title()} set to "
                    f"{item['requested_value']} {unit}".strip()
                )
                detail_parts = [f"Status: {item['status']}", item["validation_result"]]
                if item["observed_value"] is not None:
                    summary += f" · Measured {item['observed_value']} {unit}".rstrip()
                if item["warning"]:
                    summary += " · Limit exceeded"
                    detail_parts.append(f"Warning: {item['warning']}")
                if item["incident_status"] != "No incident linked":
                    detail_parts.append(item["incident_status"])
                if item["status"] == "rejected":
                    summary += " · Rejected"
                entries.append({
                    "id": f"ot-command-{item['id']}",
                    "timestamp": item["observed_at"] or item["requested_at"],
                    "username": "OT Command Console",
                    "role": "system",
                    "source_ip": "127.0.0.1",
                    "action": f"ot_command_{item['status']}",
                    "action_label": f"OT command · {item['status']}",
                    "incident_id": None,
                    "summary": summary,
                    "detail": " · ".join(detail_parts),
                })

        if "events" in tables:
            rows = connection.execute(
                """
                SELECT id,timestamp,source,machine_id,event_type,parameter,
                       old_value,new_value,severity
                FROM events
                WHERE UPPER(severity) IN ('MEDIUM','HIGH','CRITICAL')
                ORDER BY timestamp DESC,id DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
            for row in rows:
                item = dict(row)
                unit = item["parameter"] or ""
                value_description = (
                    f"{item['old_value']} → {item['new_value']}"
                    if item["old_value"] is not None or item["new_value"] is not None
                    else ""
                )
                entries.append({
                    "id": f"ot-event-{item['id']}",
                    "timestamp": item["timestamp"],
                    "username": item["source"],
                    "role": "system",
                    "source_ip": "127.0.0.1",
                    "action": f"ot_event_{item['severity'].lower()}",
                    "action_label": f"OT alert · {item['severity'].lower()}",
                    "incident_id": None,
                    "summary": (
                        f"{item['machine_id']} · {item['event_type'].replace('_', ' ').title()}"
                        + (f" · {unit} {value_description}" if value_description else "")
                    ),
                    "detail": (
                        f"Event type: {item['event_type']} · "
                        f"Severity: {item['severity']}"
                    ),
                })
        if "risk_events" in tables:
            rows = connection.execute(
                """
                SELECT event_id,incident_id,timestamp,source,event_json
                FROM risk_events
                ORDER BY timestamp DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
            for row in rows:
                item = dict(row)
                event = json.loads(item["event_json"])
                evidence = event.get("evidence", {})
                if not isinstance(evidence, dict):
                    evidence = {"message": str(evidence or "")}
                asset_id = event.get("asset_id", "Unknown asset")
                sensor = evidence.get("sensor") or evidence.get("rule_id") or "OT event"
                value = evidence.get("value")
                threshold = evidence.get("configured_threshold")
                unit = evidence.get("unit") or ""
                if value is not None and threshold is not None:
                    evidence_summary = (
                        f"{value} {unit} (limit {threshold} {unit})".strip()
                    )
                elif value is not None:
                    evidence_summary = f"{value} {unit}".strip()
                else:
                    evidence_summary = str(
                        evidence.get("message") or event.get("event_type", "event")
                    )
                detail_parts = [
                    f"Source: {item['source'] or 'Risk pipeline'}",
                    f"Event type: {event.get('detection_type', event.get('event_type', 'event'))}",
                    f"Rule: {evidence.get('rule_id') or event.get('event_type', 'event')}",
                ]
                if evidence.get("message"):
                    detail_parts.append(str(evidence["message"]))
                entries.append({
                    "id": f"risk-event-{item['event_id']}",
                    "timestamp": item["timestamp"],
                    "username": item["source"] or "Risk pipeline",
                    "role": "system",
                    "source_ip": "127.0.0.1",
                    "action": f"risk_event_{str(event.get('severity', 'unknown')).lower()}",
                    "action_label": (
                        f"Risk event · {str(event.get('severity', 'unknown')).lower()}"
                    ),
                    "incident_id": item["incident_id"],
                    "summary": f"{asset_id} · {str(sensor).replace('_', ' ').title()} · {evidence_summary}",
                    "detail": " · ".join(detail_parts),
                })
    return sorted(entries, key=lambda item: item["timestamp"], reverse=True)[:limit]


def audit_detail(**values: Any) -> str:
    return json.dumps(values, ensure_ascii=True, sort_keys=True)
