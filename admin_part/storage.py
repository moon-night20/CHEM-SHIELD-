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


def audit_detail(**values: Any) -> str:
    return json.dumps(values, ensure_ascii=True, sort_keys=True)
