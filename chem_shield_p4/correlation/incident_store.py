"""Additive SQLite storage for correlated risk incidents and source events."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, allow_nan=False)


class IncidentStore:
    """Persist risk-specific data without changing existing telemetry tables."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS risk_incidents (
                    incident_id TEXT PRIMARY KEY,
                    asset_id TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    risk_level TEXT NOT NULL DEFAULT 'UNASSESSED',
                    risk_score REAL,
                    risk_assessment_json TEXT,
                    events_json TEXT NOT NULL,
                    acknowledged_at TEXT,
                    acknowledged_by TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_risk_incidents_active_asset
                    ON risk_incidents(status, asset_id, end_time);
                CREATE TABLE IF NOT EXISTS risk_events (
                    event_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL REFERENCES risk_incidents(incident_id),
                    timestamp TEXT NOT NULL,
                    source TEXT,
                    event_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_risk_events_incident
                    ON risk_events(incident_id, timestamp);
                CREATE TABLE IF NOT EXISTS risk_ingest_state (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    last_received_at TEXT,
                    last_accepted_at TEXT,
                    accepted_count INTEGER NOT NULL DEFAULT 0,
                    rejected_count INTEGER NOT NULL DEFAULT 0
                );
                INSERT OR IGNORE INTO risk_ingest_state (id) VALUES (1);
                """
            )
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(risk_ingest_state)")
            }
            if "last_accepted_at" not in columns:
                connection.execute(
                    "ALTER TABLE risk_ingest_state ADD COLUMN last_accepted_at TEXT"
                )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def seen_event_ids(self, event_ids: Iterable[str]) -> set[str]:
        ids = list(event_ids)
        if not ids:
            return set()
        placeholders = ",".join("?" for _ in ids)
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT event_id FROM risk_events WHERE event_id IN ({placeholders})",
                ids,
            ).fetchall()
        return {row["event_id"] for row in rows}

    def matching_active(self, asset_id: str, start: str, end: str, window_seconds: float) -> Optional[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM risk_incidents WHERE status='ACTIVE' AND asset_id=? "
                "ORDER BY updated_at DESC",
                (asset_id,),
            ).fetchall()
        new_start = datetime.fromisoformat(start.replace("Z", "+00:00"))
        new_end = datetime.fromisoformat(end.replace("Z", "+00:00"))
        for row in rows:
            old_start = datetime.fromisoformat(row["start_time"].replace("Z", "+00:00"))
            old_end = datetime.fromisoformat(row["end_time"].replace("Z", "+00:00"))
            if (new_start - old_end).total_seconds() <= window_seconds and (
                old_start - new_end
            ).total_seconds() <= window_seconds:
                return self._incident_row(row)
        return None

    def save_incident(self, incident: Dict[str, Any], events: List[Dict[str, Any]]) -> List[str]:
        now = _utc_now()
        accepted: List[str] = []
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT OR IGNORE INTO risk_incidents (
                    incident_id, asset_id, start_time, end_time, status, risk_level,
                    risk_score, risk_assessment_json, events_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident["incident_id"],
                    incident["asset_id"],
                    incident["start_time"],
                    incident["end_time"],
                    incident["risk_level"],
                    incident.get("risk_score"),
                    _json(incident.get("risk_assessment")),
                    _json(incident["events"]),
                    now,
                    now,
                ),
            )
            for event in events:
                cursor = connection.execute(
                    "INSERT OR IGNORE INTO risk_events "
                    "(event_id, incident_id, timestamp, source, event_json) VALUES (?, ?, ?, ?, ?)",
                    (
                        event["event_id"],
                        incident["incident_id"],
                        event["timestamp"],
                        event.get("source"),
                        _json(event),
                    ),
                )
                if cursor.rowcount:
                    accepted.append(event["event_id"])
            if accepted:
                connection.execute(
                    """
                    UPDATE risk_incidents SET
                        start_time=MIN(start_time, ?),
                        end_time=MAX(end_time, ?),
                        status='ACTIVE',
                        risk_level=?,
                        risk_score=?,
                        risk_assessment_json=?,
                        events_json=?,
                        updated_at=?
                    WHERE incident_id=?
                    """,
                    (
                        incident["start_time"],
                        incident["end_time"],
                        incident["risk_level"],
                        incident.get("risk_score"),
                        _json(incident.get("risk_assessment")),
                        _json(incident["events"]),
                        now,
                        incident["incident_id"],
                    ),
                )
            else:
                connection.execute(
                    "DELETE FROM risk_incidents WHERE incident_id=? AND NOT EXISTS "
                    "(SELECT 1 FROM risk_events WHERE incident_id=?)",
                    (incident["incident_id"], incident["incident_id"]),
                )
            connection.commit()
        return accepted

    def get_incident(self, incident_id: str) -> Optional[dict]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM risk_incidents WHERE incident_id=?", (incident_id,)
            ).fetchone()
        return self._incident_row(row) if row else None

    def list_incidents(self, limit: int = 50, active_only: bool = False) -> List[dict]:
        query = "SELECT * FROM risk_incidents"
        params: list[Any] = []
        if active_only:
            query += " WHERE status='ACTIVE'"
        query += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, params).fetchall()
        return [self._incident_row(row) for row in rows]

    def acknowledge(self, incident_id: str, acknowledged_by: str) -> Optional[dict]:
        with self._connect() as connection:
            connection.execute(
                "UPDATE risk_incidents SET acknowledged_at=COALESCE(acknowledged_at, ?), "
                "acknowledged_by=COALESCE(acknowledged_by, ?), updated_at=? "
                "WHERE incident_id=? AND status='ACTIVE'",
                (_utc_now(), acknowledged_by, _utc_now(), incident_id),
            )
        return self.get_incident(incident_id)

    def ingest_status(self) -> dict:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM risk_ingest_state WHERE id=1").fetchone()
        return dict(row)

    def record_ingest(self, accepted: int, rejected: int = 0) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE risk_ingest_state SET last_received_at=?, "
                "last_accepted_at=CASE WHEN ? > 0 THEN ? ELSE last_accepted_at END, "
                "accepted_count=accepted_count+?, rejected_count=rejected_count+? WHERE id=1",
                (_utc_now(), accepted, _utc_now(), accepted, rejected),
            )

    @staticmethod
    def _incident_row(row: sqlite3.Row) -> dict:
        result = dict(row)
        result["events"] = json.loads(result.pop("events_json"))
        assessment = result.pop("risk_assessment_json")
        result["risk_assessment"] = json.loads(assessment) if assessment else None
        result["acknowledged"] = result["acknowledged_at"] is not None
        return result
