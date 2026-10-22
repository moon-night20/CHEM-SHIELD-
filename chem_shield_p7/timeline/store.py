"""SQLite-backed storage for Part 7 runs and ordered timeline events."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    """Return an ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class TimelineStore:
    """Persist scenario metadata and its ordered timeline in a shared SQLite file."""

    def __init__(self, database: str | Path):
        self.database = Path(database)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS p7_runs (
                    run_id TEXT PRIMARY KEY,
                    scenario_id TEXT NOT NULL,
                    scenario_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    ended_at TEXT,
                    detected_at TEXT,
                    responded_at TEXT,
                    automatic_stop INTEGER NOT NULL DEFAULT 0,
                    outcome TEXT NOT NULL DEFAULT '',
                    peak_readings_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS p7_timeline (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL REFERENCES p7_runs(run_id),
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    source TEXT NOT NULL,
                    detector TEXT NOT NULL DEFAULT '',
                    detail_json TEXT NOT NULL,
                    mitre_json TEXT NOT NULL DEFAULT '[]'
                );
                CREATE INDEX IF NOT EXISTS idx_p7_timeline_run
                    ON p7_timeline(run_id, event_id);
                """
            )
            columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(p7_runs)")
            }
            if "peak_readings_json" not in columns:
                connection.execute(
                    "ALTER TABLE p7_runs ADD COLUMN peak_readings_json TEXT NOT NULL DEFAULT '{}'"
                )

    def connect(self) -> sqlite3.Connection:
        """Create a short-lived connection with foreign keys enabled."""
        connection = sqlite3.connect(self.database, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def create_run(
        self,
        run_id: str,
        scenario_id: str,
        scenario_name: str,
        started_at: str | None = None,
    ) -> None:
        """Create a run record before recording its events."""
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO p7_runs (run_id, scenario_id, scenario_name, status, started_at) "
                "VALUES (?, ?, ?, 'RUNNING', ?)",
                (run_id, scenario_id, scenario_name, started_at or utc_now()),
            )

    def append_event(
        self,
        run_id: str,
        event_type: str,
        *,
        source: str,
        detail: dict[str, Any] | None = None,
        detector: str = "",
        mitre: list[dict[str, Any]] | None = None,
        timestamp: str | None = None,
    ) -> dict[str, Any]:
        """Append a JSON-safe timeline event and return its public representation."""
        detail_json = json.dumps(detail or {}, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)
        mitre_json = json.dumps(mitre or [], ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)
        event_time = timestamp or utc_now()
        with self.connect() as connection:
            cursor = connection.execute(
                "INSERT INTO p7_timeline "
                "(run_id, timestamp, event_type, source, detector, detail_json, mitre_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (run_id, event_time, event_type, source, detector, detail_json, mitre_json),
            )
        return {
            "event_id": int(cursor.lastrowid),
            "run_id": run_id,
            "timestamp": event_time,
            "event_type": event_type,
            "source": source,
            "detector": detector,
            "detail": json.loads(detail_json),
            "mitre": json.loads(mitre_json),
        }

    def update_run(self, run_id: str, **fields: Any) -> None:
        """Update only known run lifecycle fields."""
        allowed = {"status", "ended_at", "detected_at", "responded_at", "automatic_stop", "outcome"}
        updates = [(key, value) for key, value in fields.items() if key in allowed]
        if not updates:
            return
        assignments = ", ".join(f"{key} = ?" for key, _ in updates)
        with self.connect() as connection:
            connection.execute(
                f"UPDATE p7_runs SET {assignments} WHERE run_id = ?",
                [value for _, value in updates] + [run_id],
            )

    def record_readings(self, run_id: str, readings: dict[str, Any]) -> None:
        """Keep the observed maximum of each live sensor for this run."""
        import math

        row_keys = {
            "temperature": "temperature",
            "pressure": "pressure",
            "power": "power",
            "speed": "rpm",
        }
        with self.connect() as connection:
            row = connection.execute(
                "SELECT peak_readings_json FROM p7_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if row is None:
                raise ValueError("Scenario run does not exist.")
            peaks = json.loads(row["peak_readings_json"])
            for sensor, source_key in row_keys.items():
                value = readings.get(source_key)
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    continue
                numeric = float(value)
                if math.isfinite(numeric):
                    peaks[sensor] = max(numeric, float(peaks.get(sensor, float("-inf"))))
            encoded = json.dumps(
                peaks,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            connection.execute(
                "UPDATE p7_runs SET peak_readings_json = ? WHERE run_id = ?",
                (encoded, run_id),
            )

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        """Load one run and its timeline in insertion order."""
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM p7_runs WHERE run_id = ?", (run_id,)).fetchone()
            if row is None:
                return None
            events = connection.execute(
                "SELECT * FROM p7_timeline WHERE run_id = ? ORDER BY event_id",
                (run_id,),
            ).fetchall()
        return {
            **dict(row),
            "automatic_stop": bool(row["automatic_stop"]),
            "peak_readings": json.loads(row["peak_readings_json"]),
            "events": [self._event(item) for item in events],
        }

    def latest_run(self) -> dict[str, Any] | None:
        """Load the latest run and timeline."""
        with self.connect() as connection:
            row = connection.execute(
                "SELECT run_id FROM p7_runs ORDER BY started_at DESC LIMIT 1"
            ).fetchone()
        return self.get_run(row["run_id"]) if row else None

    def recent_runs(self, limit: int = 10) -> list[dict[str, Any]]:
        """List recent run summaries without timeline details."""
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT run_id, scenario_id, scenario_name, status, started_at, ended_at, outcome "
                "FROM p7_runs ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _event(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "event_id": row["event_id"],
            "run_id": row["run_id"],
            "timestamp": row["timestamp"],
            "event_type": row["event_type"],
            "source": row["source"],
            "detector": row["detector"],
            "detail": json.loads(row["detail_json"]),
            "mitre": json.loads(row["mitre_json"]),
        }
