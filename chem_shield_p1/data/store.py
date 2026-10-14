"""Small stable SQLite store for telemetry and common events."""

import sqlite3
from pathlib import Path


TELEMETRY_COLUMNS = (
    "timestamp", "machine_id", "plc_id", "motor_status", "target_rpm",
    "rpm", "temperature", "pressure", "power",
)


class TelemetryStore:
    def __init__(self, path: str = "chem_shield/data/telemetry.db"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS telemetry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL, machine_id TEXT NOT NULL,
                plc_id TEXT NOT NULL, motor_status TEXT NOT NULL,
                target_rpm REAL NOT NULL, rpm REAL NOT NULL,
                temperature REAL NOT NULL, pressure REAL NOT NULL,
                power REAL NOT NULL
            )""")
            connection.execute("""CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
                source TEXT NOT NULL, machine_id TEXT NOT NULL,
                event_type TEXT NOT NULL, parameter TEXT,
                old_value TEXT, new_value TEXT, severity TEXT NOT NULL
            )""")

    def _connect(self):
        return sqlite3.connect(self.path)

    def add_telemetry(self, record: dict) -> None:
        values = [record[column] for column in TELEMETRY_COLUMNS]
        with self._connect() as connection:
            connection.execute(
                f"INSERT INTO telemetry ({','.join(TELEMETRY_COLUMNS)}) VALUES ({','.join('?' for _ in values)})",
                values,
            )

    def add_event(self, event: dict) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO events (timestamp,source,machine_id,event_type,parameter,old_value,new_value,severity) VALUES (?,?,?,?,?,?,?,?)",
                (event["timestamp"], event["source"], event["machine_id"], event["event_type"],
                 event.get("parameter"), str(event.get("old_value")), str(event.get("new_value")), event["severity"]),
            )

    def recent(self, limit: int = 120) -> list[dict]:
        with self._connect() as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                "SELECT timestamp,motor_status,target_rpm,rpm,temperature,pressure,power FROM telemetry ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in reversed(rows)]

    def recent_events(self, limit: int = 30) -> list[dict]:
        with self._connect() as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                "SELECT timestamp,source,machine_id,event_type,parameter,old_value,new_value,severity "
                "FROM events ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]