"""Narrow adapter over the existing Part 1 telemetry and events tables."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Dict, Iterable, List

from chem_shield_p1.data.store import TelemetryStore


def read_telemetry_read_only(path: str | Path) -> List[Dict[str, Any]]:
    database = Path(path).resolve()
    if not database.exists():
        raise FileNotFoundError(f"Telemetry database does not exist: {database}")
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            "SELECT timestamp,machine_id,motor_status,rpm,temperature,pressure,power "
            "FROM telemetry ORDER BY id"
        ).fetchall()
    except sqlite3.Error as exc:
        raise RuntimeError(f"Could not read existing telemetry schema in {database}: {exc}") from exc
    finally:
        connection.close()
    return [
        {
            "timestamp": row["timestamp"],
            "asset_id": row["machine_id"],
            "operating_state": row["motor_status"],
            "speed": row["rpm"],
            "rpm": row["rpm"],
            "temperature": row["temperature"],
            "pressure": row["pressure"],
            "power": row["power"],
            "measurement_origin": "simulated_part1",
        }
        for row in rows
    ]


def read_telemetry_since(path: str | Path, after_id: int) -> List[Dict[str, Any]]:
    """Read newly appended Part 1 telemetry without opening SQLite for writes."""
    database = Path(path).resolve()
    if not database.exists():
        raise FileNotFoundError(f"Telemetry database does not exist: {database}")
    if isinstance(after_id, bool) or not isinstance(after_id, int) or after_id < 0:
        raise ValueError("after_id must be a non-negative integer")
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            "SELECT id,timestamp,machine_id,motor_status,rpm,temperature,pressure,power "
            "FROM telemetry WHERE id > ? ORDER BY id",
            (after_id,),
        ).fetchall()
    except sqlite3.Error as exc:
        raise RuntimeError(
            f"Could not read existing telemetry schema in {database}: {exc}"
        ) from exc
    finally:
        connection.close()
    return [
        {
            "id": row["id"],
            "timestamp": row["timestamp"],
            "asset_id": row["machine_id"],
            "operating_state": row["motor_status"],
            "speed": row["rpm"],
            "rpm": row["rpm"],
            "temperature": row["temperature"],
            "pressure": row["pressure"],
            "power": row["power"],
            "measurement_origin": "simulated_part1",
        }
        for row in rows
    ]


def persist_ot_events(path: str | Path, events: Iterable[Dict[str, Any]]) -> int:
    """Write alerts through TelemetryStore.add_event without altering its schema."""
    store = TelemetryStore(str(path))
    existing = store.recent_events(limit=10000)
    known = {
        (
            item["timestamp"], item["source"], item["machine_id"], item["event_type"],
            item.get("parameter"), item.get("old_value"), item.get("new_value"), item["severity"],
        )
        for item in existing
    }
    inserted = 0
    for event in events:
        evidence = event.get("evidence") or {}
        sensor = evidence.get("sensor")
        store_event = {
            "timestamp": event["timestamp"],
            "source": "ot_monitor",
            "machine_id": event["asset_id"],
            "event_type": event["event_type"].upper(),
            "parameter": event.get("rule_id") or sensor or event["event_type"],
            "old_value": evidence.get("configured_threshold"),
            "new_value": evidence.get("value"),
            "severity": event["severity"],
        }
        key = (
            store_event["timestamp"], store_event["source"], store_event["machine_id"],
            store_event["event_type"], store_event["parameter"],
            str(store_event["old_value"]), str(store_event["new_value"]), store_event["severity"],
        )
        if key in known:
            continue
        store.add_event(store_event)
        known.add(key)
        inserted += 1
    return inserted
