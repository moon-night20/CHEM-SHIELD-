"""Hash-chain helpers that mirror, but never rewrite, the Admin audit log."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any

GENESIS_HASH = "0" * 64
AUDIT_COLUMNS = (
    "id",
    "timestamp",
    "username",
    "role",
    "source_ip",
    "action",
    "incident_id",
    "detail",
)


def canonical_json(record: dict[str, Any]) -> str:
    """Serialize an audit record deterministically for hashing."""
    return json.dumps(
        record,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def record_hash(previous_hash: str, record: dict[str, Any]) -> str:
    """Calculate SHA-256 over the previous digest and canonical record."""
    return hashlib.sha256((previous_hash + canonical_json(record)).encode("utf-8")).hexdigest()


def _source_record(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    return {column: row[column] for column in AUDIT_COLUMNS}


def initialize_chain(connection: sqlite3.Connection) -> None:
    """Create the mirror table and chain any legacy audit rows once."""
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS p7_audit_chain (
            chain_order INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_id INTEGER NOT NULL UNIQUE,
            prev_hash TEXT NOT NULL,
            hash TEXT NOT NULL,
            record_json TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS p7_audit_chain_meta (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            initialized INTEGER NOT NULL
        )
        """
    )
    initialized = connection.execute(
        "SELECT initialized FROM p7_audit_chain_meta WHERE id = 1"
    ).fetchone()
    if initialized:
        return
    rows = connection.execute(
        "SELECT id, timestamp, username, role, source_ip, action, incident_id, detail "
        "FROM audit_log ORDER BY id"
    ).fetchall()
    for row in rows:
        append_record(connection, _source_record(row))
    connection.execute(
        "INSERT INTO p7_audit_chain_meta (id, initialized) VALUES (1, 1)"
    )


def append_record(connection: sqlite3.Connection, record: dict[str, Any]) -> None:
    """Append one source audit row to the chain using the caller's transaction."""
    previous = connection.execute(
        "SELECT hash FROM p7_audit_chain ORDER BY chain_order DESC LIMIT 1"
    ).fetchone()
    previous_hash = previous["hash"] if previous else GENESIS_HASH
    normalized = {column: record[column] for column in AUDIT_COLUMNS}
    encoded = canonical_json(normalized)
    digest = hashlib.sha256((previous_hash + encoded).encode("utf-8")).hexdigest()
    connection.execute(
        "INSERT INTO p7_audit_chain (audit_id, prev_hash, hash, record_json) VALUES (?, ?, ?, ?)",
        (normalized["id"], previous_hash, digest, encoded),
    )


def verify_chain(database: str) -> dict[str, Any]:
    """Validate the mirror chain against the existing Admin audit rows."""
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    try:
        tables = {
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "audit_log" not in tables or "p7_audit_chain" not in tables:
            return {
                "ok": False,
                "first_broken_index": 1,
                "record_id": None,
                "reason": "Audit chain has not been initialized.",
            }
        source_rows = connection.execute(
            "SELECT id, timestamp, username, role, source_ip, action, incident_id, detail "
            "FROM audit_log ORDER BY id"
        ).fetchall()
        chain_rows = connection.execute(
            "SELECT chain_order, audit_id, prev_hash, hash, record_json "
            "FROM p7_audit_chain ORDER BY chain_order"
        ).fetchall()
        if len(source_rows) != len(chain_rows):
            return {
                "ok": False,
                "first_broken_index": min(len(source_rows), len(chain_rows)) + 1,
                "record_id": None,
                "reason": "Audit source and hash-chain record counts differ.",
            }

        expected_previous = GENESIS_HASH
        for index, (source, chained) in enumerate(zip(source_rows, chain_rows), start=1):
            source_record = _source_record(source)
            try:
                saved_record = json.loads(chained["record_json"])
            except (TypeError, json.JSONDecodeError):
                saved_record = None
            if chained["audit_id"] != source["id"]:
                reason = "Audit record order or identity changed."
            elif saved_record != source_record:
                reason = "Audit record contents differ from the chained snapshot."
            elif chained["prev_hash"] != expected_previous:
                reason = "Previous-record hash link is invalid."
            elif chained["hash"] != record_hash(expected_previous, source_record):
                reason = "Audit record hash is invalid."
            else:
                expected_previous = chained["hash"]
                continue
            return {
                "ok": False,
                "first_broken_index": index,
                "record_id": source["id"],
                "reason": reason,
            }
        return {"ok": True, "records": len(chain_rows)}
    finally:
        connection.close()
