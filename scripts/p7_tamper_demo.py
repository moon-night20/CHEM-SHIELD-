"""Create and tamper with a disposable copy of the Admin audit database."""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIVE_DATABASE = ROOT / "admin_part" / "data" / "admin.db"


def create_tampered_copy(source: Path, destination: Path, live_database: Path = LIVE_DATABASE) -> Path:
    """Back up source to destination, then alter one copied audit row."""
    source = source.resolve()
    destination = destination.resolve()
    live = live_database.resolve()
    if destination == live:
        raise ValueError("Refusing to edit the live Admin database; choose a separate copy path.")
    if destination == source:
        raise ValueError("The tamper demo destination must differ from the source database.")
    if not source.is_file():
        raise FileNotFoundError(f"Source Admin database does not exist: {source}")
    if destination.exists():
        raise FileExistsError(f"Refusing to overwrite existing demo copy: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)

    source_connection = sqlite3.connect(source)
    destination_connection = sqlite3.connect(destination)
    try:
        source_connection.backup(destination_connection)
        tables = {
            row[0] for row in destination_connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        if "audit_log" not in tables:
            raise ValueError("Source database has no Admin audit_log table.")
        row = destination_connection.execute(
            "SELECT id, detail FROM audit_log ORDER BY id LIMIT 1"
        ).fetchone()
        if row is None:
            raise ValueError("The audit log is empty; add an audit event before the demo.")
        destination_connection.execute(
            "UPDATE audit_log SET detail = ? WHERE id = ?",
            (str(row[1]) + " [DEMO COPY MODIFIED]", row[0]),
        )
        destination_connection.commit()
    finally:
        destination_connection.close()
        source_connection.close()
    return destination


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create a disposable tampered copy for the Part 7 integrity demo."
    )
    parser.add_argument("--source", type=Path, default=LIVE_DATABASE)
    parser.add_argument("--copy", type=Path, default=ROOT / "out" / "p7-audit-tamper-copy.db")
    args = parser.parse_args(argv)
    try:
        copied = create_tampered_copy(args.source, args.copy)
    except (OSError, sqlite3.Error, ValueError) as error:
        print(f"Tamper demo refused: {error}", file=sys.stderr)
        return 1
    print(f"DEMO COPY ONLY: audit record changed in {copied}")
    print("The live Admin database was read-only and was not modified.")
    print("Point the local verifier at this copy to demonstrate a TAMPERED result.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
