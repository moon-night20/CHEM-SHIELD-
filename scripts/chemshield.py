"""Cross-platform command-line entry point for the local CHEM-SHIELD demo."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

if __package__:
    from . import run_all
else:
    import run_all


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE = REPO_ROOT / "chem_shield_p1" / "data" / "telemetry.db"


def _child_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment["PYTHONUTF8"] = "1"
    environment["PYTHONIOENCODING"] = "utf-8"
    environment["PYTHONUNBUFFERED"] = "1"
    return environment


def _run_script(script: str, args: list[str]) -> int:
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / script), *args],
        cwd=REPO_ROOT,
        env=_child_environment(),
        check=False,
    ).returncode


def _setup(_args: argparse.Namespace) -> int:
    requirements = REPO_ROOT / "requirements.txt"
    return subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", str(requirements)],
        cwd=REPO_ROOT,
        env=_child_environment(),
        check=False,
    ).returncode


def _test(args: argparse.Namespace) -> int:
    return subprocess.run(
        [sys.executable, "-m", "pytest", *args.pytest_args],
        cwd=REPO_ROOT,
        env=_child_environment(),
        check=False,
    ).returncode


def _run(args: argparse.Namespace) -> int:
    return _run_script("run_all.py", args.run_args)


def _stop(args: argparse.Namespace) -> int:
    return _run_script("stop_all.py", args.stop_args)


def _database_path(value: str | Path) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else REPO_ROOT / path


def _reset_incidents(args: argparse.Namespace) -> int:
    database = _database_path(args.database)
    if not database.is_file():
        print(f"Incident database does not exist: {database}", file=sys.stderr)
        return 1
    try:
        with sqlite3.connect(database) as connection:
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            required = {"risk_incidents", "risk_events", "risk_ingest_state"}
            if not required.issubset(tables):
                missing = ", ".join(sorted(required - tables))
                raise RuntimeError(f"not a CHEM-SHIELD incident database (missing {missing})")
            connection.execute("BEGIN IMMEDIATE")
            event_count = connection.execute("SELECT COUNT(*) FROM risk_events").fetchone()[0]
            incident_count = connection.execute(
                "SELECT COUNT(*) FROM risk_incidents"
            ).fetchone()[0]
            connection.execute("DELETE FROM risk_events")
            connection.execute("DELETE FROM risk_incidents")
            connection.execute(
                "UPDATE risk_ingest_state SET last_received_at=NULL, "
                "last_accepted_at=NULL, accepted_count=0, rejected_count=0 WHERE id=1"
            )
    except (OSError, sqlite3.Error, RuntimeError) as error:
        print(f"Could not reset incident data: {error}", file=sys.stderr)
        return 1
    print(
        f"Reset {incident_count} incident(s) and {event_count} risk event(s) in "
        f"{database}. Telemetry data was not changed."
    )
    return 0


def _status(args: argparse.Namespace) -> int:
    try:
        admin_port = run_all._port_number(
            args.admin_port
            if args.admin_port is not None
            else os.environ.get("CHEM_SHIELD_ADMIN_PORT", run_all.ADMIN_PORT)
        )
    except ValueError as error:
        print(error, file=sys.stderr)
        return 2

    ports = (
        ("PLC", run_all.PLC_PORT),
        ("HMI", run_all.HMI_PORT),
        ("Admin", admin_port),
        ("OT Console", run_all.OT_CONSOLE_PORT),
    )
    for name, port in ports:
        if run_all._port_is_available(port):
            print(f"{name}: stopped (port {port} is available)")
            continue
        listeners = run_all._listener_details(port)
        if listeners:
            details = "; ".join(
                f"PID {pid}: {command or 'process command unavailable'}"
                for pid, command in listeners
            )
            print(f"{name}: running/occupied on port {port} ({details})")
        else:
            print(f"{name}: port {port} is occupied (process attribution unavailable)")

    database = _database_path(args.database)
    if not database.is_file():
        print(f"Incidents: database not found ({database})")
        return 0
    try:
        with sqlite3.connect(database) as connection:
            table = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='risk_incidents'"
            ).fetchone()
            active = (
                connection.execute(
                    "SELECT COUNT(*) FROM risk_incidents WHERE status='ACTIVE'"
                ).fetchone()[0]
                if table
                else 0
            )
    except sqlite3.Error as error:
        print(f"Incidents: unable to read database ({error})", file=sys.stderr)
        return 1
    print(f"Incidents: {active} active")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage the local, loopback-only CHEM-SHIELD simulation."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    setup = subparsers.add_parser("setup", help="Install project dependencies.")
    setup.set_defaults(handler=_setup)

    test = subparsers.add_parser("test", help="Run project tests with this Python.")
    test.add_argument("pytest_args", nargs=argparse.REMAINDER)
    test.set_defaults(handler=_test)

    run = subparsers.add_parser("run", help="Start all loopback demo services.")
    run.add_argument("run_args", nargs=argparse.REMAINDER)
    run.set_defaults(handler=_run)

    stop = subparsers.add_parser("stop", help="Stop recognized CHEM-SHIELD services.")
    stop.add_argument("stop_args", nargs=argparse.REMAINDER)
    stop.set_defaults(handler=_stop)

    reset = subparsers.add_parser(
        "reset-incidents",
        help="Delete risk incidents/events without changing telemetry data.",
    )
    reset.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    reset.set_defaults(handler=_reset_incidents)

    status = subparsers.add_parser("status", help="Show service-port and incident status.")
    status.add_argument("--admin-port", type=int, default=None)
    status.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    status.set_defaults(handler=_status)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
