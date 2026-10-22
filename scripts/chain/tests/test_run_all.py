"""Smoke tests for the cross-platform demo launcher."""

from __future__ import annotations

from io import StringIO
import sqlite3
from unittest.mock import patch

import pytest

from scripts import run_all
from scripts import chemshield
from scripts import stop_all


class FakeProcess:
    def __init__(self, command: list[str], **_kwargs) -> None:
        self.command = command
        self.stdout = StringIO("simulated startup\n")
        self.returncode = None
        self.terminated = False

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = 0

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is None:
            self.returncode = 0
        return self.returncode

    def kill(self) -> None:
        self.returncode = -9


def test_starts_readme_commands_in_order_without_network() -> None:
    launched: list[FakeProcess] = []
    readiness_checks: list[tuple[str, int, FakeProcess]] = []
    environments: list[dict[str, str]] = []

    def process_factory(command: list[str], **kwargs) -> FakeProcess:
        environments.append(kwargs["env"])
        process = FakeProcess(command, **kwargs)
        launched.append(process)
        return process

    def readiness_probe(
        host: str, port: int, process: FakeProcess, timeout: float
    ) -> None:
        readiness_checks.append((host, port, process))
        assert timeout == run_all.PLC_READY_TIMEOUT
        assert len(launched) == 1

    output = StringIO()
    with patch.dict("os.environ", {}, clear=True), patch(
        "scripts.run_all.secrets.token_urlsafe", return_value="shared-demo-token"
    ):
        children = run_all.start_services(
            python_executable="python-test",
            process_factory=process_factory,
            readiness_probe=readiness_probe,
            stream=output,
            admin_port=5002,
        )
    try:
        assert [child.name for child in children] == [
            "PLC", "Process", "HMI", "Admin", "OT Console"
        ]
        assert len(readiness_checks) == 1
        assert readiness_checks[0][:2] == ("127.0.0.1", 15020)
        assert readiness_checks[0][2] is launched[0]

        commands = [process.command for process in launched]
        assert [command[2] for command in commands] == [
            "chem_shield_p1.plc.modbus_plc",
            "chem_shield_p1.process.main",
            "chem_shield_p1.hmi.app",
            "admin_part.app",
            "the_attack.app",
        ]
        assert all("127.0.0.1" in command for command in commands[:3])
        assert all("15020" in command for command in commands[:3])
        assert "15000" in commands[2]
        assert commands[3][-2:] == ["--port", "5002"]
        assert "5001" in commands[4]
        assert environments[0]["CHEM_SHIELD_ADMIN_PORT"] == "5002"
        assert all(process.command[0] == "python-test" for process in launched)
        assert all(
            environment["PYTHONUTF8"] == "1"
            and environment["PYTHONIOENCODING"] == "utf-8"
            and environment["PYTHONUNBUFFERED"] == "1"
            for environment in environments
        )
        assert len(environments) == 5
        assert all(
            environment["CHEM_SHIELD_INGEST_TOKEN"] == "shared-demo-token"
            for environment in environments
        )
        assert all(environment is environments[0] for environment in environments)
    finally:
        run_all.stop_services(children)

    assert all(process.terminated for process in launched)
    for child in children:
        assert not child.log_thread.is_alive()
    assert "[PLC] simulated startup" in output.getvalue()


def test_rejects_non_loopback_hosts_before_starting_processes() -> None:
    with pytest.raises(ValueError, match="non-loopback"):
        run_all.build_commands(host="192.0.2.10")

    started = False

    def process_factory(*_args, **_kwargs):
        nonlocal started
        started = True
        raise AssertionError("no process should be started for a remote host")

    with pytest.raises(ValueError, match="non-loopback"):
        run_all.start_services("192.0.2.10", process_factory=process_factory)
    assert not started


def test_kill_old_only_terminates_matching_chem_shield_listener(monkeypatch) -> None:
    killed: list[int] = []
    active = {
        15020: [(123, "/venv/bin/python -m chem_shield_p1.plc.modbus_plc")],
        15000: [(456, "/Applications/OtherService")],
    }

    def listeners(port: int):
        return [item for item in active.get(port, []) if item[0] not in killed]

    monkeypatch.setattr(run_all, "_listener_details", listeners)
    monkeypatch.setattr(
        run_all, "_port_is_available", lambda port: not active.get(port)
    )
    monkeypatch.setattr(run_all, "_port_pids", lambda _port: [])
    monkeypatch.setattr(run_all, "_all_processes", lambda: [])
    monkeypatch.setattr(run_all.os, "kill", lambda pid, _signal: killed.append(pid))
    output = StringIO()

    with pytest.raises(RuntimeError, match="15000"):
        run_all.ensure_ports_available(kill_old=True, stream=output)

    assert killed == [123]
    assert "Leaving unrelated" not in output.getvalue()
    assert "PID 456" in output.getvalue()


def test_airplay_port_5000_message_allows_configured_alternate_admin_port(monkeypatch) -> None:
    monkeypatch.setattr(run_all.sys, "platform", "darwin")
    monkeypatch.setattr(
        run_all,
        "_listener_details",
        lambda port: [(789, "/System/Library/.../ControlCenter")] if port == 5000 else [],
    )
    monkeypatch.setattr(run_all, "_port_is_available", lambda port: port != 5000)
    output = StringIO()

    run_all.ensure_ports_available(admin_port=5002, stream=output)

    assert "macOS AirPlay Receiver" in output.getvalue()
    assert "System Settings → General → AirDrop & Handoff" in output.getvalue()
    assert "start Admin on another port" in output.getvalue()


def test_stop_all_only_stops_chem_shield_service_listeners(monkeypatch) -> None:
    killed: list[int] = []
    active = {
        15020: [(123, "/venv/bin/python -m chem_shield_p1.plc.modbus_plc")],
        5000: [(456, "/Applications/UnrelatedAdmin")],
    }

    def listeners(port: int):
        return [item for item in active.get(port, []) if item[0] not in killed]

    monkeypatch.setattr(stop_all, "_listener_details", listeners)
    monkeypatch.setattr(
        stop_all,
        "_all_processes",
        lambda: [
            (pid, command)
            for pid, command in (
                (123, "python -m chem_shield_p1.plc.modbus_plc"),
                (789, "python -m chem_shield_p1.process.main"),
                (456, "python unrelated.py"),
            )
            if pid not in killed
        ],
    )

    def missing_process_group(_pid: int) -> int:
        raise ProcessLookupError()

    monkeypatch.setattr(stop_all.os, "getpgid", missing_process_group)
    monkeypatch.setattr(stop_all.os, "kill", lambda pid, _signal: killed.append(pid))

    assert stop_all.stop_all() == 0
    assert killed == [123, 789]


def test_parses_windows_netstat_listening_rows_on_any_host_platform() -> None:
    output = """\
Active Connections
  Proto  Local Address          Foreign Address        State           PID
  TCP    127.0.0.1:15020        0.0.0.0:0              LISTENING       1234
  TCP    [::]:5000              [::]:0                 LISTENING       987
  TCP    127.0.0.1:15020        127.0.0.1:55120        ESTABLISHED     456
"""
    assert run_all._parse_netstat_output(output, 15020) == [1234]
    assert run_all._parse_netstat_output(output, 5000) == [987]


def test_parses_posix_lsof_listening_rows_on_any_host_platform() -> None:
    output = """\
COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
python   1234 me      6u  IPv4 0x123      0t0  TCP 127.0.0.1:15020 (LISTEN)
python    987 me      7u  IPv6 0x456      0t0  TCP *:5000 (LISTEN)
"""
    assert run_all._parse_lsof_output(output, 15020) == [1234]
    assert run_all._parse_lsof_output(output, 5000) == [987]
    assert run_all._parse_lsof_output("1234\n987\n", 5000) == [987, 1234]


def test_process_match_requires_a_known_module_invocation() -> None:
    assert run_all._is_chem_shield_process(
        "/venv/bin/python -m chem_shield_p1.process.main --port 15020"
    )
    assert not run_all._is_chem_shield_process(
        "python unrelated.py --note chem_shield_p1.process.main"
    )


def test_reset_incidents_only_clears_risk_data(tmp_path) -> None:
    database = tmp_path / "telemetry.db"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE telemetry (value INTEGER);
            INSERT INTO telemetry VALUES (42);
            CREATE TABLE risk_incidents (incident_id TEXT, status TEXT);
            INSERT INTO risk_incidents VALUES ('incident-1', 'ACTIVE');
            CREATE TABLE risk_events (event_id TEXT);
            INSERT INTO risk_events VALUES ('event-1');
            CREATE TABLE risk_ingest_state (
                id INTEGER PRIMARY KEY, last_received_at TEXT,
                last_accepted_at TEXT, accepted_count INTEGER,
                rejected_count INTEGER
            );
            INSERT INTO risk_ingest_state VALUES (1, 'now', 'now', 1, 2);
            """
        )

    assert chemshield.main(["reset-incidents", "--database", str(database)]) == 0
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT value FROM telemetry").fetchone() == (42,)
        assert connection.execute("SELECT COUNT(*) FROM risk_incidents").fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM risk_events").fetchone() == (0,)
        assert connection.execute(
            "SELECT accepted_count, rejected_count FROM risk_ingest_state"
        ).fetchone() == (0, 0)


def test_command_dispatch_uses_current_python_and_absolute_script_path(monkeypatch) -> None:
    received = []

    class Result:
        returncode = 7

    def fake_run(command, **kwargs):
        received.append((command, kwargs))
        return Result()

    monkeypatch.setattr(chemshield.sys, "executable", "/python/current")
    monkeypatch.setattr(chemshield.subprocess, "run", fake_run)

    assert chemshield.main(["stop", "--admin-port", "5002"]) == 7
    command, options = received[0]
    assert command == [
        "/python/current",
        str(chemshield.REPO_ROOT / "scripts" / "stop_all.py"),
        "--admin-port",
        "5002",
    ]
    assert options["cwd"] == chemshield.REPO_ROOT
    assert options["env"]["PYTHONUNBUFFERED"] == "1"


def test_run_command_forwards_launcher_options(monkeypatch) -> None:
    received = []

    def fake_run_script(script, args):
        received.append((script, args))
        return 0

    monkeypatch.setattr(chemshield, "_run_script", fake_run_script)

    assert chemshield.main(["run", "--admin-port", "5002", "--kill-old"]) == 0
    assert received == [("run_all.py", ["--kill-old", "--admin-port", "5002"])]
