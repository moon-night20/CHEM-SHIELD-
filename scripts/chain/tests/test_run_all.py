"""Smoke tests for the cross-platform demo launcher."""

from __future__ import annotations

from io import StringIO
from unittest.mock import patch

import pytest

from scripts import run_all
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
    monkeypatch.setattr(stop_all.os, "kill", lambda pid, _signal: killed.append(pid))

    assert stop_all.stop_all() == 0
    assert killed == [123, 789]
