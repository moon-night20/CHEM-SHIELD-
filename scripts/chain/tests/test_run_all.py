"""Smoke tests for the cross-platform demo launcher."""

from __future__ import annotations

from io import StringIO

import pytest

from scripts import run_all


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

    def process_factory(command: list[str], **kwargs) -> FakeProcess:
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
    children = run_all.start_services(
        python_executable="python-test",
        process_factory=process_factory,
        readiness_probe=readiness_probe,
        stream=output,
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
        assert "5001" in commands[4]
        assert all(process.command[0] == "python-test" for process in launched)
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
