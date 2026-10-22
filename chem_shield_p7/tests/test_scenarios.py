from __future__ import annotations

import threading
import time

import pytest

from chem_shield_p7.scenarios.library import SCENARIOS, get_scenario, validate_scenarios
from chem_shield_p7.scenarios.runner import ScenarioRunner
from chem_shield_p7.timeline.store import TimelineStore


class FakeConsole:
    def __init__(self, *, block=False):
        self.clear_count = 0
        self.started = threading.Event()
        self.release = threading.Event()
        self.block = block

    def apply_step(self, sensor, value):
        self.started.set()
        if self.block:
            self.release.wait(timeout=3)
        return {"id": None, "sensor": sensor, "value": value}

    def command_status(self):
        return {"commands": []}

    def clear_overrides(self):
        self.clear_count += 1
        return {"ok": True}


def wait_finished(runner):
    deadline = time.monotonic() + 3
    while runner.status().get("running") and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not runner.status().get("running")


def test_scenario_library_has_valid_unique_simulated_steps():
    validate_scenarios()
    assert len({item["id"] for item in SCENARIOS}) == 5
    assert {item["id"] for item in SCENARIOS} == {
        "overheat",
        "pressure-spike",
        "overspeed",
        "stealthy-in-range-drift",
        "cascade",
    }
    with pytest.raises(ValueError):
        get_scenario("../admin.db")
    stealth = get_scenario("stealthy-in-range-drift")
    assert all(
        step["value"] < {"temperature": 70, "pressure": 4, "power": 12, "speed": 1500}[step["sensor"]]
        for step in stealth["steps"]
    )


def test_runner_start_abort_clears_overrides_and_records_ordered_timeline(tmp_path):
    store = TimelineStore(tmp_path / "p7.db")
    console = FakeConsole(block=True)
    runner = ScenarioRunner(
        store,
        admin_database=str(tmp_path / "admin.db"),
        report_dir=str(tmp_path / "reports"),
        console=console,
        monitor=False,
        poll_interval=0.05,
    )
    run_id = runner.start("overheat")
    assert console.started.wait(timeout=2)
    with pytest.raises(RuntimeError, match="already running"):
        runner.start("pressure-spike")
    assert runner.abort()
    console.release.set()
    wait_finished(runner)

    run = store.get_run(run_id)
    event_types = [event["event_type"] for event in run["events"]]
    assert event_types[0] == "SCENARIO_STARTED"
    assert "ABNORMAL_READING" in event_types
    assert event_types[-2:] == ["OVERRIDES_CLEARED", "RESOLVED"]
    assert run["status"] == "ABORTED"
    assert console.clear_count == 1


def test_runner_completes_scenario_and_clears_overrides(tmp_path):
    store = TimelineStore(tmp_path / "p7.db")
    console = FakeConsole()
    runner = ScenarioRunner(
        store,
        admin_database=str(tmp_path / "admin.db"),
        report_dir=str(tmp_path / "reports"),
        console=console,
        monitor=False,
        poll_interval=0.05,
    )
    run_id = runner.start("overheat")
    wait_finished(runner)
    run = store.get_run(run_id)
    types = [event["event_type"] for event in run["events"]]
    assert types.index("SCENARIO_STARTED") < types.index("ABNORMAL_READING")
    assert types[-2:] == ["OVERRIDES_CLEARED", "RESOLVED"]
    assert run["status"] == "COMPLETED"
    assert console.clear_count == 1


def test_runner_reports_audit_failure_after_clearing_overrides(tmp_path):
    store = TimelineStore(tmp_path / "p7.db")
    console = FakeConsole()

    def failed_audit(**_fields):
        raise OSError("audit database unavailable")

    runner = ScenarioRunner(
        store,
        admin_database=str(tmp_path / "admin.db"),
        report_dir=str(tmp_path / "reports"),
        console=console,
        monitor=False,
        audit=failed_audit,
        poll_interval=0.05,
    )
    run_id = runner.start("overheat")
    wait_finished(runner)

    run = store.get_run(run_id)
    assert run["status"] == "FAILED"
    assert console.clear_count == 1
    assert runner.status()["status"] == "FAILED"
    assert "audit database unavailable" in runner.status()["error"]
