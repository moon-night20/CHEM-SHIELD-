from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from chem_shield_p8.attack_lab import ReplayRunner, load_scenarios
from chem_shield_p8.attack_lab.mitre import TECHNIQUES

SCENARIOS = Path(__file__).resolve().parents[1] / "attack_lab" / "scenarios.json"


@pytest.fixture(scope="module")
def runner():
    return ReplayRunner(load_scenarios(SCENARIOS))


@pytest.mark.parametrize(
    "scenario_id, expected_rule",
    [
        ("setpoint-manipulation", "SETPOINT_OUT_OF_RANGE"),
        ("sensor-replay", "DUPLICATE_PACKET_REPLAY"),
        ("rogue-engineering-workstation", "UNAUTHORIZED_WRITE"),
        ("loss-of-view", "LOSS_OF_VIEW"),
        ("safety-bypass-attempt", "SIS_BASELINE_CHANGE"),
        ("it-to-ot-lateral-movement", "DIRECT_IT_TO_CONTROL"),
    ],
)
def test_each_scenario_detects_expected_behavior(runner, scenario_id, expected_rule):
    result = runner.run(
        scenario_id,
        started_at=datetime(2026, 10, 22, tzinfo=timezone.utc),
    )
    assert result.status == "COMPLETE"
    assert expected_rule in result.detected_rules
    assert result.detection_time_seconds is not None
    assert result.missed_steps == []
    assert result.false_positive_count == 0
    assert all(alert.techniques for alert in result.alerts)
    assert all(
        technique["id"] in TECHNIQUES
        for alert in result.alerts
        for technique in alert.techniques
    )


def test_sensor_replay_detection_latency_is_simulated_not_wall_clock(runner):
    result = runner.run(
        "sensor-replay",
        started_at=datetime(2026, 10, 22, tzinfo=timezone.utc),
    )
    assert result.detection_time_seconds == 2.0
    assert result.ended_at == datetime(2026, 10, 22, 0, 0, 2, tzinfo=timezone.utc)


def test_session_supports_stepwise_replay(runner):
    session = runner.start(
        "sensor-replay",
        started_at=datetime(2026, 10, 22, tzinfo=timezone.utc),
    )
    assert not session.complete
    first = session.step()
    assert first["step"] == 1
    assert first["complete"] is False
    second = session.step()
    assert second["step"] == 2
    assert second["complete"] is True
    assert any(alert["rule_id"] == "DUPLICATE_PACKET_REPLAY" for alert in second["alerts"])
    with pytest.raises(RuntimeError, match="already complete"):
        session.step()


def test_scenarios_define_expected_attack_surface_and_techniques(runner):
    scenarios = load_scenarios(SCENARIOS)
    assert len(scenarios) == 6
    assert {scenario["id"] for scenario in scenarios} == {
        "setpoint-manipulation",
        "sensor-replay",
        "rogue-engineering-workstation",
        "loss-of-view",
        "safety-bypass-attempt",
        "it-to-ot-lateral-movement",
    }
    assert {item["id"] for item in TECHNIQUES.values()} == {
        "T0831", "T0836", "T1691.002", "T1692.001",
    }


def test_unknown_scenario_fails_explicitly(runner):
    with pytest.raises(ValueError, match="Unknown synthetic scenario"):
        runner.start("../not-a-scenario")
