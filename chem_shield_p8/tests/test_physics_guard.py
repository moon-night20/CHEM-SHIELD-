from __future__ import annotations

import pytest

from chem_shield_p8.physics_guard import PhysicalAnomalyModel, PhysicsGuard
from chem_shield_p8.plant_twin.model import Controls, PlantState, ReactorTwin, load_config


def state(
    temperature=35.0,
    pressure=2.0,
    level=55.0,
    flow=0.0,
    coolant=35.0,
    pump=False,
    relief=False,
):
    return PlantState(
        temperature_c=temperature,
        pressure_bar=pressure,
        level_pct=level,
        flow_l_min=flow,
        coolant_valve_pct=coolant,
        feed_pump_on=pump,
        relief_valve_open=relief,
    )


@pytest.fixture(scope="module")
def fitted_model():
    return PhysicalAnomalyModel.fit_simulated_normal(
        load_config(),
        seeds=range(3),
        steps_per_seed=80,
    )


def test_training_uses_deterministic_simulated_normal_trajectories(fitted_model):
    assert fitted_model.estimator is not None
    assert fitted_model.training_rows == 240
    assert fitted_model.threshold is not None


def test_guard_returns_both_scores_and_explanation(fitted_model):
    guard = PhysicsGuard(ml_model=fitted_model)
    first = guard.analyze(state(), 1.0)
    assert first.physics_score == 0.0
    assert 0.0 <= first.ml_score <= 1.0
    assert first.findings == []
    assert first.explanation


def test_ml_score_rises_for_a_sensor_combination_outside_normal_training(fitted_model):
    normal = state(temperature=35.0, pressure=2.0, level=55.0, flow=10.0, coolant=40.0, pump=True)
    spoofed = state(
        temperature=110.0,
        pressure=11.5,
        level=15.0,
        flow=0.0,
        coolant=100.0,
        pump=False,
    )
    assert fitted_model.score(spoofed, None, 1.0) > fitted_model.score(normal, None, 1.0)


def test_unexplained_temperature_jump_triggers_energy_and_rate_findings(fitted_model):
    guard = PhysicsGuard(ml_model=fitted_model)
    guard.analyze(state(), 1.0)
    result = guard.analyze(
        state(temperature=75.0, flow=0.0, coolant=35.0),
        1.0,
    )
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "RATE_OF_CHANGE" in rule_ids
    assert "ENERGY_BALANCE" in rule_ids
    assert "possible spoofing" in result.explanation
    assert "coolant flow" in result.explanation
    assert result.physics_score > 0.0


def test_mass_balance_detects_level_change_without_corresponding_flow(fitted_model):
    guard = PhysicsGuard(ml_model=fitted_model)
    guard.analyze(state(), 1.0)
    result = guard.analyze(state(level=70.0), 1.0)
    assert any(finding.rule_id == "MASS_BALANCE" for finding in result.findings)


def test_cross_sensor_rules_detect_flow_with_pump_off(fitted_model):
    guard = PhysicsGuard(ml_model=fitted_model)
    guard.analyze(state(), 1.0)
    result = guard.analyze(state(flow=18.0, pump=False), 1.0)
    assert any(finding.rule_id == "PUMP_FLOW_CORRELATION" for finding in result.findings)


def test_normal_reactor_trajectory_has_no_critical_physics_alerts(fitted_model):
    twin = ReactorTwin(seed=19)
    guard = PhysicsGuard(ml_model=fitted_model)
    results = [
        guard.analyze(twin.step(1.0, Controls(coolant_valve_pct=40.0, feed_pump_on=True)), 1.0)
        for _ in range(20)
    ]
    assert not any(
        finding.severity == "CRITICAL"
        for result in results
        for finding in result.findings
    )


@pytest.mark.parametrize("dt", [0, -1, 5.1])
def test_guard_rejects_invalid_time_step(fitted_model, dt):
    with pytest.raises(ValueError):
        PhysicsGuard(ml_model=fitted_model).analyze(state(), dt)


def test_ml_model_rejects_nonfinite_or_wrong_shaped_training_data():
    model = PhysicalAnomalyModel(config=load_config())
    with pytest.raises(ValueError, match="at least 20 rows"):
        model.fit([])
    with pytest.raises(ValueError, match="finite values"):
        model.fit([[float("nan")] * 11 for _ in range(20)])
