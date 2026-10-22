from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from chem_shield_p8.plant_twin import Controls, ReactorTwin, SimulatedPLC, load_config

CONFIG = Path(__file__).resolve().parents[1] / "config" / "plant.yaml"


def test_config_loads_expected_tags_and_trip_limits():
    config = load_config(CONFIG)
    assert set(config.tags) == {
        "temperature", "pressure", "level", "flow",
        "coolant_valve", "feed_pump", "relief_valve",
    }
    assert config.tags["temperature"].unit == "degC"
    assert config.tags["temperature"].trip_high == 100.0
    assert config.tags["pressure"].safe_max == 12.0


def test_invalid_config_is_reported(tmp_path):
    invalid = tmp_path / "invalid.yaml"
    invalid.write_text("plant: []\ntags: {}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="plant' and 'tags"):
        load_config(invalid)


def test_twin_is_deterministic_for_same_seed():
    first = ReactorTwin(seed=123)
    second = ReactorTwin(seed=123)
    controls = Controls(coolant_valve_pct=45.0, feed_pump_on=True)
    for _ in range(10):
        assert first.step(1.0, controls).as_dict() == second.step(1.0, controls).as_dict()


def test_energy_balance_heats_with_feed_and_cooling_reduces_temperature():
    config = load_config(CONFIG)
    hotter = ReactorTwin(config=config, seed=1)
    cooled = ReactorTwin(config=config, seed=1)
    for _ in range(40):
        hotter.step(1.0, Controls(coolant_valve_pct=0.0, feed_pump_on=True))
        cooled.step(1.0, Controls(coolant_valve_pct=100.0, feed_pump_on=True))
    assert hotter.state.temperature_c > 35.0
    assert cooled.state.temperature_c < hotter.state.temperature_c


def test_mass_balance_increases_level_with_feed_and_outflow_without_feed():
    feeding = ReactorTwin(seed=2)
    not_feeding = ReactorTwin(seed=2)
    for _ in range(20):
        feeding.step(1.0, Controls(feed_pump_on=True))
        not_feeding.step(1.0, Controls(feed_pump_on=False))
    assert feeding.state.level_pct > 55.0
    assert not_feeding.state.level_pct < 55.0


def test_actuator_and_flow_use_first_order_lag():
    twin = ReactorTwin(seed=3)
    state = twin.step(1.0, Controls(coolant_valve_pct=100.0, feed_pump_on=True))
    assert 0.0 < state.coolant_valve_pct < 100.0
    assert 0.0 < state.flow_l_min < 72.0


def test_pressure_relief_state_reduces_pressure_rate():
    config = load_config(CONFIG)
    parameters = dict(config.parameters, initial_pressure_bar=8.0)
    config = replace(config, parameters=parameters)
    relief_on = ReactorTwin(config=config, seed=4)
    relief_off = ReactorTwin(config=config, seed=4)
    for _ in range(4):
        relief_on.step(1.0, Controls(feed_pump_on=False, relief_valve_open=True))
        relief_off.step(1.0, Controls(feed_pump_on=False, relief_valve_open=False))
    assert relief_on.state.pressure_bar < relief_off.state.pressure_bar


@pytest.mark.parametrize("dt", [0, -1, 5.1, float("nan"), float("inf")])
def test_time_step_must_be_finite_and_bounded(dt):
    with pytest.raises(ValueError):
        ReactorTwin().step(dt)


def test_configured_trip_alarms_are_reported_without_actuation():
    twin = ReactorTwin(seed=5)
    twin.state.temperature_c = 101.0
    alarms = twin.trip_alarms()
    assert {"tag": "temperature", "value": 101.0, "limit": 100.0, "direction": "high"} in alarms
    assert twin.state.feed_pump_on is False


def test_plc_register_and_coil_round_trip_and_measurements():
    config = load_config(CONFIG)
    plc = SimulatedPLC(config)
    plc.write_holding_register(plc.COOLANT_SETPOINT, 6500)
    plc.write_coil(0, True)
    assert plc.controls() == Controls(coolant_valve_pct=65.0, feed_pump_on=True, relief_valve_open=None)

    twin = ReactorTwin(config=config)
    state = twin.step(1.0, plc.controls())
    plc.publish_state(state)
    assert plc.read_input_registers(4)[0] == round(state.coolant_valve_pct * 100)
    assert plc.read_input_registers(5, 2) == [1, 0]
    assert plc.read_coils(0, 2) == [True, False]


def test_plc_rejects_invalid_addresses_values_and_input_writes():
    plc = SimulatedPLC(load_config(CONFIG))
    with pytest.raises(ValueError, match="read-only"):
        plc.write_input_register(0, 20)
    with pytest.raises(ValueError, match="0-100"):
        plc.write_holding_register(plc.COOLANT_SETPOINT, 10001)
    with pytest.raises(ValueError, match="0 or 1"):
        plc.write_holding_register(plc.FEED_PUMP_COMMAND, 2)
    with pytest.raises(ValueError, match="outside the simulated map"):
        plc.read_coils(3)
