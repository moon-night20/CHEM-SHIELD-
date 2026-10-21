import tempfile
import unittest
from pathlib import Path

from chem_shield_p1.data.store import TelemetryStore
from chem_shield_p1.events.abnormal_events import event_record
from chem_shield_p1.plc.register_map import (
    OVERRIDE_POWER,
    OVERRIDE_PRESSURE,
    OVERRIDE_SPEED,
    OVERRIDE_TEMPERATURE,
    REGISTER_COUNT,
    SIM_OVERRIDE_MASK,
    SIM_POWER,
    SIM_PRESSURE,
    SIM_SPEED,
    SIM_TEMPERATURE,
)
from chem_shield_p1.process.main import (
    apply_simulation_overrides,
    cap_uncommanded_values,
)
from chem_shield_p1.process.machine import (
    MAX_SIMULATED_POWER_KW,
    MAX_SIMULATED_PRESSURE_BAR,
    MAX_SIMULATED_SPEED_RPM,
    MAX_SIMULATED_TEMPERATURE_C,
    ProcessUnit,
)


class PartOneTests(unittest.TestCase):
    def test_process_ramps_and_coasts(self):
        unit = ProcessUnit(seed=1)
        ramp = [unit.step(True, 1500).rpm for _ in range(8)]
        self.assertGreater(ramp[-1], ramp[0])
        self.assertLess(ramp[-1], 1500)
        before_stop = unit.state.temperature
        for _ in range(80):
            unit.step(False, 1500)
        self.assertLess(unit.state.rpm, ramp[-1])
        self.assertLess(unit.state.temperature, before_stop)

    def test_normal_process_values_stay_within_all_operating_limits(self):
        unit = ProcessUnit(seed=1)
        for _ in range(1200):
            state = unit.step(True, 3000)
            self.assertLessEqual(state.temperature, MAX_SIMULATED_TEMPERATURE_C)
            self.assertLessEqual(state.pressure, MAX_SIMULATED_PRESSURE_BAR)
            self.assertLessEqual(state.power, MAX_SIMULATED_POWER_KW)
            self.assertLessEqual(state.rpm, MAX_SIMULATED_SPEED_RPM)

    def test_normal_process_values_fluctuate_below_operating_limits(self):
        unit = ProcessUnit(seed=1)
        samples = []
        for _ in range(1200):
            state = unit.step(True, 3000)
            samples.append((state.rpm, state.temperature, state.pressure, state.power))

        recent = samples[-100:]
        for index, minimum_range in enumerate((3.0, 0.2, 0.05, 0.3)):
            values = [sample[index] for sample in recent]
            self.assertGreater(max(values) - min(values), minimum_range)

        averages = [sum(sample[index] for sample in recent) / len(recent) for index in range(4)]
        self.assertLess(averages[0], 1490)
        self.assertLess(averages[1], 69)
        self.assertLess(averages[2], 3.95)
        self.assertLess(averages[3], 11.8)
        for index, maximum in enumerate((
            MAX_SIMULATED_SPEED_RPM,
            MAX_SIMULATED_TEMPERATURE_C,
            MAX_SIMULATED_PRESSURE_BAR,
            MAX_SIMULATED_POWER_KW,
        )):
            self.assertLess(max(sample[index] for sample in recent), maximum)

    def test_values_above_limits_require_the_matching_explicit_override(self):
        state = ProcessUnit().state
        registers = [0] * REGISTER_COUNT
        state.temperature = 75
        state.pressure = 6.5
        state.power = 13
        state.rpm = 1600

        cap_uncommanded_values(state, registers)
        self.assertEqual(state.temperature, 69.99)
        self.assertEqual(state.pressure, 3.99)
        self.assertEqual(state.power, 11.99)
        self.assertEqual(state.rpm, 1499)

        registers[SIM_OVERRIDE_MASK] = (
            OVERRIDE_TEMPERATURE | OVERRIDE_PRESSURE | OVERRIDE_POWER | OVERRIDE_SPEED
        )
        registers[SIM_TEMPERATURE] = 7500
        registers[SIM_PRESSURE] = 650
        registers[SIM_POWER] = 1300
        registers[SIM_SPEED] = 1600
        cap_uncommanded_values(state, registers)
        apply_simulation_overrides(state, registers)
        self.assertEqual(state.temperature, 75)
        self.assertEqual(state.pressure, 6.5)
        self.assertEqual(state.power, 13)
        self.assertEqual(state.rpm, 1600)

    def test_telemetry_schema_and_event_format(self):
        with tempfile.TemporaryDirectory() as directory:
            store = TelemetryStore(str(Path(directory) / "telemetry.db"))
            record = {
                "timestamp": "2026-01-01T00:00:00+00:00", "machine_id": "M-01",
                "plc_id": "PLC-01", "motor_status": "RUNNING", "target_rpm": 1500,
                "rpm": 100, "temperature": 20, "pressure": 1, "power": 1,
            }
            store.add_telemetry(record)
            self.assertEqual(store.recent()[0]["target_rpm"], 1500)
            event = event_record("pressure_spike", 4, 8)
            self.assertEqual(event["event_type"], "PRESSURE_SPIKE")
            store.add_event(event)


if __name__ == "__main__":
    unittest.main()