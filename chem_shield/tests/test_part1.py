import tempfile
import unittest
from pathlib import Path

from chem_shield.data.store import TelemetryStore
from chem_shield.events.abnormal_events import event_record
from chem_shield.process.machine import ProcessUnit


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