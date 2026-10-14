import json
import sys
import unittest
from pathlib import Path

from chem_shield_p5.ot_monitor.ot_monitor import MonitorConfig, OTMonitor
from chem_shield_p1.events.abnormal_events import event_record
from chem_shield_p3.src.detector import PhysicalAnomalyDetector
from chem_shield_p5.ot_monitor.event_normalizer import (
    to_part1_event_record,
    to_part4_correlation_event,
)
from chem_shield_p5.ot_monitor.sensor_validation import SensorValidator


ROOT = Path(__file__).resolve().parents[1]


def make_config():
    config_data = json.loads((ROOT / "config.example.json").read_text())
    config_data["rules"]["limits"]["temperature"]["high"] = 80
    return MonitorConfig.from_dict(config_data)


class Part5IntegrationTests(unittest.TestCase):
    def test_part5_exports_reuse_part1_implementation(self):
        self.assertEqual(
            PhysicalAnomalyDetector.__module__,
            "chem_shield_p3.src.detector",
        )
        self.assertIsNotNone(SensorValidator)

    def test_normalized_event_converts_to_part1_and_part4_contracts(self):
        event = OTMonitor(make_config()).process([{
            "timestamp": "2026-10-14T09:30:00Z",
            "asset_id": "M-01",
            "temperature": 95,
            "pressure": 2.4,
            "speed": 1200,
            "operating_state": "RUNNING",
            "measurement_origin": "synthetic_test",
        }])[0]
        p1_event = to_part1_event_record(event)
        self.assertEqual(
            set(p1_event),
            set(event_record("rpm_deviation", "normal", 100)),
        )
        self.assertEqual(p1_event["source"], "ot_monitor")
        self.assertEqual(p1_event["machine_id"], "M-01")
        self.assertEqual(p1_event["event_type"], "TEMPERATURE_HIGH")
        self.assertEqual(p1_event["parameter"], "TEMPERATURE-HIGH")

        p4_event = to_part4_correlation_event(event, 0.7)
        self.assertEqual(set(p4_event), {"timestamp", "asset_id", "event_type", "anomaly_score"})
        self.assertEqual(p4_event["event_type"], "physical")

        from chem_shield_p4.correlation.validator import EventValidator

        validated = EventValidator().validate_one(p4_event)
        self.assertEqual(validated.asset_id, "M-01")
        self.assertEqual(validated.event_type, "physical")

    def test_part5_replay_module_uses_p5_default_configuration(self):
        from chem_shield_p5.ot_monitor.__main__ import DEFAULT_CONFIG
        self.assertEqual(DEFAULT_CONFIG, ROOT / "config.example.json")


if __name__ == "__main__":
    unittest.main()
