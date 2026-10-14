import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from chem_shield_p1.data.store import TelemetryStore
from chem_shield_p1.ot_monitor.event_normalizer import to_part4_correlation_event
from chem_shield_p1.ot_monitor.ot_anomaly_model import PhysicalProcessIsolationForest
from chem_shield_p1.ot_monitor.ot_monitor import MonitorConfig, OTMonitor
from chem_shield_p1.ot_monitor.sensor_validation import SensorValidator
from chem_shield_p1.ot_monitor.sqlite_adapter import persist_ot_events, read_telemetry_read_only


ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def rows(filename):
    import csv
    with (SAMPLES / filename).open(newline="", encoding="utf-8") as stream:
        return [
            {
                **row,
                "temperature": float(row["temperature"]),
                "pressure": float(row["pressure"]),
                "speed": float(row["speed"]),
            }
            for row in csv.DictReader(stream)
        ]


def config(**changes):
    value = {
        "sensor_names": {"temperature": "temperature", "pressure": "pressure", "speed": "speed"},
        "units": {"temperature": "degC", "pressure": "bar", "speed": "rpm"},
        "plausibility_ranges": {},
        "stale_after_seconds": None,
        "model_anomaly_threshold": 0.5,
        "rules": {
            "limits": {
                "temperature": {"low": 10, "high": 80},
                "pressure": {"low": 0.5, "high": 5},
                "speed": {"low": 0, "high": 3000},
            },
            "rate_of_change": {"temperature": 10, "pressure": 1, "speed": 1000},
            "fluctuation": {
                "temperature": 5, "pressure": 1, "speed": 500,
                "window_samples": 3, "minimum_samples": 3,
            },
            "state_limits": {},
            "operating_rules": {
                "expected_running_states": ["RUNNING"],
                "stopped_states": ["STOPPED"],
                "minimum_speed_when_running": 50,
                "maximum_speed_when_stopped": 10,
            },
        },
    }
    value.update(changes)
    return MonitorConfig.from_dict(value)


def record(second, temperature=25, pressure=2, speed=500, state="RUNNING", **extra):
    return {
        "timestamp": f"2026-10-14T11:00:{second:02d}Z",
        "asset_id": "M-01",
        "temperature": temperature,
        "pressure": pressure,
        "speed": speed,
        "operating_state": state,
        "sensor_status": "OK",
        "measurement_origin": "synthetic_unit_test",
        **extra,
    }


class OTMonitorTests(unittest.TestCase):
    def test_normal_values_produce_no_engineering_alerts(self):
        events = OTMonitor(config()).process([record(0), record(10, 25.1, 2.01, 510)])
        self.assertEqual(events, [])

    def test_high_low_temperature_pressure_speed_rules(self):
        cases = [
            (record(0, temperature=90), "temperature_high"),
            (record(0, temperature=5), "temperature_low"),
            (record(0, pressure=6), "pressure_high"),
            (record(0, pressure=0.1), "pressure_low"),
            (record(0, speed=3200), "speed_high"),
            (record(0, speed=0), "speed_low"),
        ]
        for reading, expected in cases:
            with self.subTest(event_type=expected):
                events = OTMonitor(config()).process([reading])
                self.assertIn(expected, {event["event_type"] for event in events})

    def test_roc_fluctuation_and_operating_state_checks(self):
        cfg = config(rules={
            "rate_of_change": {"temperature": 5, "pressure": 0.5, "speed": 100},
            "fluctuation": {"temperature": 2, "pressure": 0.5, "speed": 100, "window_samples": 3, "minimum_samples": 3},
            "state_limits": {"RUNNING": {"temperature": {"high": 28}}},
            "operating_rules": {"minimum_speed_when_running": 50, "maximum_speed_when_stopped": 10},
        })
        readings = [
            record(0),
            record(10, temperature=29, pressure=4, speed=700),
            record(20, temperature=24, pressure=2, speed=500),
        ]
        events = OTMonitor(cfg).process(readings)
        types = {event["event_type"] for event in events}
        self.assertIn("rapid_process_change", types)
        self.assertIn("temperature_state_inconsistent", types)
        self.assertIn("process_fluctuation", types)
        stopped = OTMonitor(cfg).process([record(20, speed=100, state="STOPPED")])
        self.assertIn("unexpected_speed_while_stopped", {e["event_type"] for e in stopped})

    def test_missing_invalid_nonfinite_stale_and_duplicate_data(self):
        validator = SensorValidator(stale_after_seconds=20)
        now = datetime(2026, 10, 14, 11, 0, 21, tzinfo=timezone.utc)
        missing = dict(record(0))
        del missing["temperature"]
        self.assertIn(
            "sensor_data_invalid",
            {issue.event_type for issue in validator.validate(missing, now=now).issues},
        )
        invalid_type = record(1, temperature="hot")
        self.assertEqual(validator.validate(invalid_type, now=now).issues[0].event_type, "sensor_data_invalid")
        non_finite = record(2, pressure=float("nan"))
        invalid_events = OTMonitor(config()).process([non_finite], now=now)
        self.assertIn("sensor_data_invalid", {event["event_type"] for event in invalid_events})
        json.dumps(invalid_events, allow_nan=False)
        stale = record(0)
        self.assertEqual(validator.validate(stale, now=now).issues[0].event_type, "sensor_stale")
        seen = set()
        validator.validate(record(10), now=now, seen_timestamps=seen)
        duplicate = validator.validate(record(10), now=now, seen_timestamps=seen)
        self.assertTrue(any("Duplicate" in issue.message for issue in duplicate.issues))
        future = validator.validate(record(30), now=now).issues
        self.assertIn("sensor_data_invalid", {issue.event_type for issue in future})

    def test_invalid_severity_configuration_is_rejected(self):
        bad_rules = {
            "limits": {"temperature": {"high": 80, "high_severity": "urgent"}},
        }
        with self.assertRaisesRegex(ValueError, "high_severity"):
            config(rules=bad_rules)

    def test_sensor_aliases_and_units_are_configurable(self):
        validator = SensorValidator(
            sensor_names={"temperature": "temp_c", "pressure": "pressure_bar", "speed": "motor_rpm"},
            units={"temperature": "C", "pressure": "bar", "speed": "rpm"},
            plausibility_ranges={"temperature": {"min": -20, "max": 120}},
        )
        result = validator.validate({
            "timestamp": "2026-10-14T11:00:00Z",
            "asset_id": "M-01",
            "temp_c": 25,
            "pressure_bar": 2,
            "motor_rpm": 500,
        })
        self.assertFalse(result.issues)
        self.assertEqual(result.reading.measurements["speed"], 500)
        self.assertEqual(result.reading.units["temperature"], "C")
        implausible = validator.validate({
            "timestamp": "2026-10-14T11:00:00Z",
            "asset_id": "M-01",
            "temp_c": 121,
            "pressure_bar": 2,
            "motor_rpm": 500,
        })
        self.assertIn("sensor_data_invalid", {issue.event_type for issue in implausible.issues})
        bad_status = validator.validate({
            "timestamp": "2026-10-14T11:00:00Z",
            "asset_id": "M-01",
            "temp_c": 25,
            "pressure_bar": 2,
            "motor_rpm": 500,
            "sensor_status": "FAULT",
        })
        self.assertTrue(bad_status.issues)

    def test_normalized_output_and_part4_shape(self):
        event = OTMonitor(config()).process([record(0, temperature=90)])[0]
        self.assertEqual(event["source"], "ot_monitor")
        self.assertIn("event_id", event)
        self.assertEqual(event["units"]["temperature"], "degC")
        self.assertEqual(event["measurement_origin"], "synthetic_unit_test")
        correlation_event = to_part4_correlation_event(event, 0.7)
        self.assertEqual(
            set(correlation_event),
            {"timestamp", "asset_id", "event_type", "anomaly_score"},
        )
        self.assertEqual(correlation_event["event_type"], "physical")

    def test_model_training_evaluation_save_and_load(self):
        baseline = rows("normal_telemetry.csv")
        evaluation = rows("abnormal_telemetry.csv")
        model = PhysicalProcessIsolationForest(n_estimators=32, random_state=9).fit(baseline)
        metrics = model.evaluate(evaluation)
        self.assertEqual(set(metrics), {"precision", "recall", "f1", "false_positive_rate", "confusion_matrix"})
        self.assertGreaterEqual(metrics["precision"], 0)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "physical-model.joblib"
            model.save(path)
            loaded = PhysicalProcessIsolationForest.load(path)
            self.assertEqual(loaded.metadata["version"], model.metadata["version"])
            self.assertEqual(len(loaded.score_records(evaluation)), len(evaluation))
        with self.assertRaisesRegex(ValueError, "not labeled normal"):
            PhysicalProcessIsolationForest().fit([dict(baseline[0], label="abnormal")])

    def test_existing_sqlite_read_and_event_persistence(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "telemetry.db"
            store = TelemetryStore(str(database))
            store.add_telemetry({
                "timestamp": "2026-10-14T11:00:00+00:00", "machine_id": "M-01",
                "plc_id": "PLC-01", "motor_status": "RUNNING", "target_rpm": 1000,
                "rpm": 400, "temperature": 25, "pressure": 2, "power": 3,
            })
            records = read_telemetry_read_only(database)
            self.assertEqual(records[0]["speed"], 400)
            self.assertEqual(records[0]["measurement_origin"], "simulated_part1")
            events = OTMonitor(config()).process([dict(records[0], temperature=90)])
            first_count = persist_ot_events(database, events)
            second_count = persist_ot_events(database, events)
            self.assertGreater(first_count, 0)
            self.assertEqual(second_count, 0)
            self.assertEqual(store.recent_events()[0]["source"], "ot_monitor")

    def test_correlation_validator_accepts_normalized_bridge_event(self):
        from chem_shield_p4.correlation.validator import EventValidator

        ot_event = OTMonitor(config()).process([record(0, pressure=6)])[0]
        validated = EventValidator().validate_one(to_part4_correlation_event(ot_event, 0.6))
        self.assertEqual(validated.asset_id, "M-01")
        self.assertEqual(validated.event_type, "physical")


if __name__ == "__main__":
    unittest.main()
