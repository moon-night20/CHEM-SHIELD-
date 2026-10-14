import json
import unittest
from pathlib import Path

from chem_shield_p2.adapters import (
    ModbusMonitorAdapter,
    OsSecurityAdapter,
    SuricataEveAdapter,
    ZeekConnectionAdapter,
    normalize_record,
    replay_events,
    to_part4_event,
)

ROOT = Path(__file__).resolve().parents[1]


class ReplayEventTests(unittest.TestCase):
    def test_to_part4_event_converts_scored_network_event(self):
        source = {
            "event_id": "stable-fixture-event",
            "timestamp": "2026-10-14T10:00:00Z",
            "source": "zeek",
            "asset_id": "10.10.10.5",
            "event_type": "connection",
            "severity": "medium",
            "evidence": {"dst_port": 502, "conn_state": "SF"},
        }
        converted = to_part4_event(source, 0.72, "PLC-01")
        repeated = to_part4_event(source, 0.72, "PLC-01")

        self.assertEqual(converted, repeated)
        self.assertEqual(converted["event_type"], "network")
        self.assertEqual(converted["anomaly_score"], 0.72)
        self.assertEqual(converted["asset_id"], "PLC-01")
        self.assertEqual(converted["event_id"], source["event_id"])
        self.assertEqual(converted["source"], "zeek")
        self.assertEqual(converted["severity"], "medium")
        self.assertEqual(converted["evidence"]["adapter_event_type"], "connection")

        from chem_shield_p4.correlation.validator import EventValidator

        validated = EventValidator().validate_one(converted)
        self.assertEqual(validated.event_type, "network")
        self.assertEqual(validated.anomaly_score, 0.72)

    def test_to_part4_event_rejects_scores_outside_part4_range(self):
        with self.assertRaisesRegex(ValueError, "anomaly_score"):
            to_part4_event(
                {"timestamp": "2026-10-14T10:00:00Z", "asset_id": "PLC-01"},
                1.01,
            )

    def test_replay_sample_json(self):
        records = replay_events([ROOT / "fixtures" / "sample_network_events.json"])
        self.assertEqual(len(records), 4)
        self.assertEqual(records[0]["source"], "zeek")
        self.assertIn("event_id", records[0])
        self.assertIn("timestamp", records[0])
        self.assertTrue(records[0]["timestamp"].endswith("Z"))
        self.assertEqual(records[0]["event_type"], "connection")
        self.assertEqual(records[0]["evidence"]["dst_port"], 502)

    def test_zeek_adapter_keeps_tcp_fields(self):
        record = json.loads((ROOT / "fixtures" / "zeek_conn.jsonl").read_text().splitlines()[0])
        normalized = ZeekConnectionAdapter().normalize(record)
        self.assertEqual(normalized["source"], "zeek")
        self.assertEqual(normalized["evidence"]["src_ip"], "192.168.2.10")
        self.assertIn("conn_state", normalized["evidence"])
        self.assertEqual(normalized["event_type"], "connection")

    def test_suricata_adapter_keeps_alert_fields(self):
        record = json.loads((ROOT / "fixtures" / "suricata_eve.jsonl").read_text().splitlines()[0])
        normalized = SuricataEveAdapter().normalize(record)
        self.assertEqual(normalized["source"], "suricata")
        self.assertEqual(normalized["severity"], "high")
        self.assertEqual(normalized["evidence"]["signature_id"], 2020123)

    def test_modbus_adapter_keeps_modbus_fields(self):
        record = json.loads((ROOT / "fixtures" / "modbus_monitor.json").read_text())[0]
        normalized = ModbusMonitorAdapter().normalize(record)
        self.assertEqual(normalized["event_type"], "modbus")
        self.assertTrue(normalized["evidence"]["approved_client"])
        self.assertEqual(normalized["evidence"]["function_code"], 3)
        self.assertEqual(normalized["evidence"]["operation"], "read_holding_registers")

    def test_os_security_adapter_keeps_log_fields(self):
        record = json.loads((ROOT / "fixtures" / "os_security.json").read_text())[0]
        normalized = OsSecurityAdapter().normalize(record)
        self.assertEqual(normalized["source"], "os_security")
        self.assertEqual(normalized["event_type"], "os_security")
        self.assertEqual(normalized["evidence"]["log_name"], "Security")

    def test_invalid_record_raises_useful_error(self):
        with self.assertRaises(ValueError):
            normalize_record({"nonsense": True})


if __name__ == "__main__":
    unittest.main()
