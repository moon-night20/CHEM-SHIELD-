from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from chem_shield_p8.ot_monitor import MonitorConfig, OTMonitor, parse_event, parse_event_stream

CONFIG = Path(__file__).resolve().parents[1] / "config" / "monitor.yaml"
BASE_TIME = "2026-10-22T10:00:00Z"


def modbus(event_id: str, **changes):
    event = {
        "event_id": event_id,
        "timestamp": BASE_TIME,
        "protocol": "modbus-tcp",
        "source_ip": "192.0.2.10",
        "destination_ip": "192.0.2.20",
        "device_id": "PLC-REACTOR-01",
        "function_code": 3,
        "register": 0,
        "tag": "temperature",
        "value": 35,
    }
    event.update(changes)
    return event


def test_parser_normalizes_modbus_and_opc_ua_events():
    modbus_event = parse_event(modbus("m-1"))
    assert modbus_event.protocol == "modbus-tcp"
    assert modbus_event.operation == "read"
    assert modbus_event.timestamp.tzinfo == timezone.utc

    opc_event = parse_event({
        "event_id": "o-1",
        "timestamp": BASE_TIME,
        "protocol": "opcua",
        "source_ip": "192.0.2.10",
        "destination_ip": "192.0.2.20",
        "device_id": "PLC-REACTOR-01",
        "message": {"type": "Write", "node_id": "temperature", "value": 95},
    })
    assert opc_event.operation == "write"
    assert opc_event.tag == "temperature"
    assert opc_event.value == 95.0
    assert parse_event_stream([modbus("m-2")])[0].event_id == "m-2"


@pytest.mark.parametrize(
    "record, message",
    [
        ({}, "Unsupported simulated protocol"),
        (modbus(""), "non-empty event_id"),
        (modbus("bad-ip", source_ip="not-an-ip"), "source_ip must be an IP"),
        (modbus("bad-code", function_code="6"), "function_code must be an integer"),
        (
            {
                "event_id": "bad-opc",
                "timestamp": BASE_TIME,
                "protocol": "opcua",
                "source_ip": "192.0.2.10",
                "destination_ip": "192.0.2.20",
                "message": {"type": "Call"},
            },
            "must be 'Read' or 'Write'",
        ),
    ],
)
def test_parser_rejects_malformed_records(record, message):
    with pytest.raises(ValueError, match=message):
        parse_event(record)


def test_non_engineering_write_and_out_of_range_setpoint_raise_alerts():
    monitor = OTMonitor(MonitorConfig.load(CONFIG))
    alerts = monitor.process(modbus(
        "write-1",
        source_ip="192.0.2.30",
        function_code=6,
        value=130,
    ))
    rule_ids = {alert.rule_id for alert in alerts}
    assert "UNAUTHORIZED_WRITE" in rule_ids
    assert "SETPOINT_OUT_OF_RANGE" in rule_ids


def test_illegal_modbus_function_code_is_reported():
    alerts = OTMonitor(MonitorConfig.load(CONFIG)).process(
        modbus("illegal-fc", function_code=99)
    )
    assert any(alert.rule_id == "ILLEGAL_FUNCTION_CODE" for alert in alerts)


def test_new_endpoint_is_discovered_once_and_inventory_tracks_timestamps():
    monitor = OTMonitor(MonitorConfig.load(CONFIG))
    first_time = "2026-10-22T10:00:02Z"
    alerts = monitor.process(modbus(
        "discover-1",
        timestamp=first_time,
        source_ip="198.51.100.77",
    ))
    assert sum(alert.rule_id == "UNKNOWN_ASSET" for alert in alerts) == 1
    monitor.process(modbus(
        "discover-2",
        timestamp="2026-10-22T10:00:05Z",
        source_ip="198.51.100.77",
    ))
    asset = monitor.inventory.get("198.51.100.77")
    assert asset is not None
    assert asset.role == "unknown"
    assert asset.first_seen == datetime.fromisoformat(first_time.replace("Z", "+00:00"))
    assert asset.last_seen.isoformat() == "2026-10-22T10:00:05+00:00"
    assert asset.observations == 2


def test_polling_rate_threshold_counts_reads_in_rolling_window():
    config = MonitorConfig.load(CONFIG)
    config = MonitorConfig(
        known_hosts=config.known_hosts,
        allowed_modbus_function_codes=config.allowed_modbus_function_codes,
        poll_window_seconds=10,
        maximum_reads_per_window=2,
        replay_window_seconds=0.25,
        engineering_role=config.engineering_role,
    )
    monitor = OTMonitor(config)
    records = [
        modbus(
            f"poll-{index}",
            timestamp=f"2026-10-22T10:00:0{index}Z",
            value=35 + index,
        )
        for index in range(3)
    ]
    alerts = monitor.process_stream(records)
    assert sum(alert.rule_id == "ABNORMAL_POLLING_RATE" for alert in alerts) == 1


def test_replayed_identical_record_is_detected_within_replay_window():
    monitor = OTMonitor(MonitorConfig.load(CONFIG))
    first = modbus("replay-1", timestamp="2026-10-22T10:00:00Z")
    replay = dict(first, event_id="replay-2", timestamp="2026-10-22T10:00:01Z")
    monitor.process(first)
    alerts = monitor.process(replay)
    assert any(alert.rule_id == "DUPLICATE_PACKET_REPLAY" for alert in alerts)


def test_opc_ua_non_engineering_write_is_also_detected():
    monitor = OTMonitor(MonitorConfig.load(CONFIG))
    alerts = monitor.process({
        "event_id": "opc-write",
        "timestamp": BASE_TIME,
        "protocol": "opcua",
        "source_ip": "192.0.2.30",
        "destination_ip": "192.0.2.20",
        "device_id": "PLC-REACTOR-01",
        "message": {"type": "Write", "node_id": "pressure", "value": 13.5},
    })
    assert any(alert.rule_id == "UNAUTHORIZED_WRITE" for alert in alerts)
    assert any(alert.rule_id == "SETPOINT_OUT_OF_RANGE" for alert in alerts)
