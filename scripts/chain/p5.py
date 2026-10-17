"""Stage 4: run read-only OT validation and rule checks for each P4 incident."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from chem_shield_p5.ot_monitor.ot_monitor import MonitorConfig, OTMonitor

from .contracts import (
    ContractError,
    load_json,
    load_telemetry,
    parse_timestamp,
    validate_p4_incidents,
    validate_p5_report,
    write_json,
)


DEFAULT_P5_CONFIG = (
    Path(__file__).resolve().parents[2]
    / "chem_shield_p5"
    / "ot_monitor"
    / "config.example.json"
)


def _within(value: str, start: datetime, end: datetime) -> bool:
    timestamp = parse_timestamp(value, "telemetry.timestamp")
    return start <= timestamp <= end


def run(
    p4_path: str | Path,
    telemetry_path: str | Path,
    output_path: str | Path,
    *,
    config_path: str | Path = DEFAULT_P5_CONFIG,
) -> list[dict[str, Any]]:
    incidents = validate_p4_incidents(load_json(p4_path, "P4"))
    try:
        with Path(config_path).open(encoding="utf-8") as stream:
            raw_config = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"P5 config is unreadable or invalid JSON: {exc}") from exc
    if not isinstance(raw_config, dict):
        raise ContractError("P5 config must be a JSON object")
    config = MonitorConfig.from_dict(raw_config)
    telemetry = load_telemetry(telemetry_path)
    reports = []

    for incident in incidents:
        start = parse_timestamp(incident["start_time"], "P4.incident.start_time")
        end = parse_timestamp(incident["end_time"], "P4.incident.end_time")
        selected = []
        for row in telemetry.to_dict(orient="records"):
            if not _within(row["timestamp"], start, end):
                continue
            original_asset_id = row["asset_id"]
            if original_asset_id != incident["asset_id"]:
                if config.risk_asset_id != incident["asset_id"]:
                    continue
                row["asset_id"] = incident["asset_id"]
            selected.append(row)

        # model=None is deliberate: P3 owns physical anomaly scoring. This
        # call performs only the configured SensorValidator and RuleEngine work.
        monitor = OTMonitor(config, model=None)
        output_events = monitor.process(selected)
        issues = [
            event for event in output_events
            if event["event_type"] in {"sensor_data_invalid", "sensor_stale"}
        ]
        alerts = [
            event for event in output_events
            if event["event_type"] not in {"sensor_data_invalid", "sensor_stale"}
        ]
        reports.append({
            "incident_id": incident["incident_id"],
            "risk_level": incident["risk_level"],
            "risk_score": incident["risk_score"],
            "rule_alerts": alerts,
            "sensor_validation_issues": issues,
            "rule_confirmation": bool(alerts),
        })

    write_json(output_path, reports, validate_p5_report)
    return reports
