"""Offline and read-only OT physical-process monitoring pipeline."""

from __future__ import annotations

import argparse
import csv
import json
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .event_normalizer import normalize_ot_event, rule_alert_to_event
from .ot_anomaly_model import PhysicalProcessIsolationForest
from .rule_engine import RuleEngine
from .sensor_validation import SensorValidator, parse_timestamp
from .sqlite_adapter import read_telemetry_read_only, persist_ot_events


@dataclass
class MonitorConfig:
    sensor_names: Dict[str, str]
    units: Dict[str, str]
    plausibility_ranges: Dict[str, Dict[str, Optional[float]]]
    stale_after_seconds: Optional[float]
    accepted_sensor_status: List[str]
    validation_severity: Dict[str, str]
    rules: Dict[str, Any]
    model_anomaly_threshold: float = 0.5
    model_anomaly_severity: str = "medium"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MonitorConfig":
        model_threshold = float(data.get("model_anomaly_threshold", 0.5))
        if not 0.0 <= model_threshold <= 1.0:
            raise ValueError("model_anomaly_threshold must be within [0, 1]")
        severity_values = {"info", "low", "medium", "high", "critical"}

        def validate_severities(value: Any, path: str = "rules") -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    if key.endswith("severity") and child not in severity_values:
                        raise ValueError(f"{path}.{key} must be one of {sorted(severity_values)}")
                    validate_severities(child, f"{path}.{key}")

        rules = dict(data.get("rules", {}))
        validation_severity = dict(data.get("validation_severity", {}))
        model_anomaly_severity = data.get("model_anomaly_severity", "medium")
        validate_severities(rules)
        for key, severity in validation_severity.items():
            if severity not in severity_values:
                raise ValueError(f"validation_severity.{key} must be one of {sorted(severity_values)}")
        if model_anomaly_severity not in severity_values:
            raise ValueError(f"model_anomaly_severity must be one of {sorted(severity_values)}")

        numeric_rule_keys = {
            "low", "high", "temperature", "pressure", "speed",
            "minimum_speed_when_running", "maximum_speed_when_stopped",
            "window_samples", "minimum_samples", "history_size",
        }

        def validate_rule_numbers(value: Any, path: str = "rules") -> None:
            if not isinstance(value, dict):
                return
            for key, child in value.items():
                child_path = f"{path}.{key}"
                if isinstance(child, dict):
                    validate_rule_numbers(child, child_path)
                elif key in numeric_rule_keys and child is not None:
                    if isinstance(child, bool) or not isinstance(child, (int, float)):
                        raise ValueError(f"{child_path} must be a finite number or null")
                    if not math.isfinite(float(child)):
                        raise ValueError(f"{child_path} must be a finite number or null")
                    if key in {"window_samples", "minimum_samples", "history_size"} and (
                        int(child) != child or child < 1
                    ):
                        raise ValueError(f"{child_path} must be a positive integer")

        validate_rule_numbers(rules)
        stale_after = data.get("stale_after_seconds")
        if stale_after is not None and (
            isinstance(stale_after, bool)
            or not isinstance(stale_after, (int, float))
            or not math.isfinite(float(stale_after))
            or stale_after <= 0
        ):
            raise ValueError("stale_after_seconds must be a positive finite number or null")
        return cls(
            sensor_names=dict(data.get("sensor_names", {})),
            units=dict(data.get("units", {})),
            plausibility_ranges=dict(data.get("plausibility_ranges", {})),
            stale_after_seconds=data.get("stale_after_seconds"),
            accepted_sensor_status=list(data.get("accepted_sensor_status", ["OK", "GOOD", "NORMAL"])),
            validation_severity=validation_severity,
            rules=rules,
            model_anomaly_threshold=model_threshold,
            model_anomaly_severity=model_anomaly_severity,
        )


class OTMonitor:
    """Validate readings, apply independent rules, and optionally score a fitted model."""

    def __init__(
        self,
        config: MonitorConfig,
        model: Optional[PhysicalProcessIsolationForest] = None,
    ) -> None:
        self.config = config
        self.validator = SensorValidator(
            sensor_names=config.sensor_names,
            units=config.units,
            plausibility_ranges=config.plausibility_ranges,
            stale_after_seconds=config.stale_after_seconds,
            accepted_sensor_status=config.accepted_sensor_status,
            validation_severity=config.validation_severity,
        )
        self.rule_engine = RuleEngine(config.rules)
        self.model = model

    def process(
        self,
        records: Iterable[Dict[str, Any]],
        now: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        records = list(records)
        records.sort(key=self._sort_timestamp)
        seen = set()
        events: List[Dict[str, Any]] = []
        valid_readings = []

        for record in records:
            result = self.validator.validate(record, now=now, seen_timestamps=seen)
            if result.issues:
                try:
                    event_time = parse_timestamp(record.get("timestamp"))
                except (ValueError, AttributeError):
                    event_time = now or datetime.now(timezone.utc)
                    if event_time.tzinfo is None:
                        event_time = event_time.replace(tzinfo=timezone.utc)
                asset = record.get("asset_id", record.get("machine_id", "UNKNOWN")) if isinstance(record, dict) else "UNKNOWN"
                if not isinstance(asset, str) or not asset.strip():
                    asset = "UNKNOWN"
                invalid_measurements = {}
                if isinstance(record, dict):
                    invalid_measurements = {
                        canonical: record.get(source_name)
                        for canonical, source_name in self.validator.sensor_names.items()
                    }
                for issue in result.issues:
                    events.append(normalize_ot_event(
                        reading=None,
                        event_type=issue.event_type,
                        severity=issue.severity,
                        evidence={"message": issue.message, "field": issue.field, "raw_record": record},
                        timestamp=event_time,
                        asset_id=asset.strip(),
                        measurements=invalid_measurements,
                        units=self.validator.units,
                        measurement_origin=(
                            record.get("measurement_origin", "unspecified")
                            if isinstance(record, dict) else "unspecified"
                        ),
                    ))
                continue

            reading = result.reading
            valid_readings.append(reading)
            for alert in self.rule_engine.evaluate(reading):
                events.append(rule_alert_to_event(reading, alert))

        if self.model is not None and valid_readings:
            model_rows = [reading.raw for reading in valid_readings]
            scored = self.model.score_records(model_rows)
            for reading, result in zip(valid_readings, scored):
                if result["anomaly_score"] >= self.config.model_anomaly_threshold:
                    events.append(normalize_ot_event(
                        reading=reading,
                        event_type="process_multivariable_anomaly",
                        severity=self.config.model_anomaly_severity,
                        evidence={
                            "message": "Physical telemetry deviates from the fitted normal baseline",
                            "detection_method": "isolation_forest",
                            "anomaly_score": result["anomaly_score"],
                            "score_interpretation": "relative anomaly score; not a probability",
                            "decision_function": result["decision_function"],
                        },
                        model={
                            "name": "PhysicalProcessIsolationForest",
                            "version": result["model_version"],
                            "feature_names": self.model.feature_names_,
                        },
                    ))
        return events

    @staticmethod
    def _sort_timestamp(record: Any) -> str:
        if isinstance(record, dict):
            try:
                return parse_timestamp(record.get("timestamp")).isoformat()
            except (ValueError, AttributeError):
                return "9999-12-31T23:59:59+00:00"
        return "9999-12-31T23:59:59+00:00"


def _read_csv(path: str | Path, sensor_names: Dict[str, str]) -> List[Dict[str, Any]]:
    sensor_fields = set(sensor_names.values())
    with open(path, "r", encoding="utf-8", newline="") as stream:
        records = []
        for row in csv.DictReader(stream):
            for field in sensor_fields:
                if row.get(field) not in (None, ""):
                    try:
                        row[field] = float(row[field])
                    except ValueError:
                        pass
            records.append(row)
        return records


def _load_config(path: str | Path) -> MonitorConfig:
    with open(path, "r", encoding="utf-8") as stream:
        return MonitorConfig.from_dict(json.load(stream))


def main(argv: Optional[Sequence[str]] = None) -> int:
    root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Read-only CHEM-SHIELD physical telemetry monitor")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--csv", help="Read telemetry from CSV")
    source.add_argument("--database", help="Read existing Part 1 SQLite telemetry database in read-only mode")
    parser.add_argument("--config", default=str(root / "config.example.json"))
    parser.add_argument("--model", help="Optional fitted physical Isolation Forest joblib artifact")
    parser.add_argument("--persist", action="store_true", help="Persist alerts through the existing events table adapter")
    parser.add_argument("--output", help="Write normalized event JSON to this path")
    args = parser.parse_args(argv)

    config = _load_config(args.config)
    model = PhysicalProcessIsolationForest.load(args.model) if args.model else None
    records = (
        _read_csv(args.csv, config.sensor_names)
        if args.csv
        else read_telemetry_read_only(args.database)
    )
    events = OTMonitor(config, model).process(records)
    if args.persist:
        if not args.database:
            parser.error("--persist requires --database")
        persist_ot_events(args.database, events)
    encoded = json.dumps(events, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(encoded + "\n", encoding="utf-8")
    print(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
