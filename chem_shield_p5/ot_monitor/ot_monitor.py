"""Offline and read-only OT physical-process monitoring pipeline."""

from __future__ import annotations

import argparse
import csv
import json
import logging
import math
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

import pandas as pd
from chem_shield_p3.src.detector import PhysicalAnomalyDetector
from chem_shield_p3.src.features import (
    BASE_FEATURE_COLUMNS,
    TelemetryValidationError,
    map_telemetry_reading,
)

from chem_shield_common.publisher import DEFAULT_HMI_URL, publish_events
from .event_normalizer import normalize_ot_event, rule_alert_to_event
from .event_normalizer import to_part4_correlation_event
from .rule_engine import RuleEngine
from .sensor_validation import SensorValidator, parse_timestamp
from .sqlite_adapter import (
    persist_ot_events,
    read_telemetry_read_only,
    read_telemetry_since,
)


LOGGER = logging.getLogger(__name__)
DEFAULT_PHYSICAL_MODEL = (
    Path(__file__).resolve().parents[2]
    / "chem_shield_p3"
    / "models"
    / "isolation_forest.joblib"
)
DEFAULT_TELEMETRY_DATABASE = (
    Path(__file__).resolve().parents[2]
    / "chem_shield_p1"
    / "data"
    / "telemetry.db"
)


@dataclass
class MonitorConfig:
    sensor_names: Dict[str, str]
    units: Dict[str, str]
    plausibility_ranges: Dict[str, Dict[str, Optional[float]]]
    stale_after_seconds: Optional[float]
    accepted_sensor_status: List[str]
    validation_severity: Dict[str, str]
    rules: Dict[str, Any]
    risk_asset_id: Optional[str] = None
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
        risk_asset_id = data.get("risk_asset_id")
        if risk_asset_id is not None and (
            not isinstance(risk_asset_id, str) or not risk_asset_id.strip()
        ):
            raise ValueError("risk_asset_id must be a non-empty string or null")

        numeric_rule_keys = {
            "low", "high", "temperature", "pressure", "speed",
            "minimum_speed_when_running", "maximum_speed_when_stopped",
            "window_samples", "minimum_samples", "history_size",
            "minimum_rpm_increase", "maximum_power_change", "minimum_power",
            "minimum_temperature_drop", "minimum_rpm_change",
            "minimum_pressure_change", "duration_seconds", "tolerance",
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
        physics_rules = rules.get("physics_consistency", {})
        frozen_sensor = physics_rules.get("frozen_sensor", {})
        frozen_sensors = frozen_sensor.get("sensors", [])
        if not isinstance(frozen_sensors, (list, tuple)) or any(
            not isinstance(sensor, str) or not sensor.strip()
            for sensor in frozen_sensors
        ):
            raise ValueError(
                "rules.physics_consistency.frozen_sensor.sensors must be a list of sensor names"
            )
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
            risk_asset_id=risk_asset_id,
            model_anomaly_threshold=model_threshold,
            model_anomaly_severity=model_anomaly_severity,
        )


class OTMonitor:
    """Validate readings, apply independent rules, and optionally score a fitted model."""

    def __init__(
        self,
        config: MonitorConfig,
        model: Optional[PhysicalAnomalyDetector] = None,
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
        self._model_previous_states: Dict[str, Dict[str, float]] = {}

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
            model_rows_by_asset: Dict[str, List[tuple[Any, Dict[str, Any]]]] = {}
            for reading in valid_readings:
                measurements = map_telemetry_reading(reading.measurements)
                missing = [
                    column for column in BASE_FEATURE_COLUMNS
                    if column not in measurements
                ]
                if missing:
                    message = "P3 model cannot score reading; missing required channels: " + ", ".join(missing)
                    LOGGER.warning("%s for asset %s", message, reading.asset_id)
                    events.append(normalize_ot_event(
                        reading=reading,
                        event_type="model_scoring_unavailable",
                        severity="medium",
                        evidence={"message": message, "missing_channels": missing},
                        model={"name": "PhysicalAnomalyDetector"},
                    ))
                    continue
                model_rows_by_asset.setdefault(reading.asset_id, []).append((reading, {
                    "timestamp": reading.timestamp.isoformat(),
                    "asset_id": reading.asset_id,
                    **measurements,
                }))
            if not model_rows_by_asset:
                return events
            score_by_reading: dict[tuple[str, str], float] = {}
            for asset_id, reading_rows in model_rows_by_asset.items():
                model_rows = [row for _, row in reading_rows]
                try:
                    scored = self.model.predict(
                        pd.DataFrame(model_rows),
                        previous_state=self._model_previous_states.get(asset_id),
                    )
                    if not isinstance(scored, pd.DataFrame):
                        raise RuntimeError("P3 detector returned a single event for a batch")
                except (KeyError, RuntimeError, TelemetryValidationError, TypeError, ValueError) as error:
                    message = f"P3 model could not score telemetry: {error}"
                    LOGGER.warning("%s for asset %s", message, asset_id)
                    for reading, _ in reading_rows:
                        events.append(normalize_ot_event(
                            reading=reading,
                            event_type="model_scoring_unavailable",
                            severity="medium",
                            evidence={"message": message},
                            model={"name": "PhysicalAnomalyDetector"},
                        ))
                    continue

                self._model_previous_states[asset_id] = {
                    column: float(model_rows[-1][column])
                    for column in BASE_FEATURE_COLUMNS
                }
                for (reading, _), result in zip(
                    reading_rows, scored.to_dict(orient="records")
                ):
                    score = float(result["anomaly_score"])
                    score_by_reading[
                        (reading.asset_id, reading.timestamp.isoformat(timespec="seconds"))
                    ] = score
                    if score >= self.config.model_anomaly_threshold:
                        events.append(normalize_ot_event(
                            reading=reading,
                            event_type="process_multivariable_anomaly",
                            severity=self.config.model_anomaly_severity,
                            evidence={
                                "message": "Physical telemetry deviates from the fitted normal baseline",
                                "detection_method": "P3 PhysicalAnomalyDetector",
                                "anomaly_score": result["anomaly_score"],
                                "configured_anomaly_threshold": (
                                    self.config.model_anomaly_threshold
                                ),
                                "score_interpretation": "relative anomaly score; not a probability",
                                "model_decision_score": result["model_decision_score"],
                            },
                            model={
                                "name": "PhysicalAnomalyDetector",
                                "version": self.model.training_metadata.get("artifact_version"),
                                "feature_columns": self.model.feature_columns,
                            },
                        ))
            for event in events:
                if event["event_type"] in {"sensor_data_invalid", "sensor_stale"}:
                    continue
                key = (event["asset_id"], event["timestamp"])
                if key in score_by_reading:
                    event["anomaly_score"] = score_by_reading[key]
        return events

    @staticmethod
    def _sort_timestamp(record: Any) -> str:
        if isinstance(record, dict):
            try:
                return parse_timestamp(record.get("timestamp")).isoformat()
            except (ValueError, AttributeError):
                return "9999-12-31T23:59:59+00:00"


class EventDebouncer:
    """Limit repeated publication of a sustained alert for one asset and rule."""

    def __init__(self, interval_seconds: float = 60.0) -> None:
        if not math.isfinite(interval_seconds) or interval_seconds <= 0:
            raise ValueError("debounce interval must be positive and finite")
        self.interval_seconds = interval_seconds
        self._last_published: Dict[tuple[str, str, str], float] = {}

    def should_publish(self, event: Dict[str, Any], now: Optional[float] = None) -> bool:
        moment = time.monotonic() if now is None else now
        evidence = event.get("evidence") or {}
        key = (
            str(event.get("asset_id", "UNKNOWN")),
            str(event.get("event_type", "unknown")),
            str(event.get("rule_id") or evidence.get("sensor") or ""),
        )
        previous = self._last_published.get(key)
        if previous is not None and moment - previous < self.interval_seconds:
            return False
        self._last_published[key] = moment
        return True


def follow_database(
    database: str | Path,
    config: MonitorConfig,
    model: PhysicalAnomalyDetector,
    *,
    hmi_url: str = DEFAULT_HMI_URL,
    poll_interval: float = 1.0,
    debounce_seconds: float = 60.0,
    max_cycles: Optional[int] = None,
) -> int:
    """Tail new P1 telemetry and publish debounced scored events to loopback HMI."""
    if not math.isfinite(poll_interval) or poll_interval <= 0:
        raise ValueError("poll interval must be positive and finite")
    if max_cycles is not None and max_cycles < 1:
        raise ValueError("max_cycles must be positive when specified")
    if not os.environ.get("CHEM_SHIELD_INGEST_TOKEN", "").strip():
        raise RuntimeError(
            "Follow mode requires the HMI ingest token; export CHEM_SHIELD_INGEST_TOKEN "
            "with the same value configured for the loopback HMI."
        )

    publisher = publish_events
    publisher([], url=hmi_url)
    monitor = OTMonitor(config, model)
    debouncer = EventDebouncer(debounce_seconds)
    last_id = 0
    cycles = 0
    while max_cycles is None or cycles < max_cycles:
        records = read_telemetry_since(database, last_id)
        cycles += 1
        if records:
            last_id = max(int(record["id"]) for record in records)
            events = monitor.process(records)
            publishable = [
                to_part4_correlation_event(
                    event,
                    event["anomaly_score"],
                    asset_id=config.risk_asset_id,
                )
                for event in events
                if "anomaly_score" in event and debouncer.should_publish(event)
            ]
            if publishable:
                result = publisher(publishable, url=hmi_url)
                if result["failed_batches"] or result["rejected"]:
                    LOGGER.warning("Follow-mode HMI publish result: %s", result)
                else:
                    LOGGER.info(
                        "Follow mode published %d scored event(s) to the local HMI",
                        result["accepted"],
                    )
        if max_cycles is None or cycles < max_cycles:
            time.sleep(poll_interval)
    return last_id


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
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--csv", help="Read telemetry from CSV")
    source.add_argument("--database", help="Read existing Part 1 SQLite telemetry database in read-only mode")
    parser.add_argument(
        "--follow",
        action="store_true",
        help="Continuously tail the default or specified Part 1 telemetry database and publish alerts",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=1.0,
        help="Seconds between SQLite tail checks in --follow mode (default: 1)",
    )
    parser.add_argument(
        "--debounce-seconds",
        type=float,
        default=60.0,
        help="Minimum seconds between repeated publications of the same asset/rule alert",
    )
    parser.add_argument("--config", default=str(root / "config.example.json"))
    parser.add_argument(
        "--model",
        default=str(DEFAULT_PHYSICAL_MODEL),
        help="P3 PhysicalAnomalyDetector artifact (default: chem_shield_p3/models/isolation_forest.joblib)",
    )
    parser.add_argument("--persist", action="store_true", help="Persist alerts through the existing events table adapter")
    parser.add_argument("--output", help="Write normalized event JSON to this path")
    parser.add_argument(
        "--publish",
        action="store_true",
        help="Publish scored physical events to the loopback Part 1 HMI",
    )
    parser.add_argument(
        "--hmi-url",
        default=DEFAULT_HMI_URL,
        help=f"Loopback Part 1 HMI risk endpoint (default: {DEFAULT_HMI_URL})",
    )
    args = parser.parse_args(argv)

    if args.follow:
        if args.csv:
            parser.error("--follow cannot be combined with --csv")
        if args.persist or args.output or args.publish:
            parser.error("--follow publishes scored events automatically; omit batch-only options")
        config = _load_config(args.config)
        model = PhysicalAnomalyDetector.load(args.model)
        follow_database(
            args.database or DEFAULT_TELEMETRY_DATABASE,
            config,
            model,
            hmi_url=args.hmi_url,
            poll_interval=args.poll_interval,
            debounce_seconds=args.debounce_seconds,
        )
        return 0
    if not args.csv and not args.database:
        parser.error("provide --csv or --database, or use --follow")

    config = _load_config(args.config)
    model = PhysicalAnomalyDetector.load(args.model)
    records = (
        _read_csv(args.csv, config.sensor_names)
        if args.csv
        else read_telemetry_read_only(args.database)
    )
    events = OTMonitor(config, model).process(records)
    if args.publish:
        publishable = [
            to_part4_correlation_event(
                event,
                event["anomaly_score"],
                asset_id=config.risk_asset_id,
            )
            for event in events
            if "anomaly_score" in event
        ]
        skipped = len(events) - len(publishable)
        if skipped:
            logging.getLogger(__name__).warning(
                "Skipped %d physical event(s) without a P3 anomaly score",
                skipped,
            )
        publish_events(publishable, url=args.hmi_url)
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
