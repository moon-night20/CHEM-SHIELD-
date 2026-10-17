"""Stage 2: score in-window telemetry with the saved P3 physical model."""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import pandas as pd

from chem_shield_p3.src.detector import PhysicalAnomalyDetector
from chem_shield_p3.src.features import map_telemetry_reading
from chem_shield_p5.ot_monitor.ot_monitor import MonitorConfig

from .contracts import (
    ContractError,
    load_json,
    load_telemetry,
    parse_timestamp,
    validate_event_list,
    validate_p2_handoff,
    write_json,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_P3_MODEL = REPO_ROOT / "chem_shield_p3" / "models" / "isolation_forest.joblib"
DEFAULT_P5_CONFIG = REPO_ROOT / "chem_shield_p5" / "ot_monitor" / "config.example.json"
CORRELATION_WINDOW_SECONDS = 10.0


def _shared_asset_ids(p2_payload: dict[str, Any], risk_asset_id: str | None) -> list[str]:
    p2_assets = p2_payload["handoff"]["asset_ids"]
    if len(p2_assets) == 1 and risk_asset_id:
        if risk_asset_id != p2_assets[0]:
            raise ContractError(
                "asset_id mismatch: P2 uses "
                f"{p2_assets[0]!r} but P5 risk_asset_id is {risk_asset_id!r}"
            )
    if p2_assets:
        return list(p2_assets)
    return []


def run(
    p2_path: str | Path,
    telemetry_path: str | Path,
    output_path: str | Path,
    *,
    model_path: str | Path = DEFAULT_P3_MODEL,
    config_path: str | Path = DEFAULT_P5_CONFIG,
    correlation_window_seconds: float = CORRELATION_WINDOW_SECONDS,
) -> dict[str, Any]:
    p2_payload = validate_p2_handoff(load_json(p2_path, "P2"))
    if not p2_payload["handoff"]["asset_ids"]:
        events: list[dict[str, Any]] = []
        write_json(output_path, events, lambda value: validate_event_list(value, "P3", "physical"))
        return {"rows_scored": 0, "events": events, "network_trigger": False}

    with Path(config_path).open(encoding="utf-8") as stream:
        config = json.load(stream)
    if not isinstance(config, dict):
        raise ContractError("P5 config must be a JSON object")
    monitor_config = MonitorConfig.from_dict(config)
    risk_asset_id = monitor_config.risk_asset_id
    asset_ids = _shared_asset_ids(p2_payload, risk_asset_id)

    window = p2_payload["handoff"]["window"]
    if window is None:
        raise ContractError("P2 handoff.window is missing despite threshold-qualified events")
    start = parse_timestamp(window["start"], "P2.handoff.window.start") - timedelta(
        seconds=correlation_window_seconds
    )
    end = parse_timestamp(window["end"], "P2.handoff.window.end") + timedelta(
        seconds=correlation_window_seconds
    )
    telemetry = load_telemetry(telemetry_path)
    if telemetry.empty:
        selected = telemetry.copy()
    else:
        times = telemetry["timestamp"].map(
            lambda value: parse_timestamp(value, "telemetry.timestamp")
        )
        selected = telemetry.loc[(times >= start) & (times <= end)].copy()

    # risk_asset_id is the configured canonical ID for the simulated PLC. It
    # intentionally aliases fixture device IDs such as M-01 to PLC-01.
    if len(asset_ids) == 1 and risk_asset_id == asset_ids[0] and not selected.empty:
        selected["asset_id"] = asset_ids[0]
    else:
        selected = selected.loc[selected["asset_id"].isin(asset_ids)].copy()
    selected = selected.sort_values("timestamp", kind="stable").reset_index(drop=True)

    if selected.empty:
        events = []
    else:
        model_rows = []
        for row in selected.to_dict(orient="records"):
            mapped = map_telemetry_reading(row)
            model_rows.append({
                "timestamp": row["timestamp"],
                "asset_id": row["asset_id"],
                **mapped,
            })
        frame = pd.DataFrame(model_rows)
        detector = PhysicalAnomalyDetector.load(model_path)
        shared_asset_id = asset_ids[0] if len(asset_ids) == 1 else None
        predictions = (
            detector.predict(frame, asset_id=shared_asset_id)
            if shared_asset_id is not None
            else detector.predict(frame, stream_column="asset_id")
        )
        if not isinstance(predictions, pd.DataFrame):
            raise RuntimeError("P3 detector returned a single event for a telemetry batch")
        model_threshold = monitor_config.model_anomaly_threshold
        severity = monitor_config.model_anomaly_severity
        events = []
        for prediction in predictions.to_dict(orient="records"):
            score = float(prediction["anomaly_score"])
            if score < model_threshold:
                continue
            timestamp = str(prediction["timestamp"])
            prediction_asset_id = prediction["asset_id"]
            identity = f"{prediction_asset_id}:{timestamp}".encode("utf-8")
            event_id = "P3-" + hashlib.sha256(identity).hexdigest()[:16]
            events.append({
                "event_id": event_id,
                "timestamp": timestamp,
                "source": prediction.get("source", "physical_ml"),
                "asset_id": prediction_asset_id,
                "event_type": "physical",
                "anomaly_score": score,
                "severity": severity,
                "evidence": {
                    "model": prediction.get("model", "IsolationForest"),
                    "model_decision_score": float(prediction["model_decision_score"]),
                    "score_interpretation": "relative anomaly score; not a probability",
                },
            })

    write_json(output_path, events, lambda value: validate_event_list(value, "P3", "physical"))
    return {"rows_scored": len(selected), "events": events, "network_trigger": True}
