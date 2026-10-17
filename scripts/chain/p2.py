"""Stage 1: replay and score network fixtures using the existing P2 pipeline."""

from __future__ import annotations

import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from chem_shield_p2.adapters import replay_events
from chem_shield_p2.network_scoring import (
    DEFAULT_MODEL,
    load_or_train_network_model,
    score_to_part4_events,
)

from .contracts import validate_p2_handoff, write_json


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_NETWORK_INPUT = REPO_ROOT / "chem_shield_p2" / "fixtures" / "demo_network_events.json"
DEFAULT_P2_CONFIG = REPO_ROOT / "chem_shield_p2" / "config.example.json"


def _threshold(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("threshold must be a finite number within [0, 1]")
    threshold = float(value)
    if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
        raise ValueError("threshold must be a finite number within [0, 1]")
    return threshold


def run(
    network_input: str | Path,
    output_path: str | Path,
    *,
    threshold: float = 0.5,
    config_path: str | Path = DEFAULT_P2_CONFIG,
    model_path: str | Path = DEFAULT_MODEL,
) -> dict[str, Any]:
    threshold = _threshold(threshold)
    with Path(config_path).open(encoding="utf-8") as stream:
        config = json.load(stream)
    if not isinstance(config, dict):
        raise ValueError("P2 config must be a JSON object")

    records = replay_events(network_input)
    if records:
        model = load_or_train_network_model(model_path)
        events = score_to_part4_events(records, model, config)
    else:
        events = []

    anomalous = [event for event in events if event["anomaly_score"] >= threshold]
    event_times = [
        datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")).astimezone(timezone.utc)
        for event in anomalous
    ]
    window = None
    if event_times:
        start, end = min(event_times), max(event_times)
        window = {
            "start": start.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "end": end.isoformat(timespec="seconds").replace("+00:00", "Z"),
        }
    handoff = {
        "asset_ids": sorted({event["asset_id"] for event in anomalous}),
        "window": window,
        "threshold": threshold,
        "anomalous_event_count": len(anomalous),
    }
    payload = {"events": events, "handoff": handoff}
    write_json(output_path, payload, validate_p2_handoff)
    return {
        "events": events,
        "anomalous_count": len(anomalous),
        "handoff": handoff,
    }
