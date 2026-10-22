"""Read-only machine snapshot and transparent demo posture scoring."""

from __future__ import annotations

from datetime import datetime
from typing import Any


def _seconds_between(start: Any, end: Any) -> float | None:
    if not isinstance(start, str) or not isinstance(end, str):
        return None
    try:
        first = datetime.fromisoformat(start.replace("Z", "+00:00"))
        second = datetime.fromisoformat(end.replace("Z", "+00:00"))
    except ValueError:
        return None
    if first.tzinfo is None or second.tzinfo is None:
        return None
    return max(0.0, (second - first).total_seconds())


def calculate_posture_score(
    run: dict[str, Any] | None, integrity: dict[str, Any]
) -> dict[str, Any]:
    """Score four equally weighted demo signals; this is not an industry standard."""
    detection_latency = _seconds_between(
        run.get("started_at"), run.get("detected_at")
    ) if run else None
    response_latency = _seconds_between(
        run.get("detected_at"), run.get("responded_at")
    ) if run else None
    detection_points = (
        0.0 if detection_latency is None
        else 25.0 * max(0.0, 1.0 - min(detection_latency, 60.0) / 60.0)
    )
    response_points = (
        0.0 if response_latency is None
        else 25.0 * max(0.0, 1.0 - min(response_latency, 60.0) / 60.0)
    )
    auto_stop_points = 25.0 if run and run.get("automatic_stop") else 0.0
    integrity_points = 25.0 if integrity.get("ok") else 0.0
    parts = {
        "detection_speed": round(detection_points, 1),
        "operator_response": round(response_points, 1),
        "automatic_stop": round(auto_stop_points, 1),
        "audit_integrity": round(integrity_points, 1),
    }
    return {
        "score": int(round(sum(parts.values()))),
        "maximum": 100,
        "breakdown": parts,
        "formula": (
            "25 points per category. Detection and response each lose "
            "25/60 points per second, reaching zero at 60 seconds. "
            "Automatic stop and intact audit chain earn 25 points each."
        ),
        "is_industry_standard": False,
    }
