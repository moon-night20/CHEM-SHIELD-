"""
CHEM-SHIELD Part 4 — input validation.

The correlation engine should not crash on messy detector output.
This module checks each event and either:
- returns a clean AnomalyEvent, or
- records a ValidationError explaining what was wrong.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, List, Tuple

try:
    from .models import ALLOWED_EVENT_TYPES, AnomalyEvent
except ImportError:
    from models import ALLOWED_EVENT_TYPES, AnomalyEvent


REQUIRED_FIELDS = ("timestamp", "asset_id", "event_type", "anomaly_score")


@dataclass
class ValidationError:
    """One problem found in one raw event."""

    index: int
    message: str
    raw_event: Any


class EventValidator:
    """Validate raw dictionaries coming from network / physical detectors."""

    def validate_one(
        self, raw_event: Any, index: int = 0, require_anomaly_score: bool = True
    ) -> AnomalyEvent:
        """
        Validate a single event.

        Raises ValueError if the event is not usable.
        """
        if not isinstance(raw_event, dict):
            raise ValueError("Event must be a dictionary/object.")

        required_fields = REQUIRED_FIELDS if require_anomaly_score else REQUIRED_FIELDS[:-1]
        missing = [field for field in required_fields if field not in raw_event]
        if missing:
            raise ValueError(f"Missing required field(s): {', '.join(missing)}")

        timestamp = self._parse_timestamp(raw_event["timestamp"])
        asset_id = self._parse_asset_id(raw_event["asset_id"])
        event_type = self._parse_event_type(raw_event["event_type"])
        anomaly_score = (
            self._parse_anomaly_score(raw_event.get("anomaly_score"))
            if raw_event.get("anomaly_score") is not None
            else None
        )

        return AnomalyEvent(
            timestamp=timestamp,
            asset_id=asset_id,
            event_type=event_type,
            anomaly_score=anomaly_score,
            event_id=self._optional_string(raw_event.get("event_id"), "event_id"),
            source=self._optional_string(raw_event.get("source"), "source"),
            severity=self._optional_string(raw_event.get("severity"), "severity"),
            evidence=raw_event.get("evidence"),
            details={
                key: value
                for key, value in raw_event.items()
                if key not in {
                    "timestamp", "asset_id", "event_type", "anomaly_score",
                    "event_id", "source", "severity", "evidence",
                }
            },
        )

    def validate_many(
        self, raw_events: List[Any], require_anomaly_score: bool = True
    ) -> Tuple[List[AnomalyEvent], List[ValidationError]]:
        """
        Validate a list of events.

        Valid events are returned.
        Invalid events are skipped and listed in errors so the rest can still run.
        """
        valid_events: List[AnomalyEvent] = []
        errors: List[ValidationError] = []

        if not isinstance(raw_events, list):
            raise TypeError("Input must be a list of event dictionaries.")

        for index, raw_event in enumerate(raw_events):
            try:
                valid_events.append(
                    self.validate_one(
                        raw_event,
                        index=index,
                        require_anomaly_score=require_anomaly_score,
                    )
                )
            except ValueError as exc:
                errors.append(
                    ValidationError(
                        index=index,
                        message=str(exc),
                        raw_event=raw_event,
                    )
                )

        return valid_events, errors

    def _parse_timestamp(self, value: Any) -> datetime:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("timestamp must be a non-empty ISO-8601 string.")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError(
                f"Invalid timestamp '{value}'. Use ISO-8601, for example 2026-09-18T09:31:01."
            )
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _parse_asset_id(self, value: Any) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("asset_id must be a non-empty string.")
        return value.strip()

    def _parse_event_type(self, value: Any) -> str:
        if not isinstance(value, str):
            raise ValueError("event_type must be a string.")
        event_type = value.strip().lower()
        if event_type not in ALLOWED_EVENT_TYPES:
            raise ValueError(
                f"Unknown event_type '{value}'. Allowed types: {', '.join(ALLOWED_EVENT_TYPES)}."
            )
        return event_type

    def _parse_anomaly_score(self, value: Any) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("anomaly_score must be a number between 0.0 and 1.0.")
        try:
            score = float(value)
        except OverflowError as exc:
            raise ValueError("anomaly_score must be finite and within 0.0–1.0.") from exc
        if score != score or score in (float("inf"), float("-inf")) or score < 0.0 or score > 1.0:
            raise ValueError(
                f"anomaly_score {score} must be finite and within 0.0–1.0."
            )
        return score

    @staticmethod
    def _optional_string(value: Any, field: str) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} must be a non-empty string when provided.")
        return value.strip()
