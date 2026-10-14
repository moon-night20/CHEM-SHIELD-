"""
CHEM-SHIELD Part 4 — input validation.

The correlation engine should not crash on messy detector output.
This module checks each event and either:
- returns a clean AnomalyEvent, or
- records a ValidationError explaining what was wrong.

Risk Engine inputs (scores, IDs, criticality) are checked separately
by RiskInputValidator so correlation rules stay out of risk scoring.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, List, Tuple

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

    def validate_one(self, raw_event: Any, index: int = 0) -> AnomalyEvent:
        """
        Validate a single event.

        Raises ValueError if the event is not usable.
        """
        if not isinstance(raw_event, dict):
            raise ValueError("Event must be a dictionary/object.")

        missing = [field for field in REQUIRED_FIELDS if field not in raw_event]
        if missing:
            raise ValueError(f"Missing required field(s): {', '.join(missing)}")

        timestamp = self._parse_timestamp(raw_event["timestamp"])
        asset_id = self._parse_asset_id(raw_event["asset_id"])
        event_type = self._parse_event_type(raw_event["event_type"])
        anomaly_score = self._parse_anomaly_score(raw_event["anomaly_score"])

        return AnomalyEvent(
            timestamp=timestamp,
            asset_id=asset_id,
            event_type=event_type,
            anomaly_score=anomaly_score,
        )

    def validate_many(
        self, raw_events: List[Any]
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
                valid_events.append(self.validate_one(raw_event, index=index))
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
            # datetime.fromisoformat understands: 2026-09-18T09:31:01
            return datetime.fromisoformat(value)
        except ValueError:
            raise ValueError(
                f"Invalid timestamp '{value}'. Use ISO-8601, for example 2026-09-18T09:31:01."
            )

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
        score = float(value)
        if score < 0.0 or score > 1.0:
            raise ValueError(
                f"anomaly_score {score} is outside the allowed range 0.0–1.0."
            )
        return score


class RiskValidationError(ValueError):
    """Raised when a correlated incident cannot be scored."""


class RiskInputValidator:
    """
    Checks Risk Engine inputs.

    This is separate from EventValidator on purpose:
    event validation belongs to correlation; score validation belongs to risk.
    """

    def require_id(self, value: Any, field_name: str) -> str:
        if value is None or (isinstance(value, str) and not value.strip()):
            raise RiskValidationError(f"{field_name} must exist and must not be empty.")
        if not isinstance(value, str):
            raise RiskValidationError(f"{field_name} must be a non-empty string.")
        return value.strip()

    def validate_score(self, value: Any, field_name: str) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise RiskValidationError(f"{field_name} must be a number between 0.0 and 1.0.")
        score = float(value)
        if score < 0.0 or score > 1.0:
            raise RiskValidationError(
                f"{field_name} {score} is outside the allowed range 0.0–1.0."
            )
        return score
