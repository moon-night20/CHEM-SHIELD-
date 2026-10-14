"""
CHEM-SHIELD Part 4 — Correlation Engine.

This module does NOT detect network or physical anomalies.
It only groups already-detected events into incidents.

Version 1 rules (no AI / no machine learning):
1. Same asset_id only.
2. After sorting by time, an event joins the current incident for that asset
   if it is within the correlation time window of the *previous* event.
3. Default window = 10 seconds (configurable).
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Dict, List, Tuple

from models import AnomalyEvent, Incident
from validator import EventValidator, ValidationError


DEFAULT_TIME_WINDOW_SECONDS = 10.0


class CorrelationEngine:
    """Rule-based correlator for network + physical anomaly events."""

    def __init__(self, time_window_seconds: float = DEFAULT_TIME_WINDOW_SECONDS) -> None:
        if time_window_seconds <= 0:
            raise ValueError("time_window_seconds must be greater than 0.")
        self.time_window_seconds = float(time_window_seconds)
        self.validator = EventValidator()
        self._incident_counter = 0

    def correlate(
        self, raw_events: List[Any]
    ) -> Tuple[List[Incident], List[ValidationError]]:
        """
        Main entry point for other team members.

        Input: list of event dictionaries from the detectors.
        Output: (incidents, validation_errors)
        """
        valid_events, errors = self.validator.validate_many(raw_events)
        incidents = self.correlate_events(valid_events)
        return incidents, errors

    def correlate_events(self, events: List[AnomalyEvent]) -> List[Incident]:
        """
        Group already-validated events into incidents.

        Events are sorted by timestamp first, even if they already look ordered.
        Different assets never share an incident.
        """
        if not events:
            return []

        # Safety sort: detectors might not always send events in time order.
        sorted_events = sorted(events, key=lambda event: (event.timestamp, event.asset_id))

        open_incidents: Dict[str, Incident] = {}
        closed_incidents: List[Incident] = []
        window = timedelta(seconds=self.time_window_seconds)

        for event in sorted_events:
            current = open_incidents.get(event.asset_id)

            if current is None:
                open_incidents[event.asset_id] = self._new_incident(event)
                continue

            gap = event.timestamp - current.end_time
            if gap <= window:
                # Same asset + close enough in time → same incident.
                current.add_event(event)
            else:
                # Gap is too large → close the old incident and start a new one.
                closed_incidents.append(current)
                open_incidents[event.asset_id] = self._new_incident(event)

        closed_incidents.extend(open_incidents.values())

        # Keep output stable: earliest start time first.
        closed_incidents.sort(key=lambda incident: (incident.start_time, incident.asset_id))
        return closed_incidents

    def _new_incident(self, first_event: AnomalyEvent) -> Incident:
        self._incident_counter += 1
        incident_id = f"INC-{self._incident_counter:04d}"
        incident = Incident(incident_id=incident_id, asset_id=first_event.asset_id)
        incident.add_event(first_event)
        return incident


def incidents_to_dicts(incidents: List[Incident]) -> List[dict]:
    """Helper so other modules can export incidents as JSON."""
    return [incident.to_dict() for incident in incidents]
