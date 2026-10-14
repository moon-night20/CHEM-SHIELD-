"""
CHEM-SHIELD Part 4 — data models.

This module only describes the *shape* of data.
It does not detect anomalies and it does not calculate risk.

Other team members send us anomaly events. We turn related events
into an Incident. The Risk Engine later fills in a RiskAssessment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional


# The only event types this version of the correlation engine understands.
ALLOWED_EVENT_TYPES = ("network", "physical")


@dataclass
class AnomalyEvent:
    """One anomaly reported by a detector (network OR physical)."""

    timestamp: datetime
    asset_id: str
    event_type: str
    anomaly_score: float

    def to_dict(self) -> dict:
        """Convert to a JSON-friendly dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "asset_id": self.asset_id,
            "event_type": self.event_type,
            "anomaly_score": self.anomaly_score,
        }


@dataclass
class Incident:
    """
    A group of anomaly events that look like one incident.

    Version 1 rules (simple and explainable):
    - same asset_id
    - each next event is within the correlation time window of the previous event
    """

    incident_id: str
    asset_id: str
    events: List[AnomalyEvent] = field(default_factory=list)

    @property
    def start_time(self) -> datetime:
        return self.events[0].timestamp

    @property
    def end_time(self) -> datetime:
        return self.events[-1].timestamp

    @property
    def duration(self) -> timedelta:
        return self.end_time - self.start_time

    @property
    def duration_seconds(self) -> float:
        return self.duration.total_seconds()

    @property
    def number_of_events(self) -> int:
        return len(self.events)

    @property
    def network_present(self) -> bool:
        return any(event.event_type == "network" for event in self.events)

    @property
    def physical_present(self) -> bool:
        return any(event.event_type == "physical" for event in self.events)

    @property
    def max_network_score(self) -> Optional[float]:
        scores = [
            event.anomaly_score
            for event in self.events
            if event.event_type == "network"
        ]
        return max(scores) if scores else None

    @property
    def max_physical_score(self) -> Optional[float]:
        scores = [
            event.anomaly_score
            for event in self.events
            if event.event_type == "physical"
        ]
        return max(scores) if scores else None

    def add_event(self, event: AnomalyEvent) -> None:
        """Append one event. Events should already be in time order."""
        if event.asset_id != self.asset_id:
            raise ValueError(
                f"Cannot add event for asset {event.asset_id} "
                f"to incident for asset {self.asset_id}."
            )
        self.events.append(event)

    def to_dict(self) -> dict:
        """Convert to a JSON-friendly dictionary for later modules (risk, export)."""
        return {
            "incident_id": self.incident_id,
            "asset_id": self.asset_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "duration_seconds": self.duration_seconds,
            "number_of_events": self.number_of_events,
            "network_present": self.network_present,
            "physical_present": self.physical_present,
            "max_network_score": self.max_network_score,
            "max_physical_score": self.max_physical_score,
            "events": [event.to_dict() for event in self.events],
        }


@dataclass
class RiskAssessment:
    """
    Transparent risk result for one correlated incident.

    The Risk Engine fills this in. The correlation engine does not.
    """

    incident_id: str
    asset_id: str
    network_score: float
    physical_score: float
    network_weight: float
    physical_weight: float
    asset_criticality: float
    base_risk: float
    final_risk: float
    risk_level: str
    explanation: str

    def to_dict(self) -> dict:
        """JSON-friendly copy of the assessment, including the explanation."""
        return {
            "incident_id": self.incident_id,
            "asset_id": self.asset_id,
            "network_score": self.network_score,
            "physical_score": self.physical_score,
            "network_weight": self.network_weight,
            "physical_weight": self.physical_weight,
            "asset_criticality": self.asset_criticality,
            "base_risk": self.base_risk,
            "final_risk": self.final_risk,
            "risk_level": self.risk_level,
            "explanation": self.explanation,
        }
