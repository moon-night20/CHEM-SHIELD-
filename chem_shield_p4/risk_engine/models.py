"""Risk result shape emitted by the canonical risk engine."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict


@dataclass
class RiskAssessment:
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

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["score_scale"] = "0.0-1.0"
        return result
