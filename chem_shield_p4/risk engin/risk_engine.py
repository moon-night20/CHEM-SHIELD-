"""
CHEM-SHIELD Part 4 — Risk Engine.

This module does NOT group events into incidents.
The correlation engine already did that work.

Input:  one correlated incident + asset criticality
Output: a transparent, deterministic risk assessment (no AI / no ML)

Experimental formula:
    base_risk  = (network_weight × network_score)
               + (physical_weight × physical_score)
    final_risk = base_risk × asset_criticality
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Union

from config import RiskConfig, default_risk_config
from models import Incident, RiskAssessment
from validator import RiskInputValidator, RiskValidationError


# A number, a {asset_id, criticality} record, or a map of asset_id → criticality.
CriticalityInput = Union[int, float, Mapping[str, Any], None]


class RiskEngine:
    """Score a correlated incident using experimental CHEM-SHIELD weights."""

    def __init__(self, config: Optional[RiskConfig] = None) -> None:
        # Validating config here means bad weights fail at construction time.
        self.config = config if config is not None else default_risk_config()
        self.validator = RiskInputValidator()

    def calculate_risk(
        self,
        correlated_incident: Union[Incident, Mapping[str, Any]],
        asset_criticality: CriticalityInput = None,
    ) -> RiskAssessment:
        """
        Calculate risk for one correlated incident.

        Typical usage after correlation:

            incidents, _ = correlation_engine.correlate(events)
            assessment = risk_engine.calculate_risk(incidents[0], asset_criticality)
        """
        payload = self._incident_to_payload(correlated_incident)
        incident_id = self.validator.require_id(payload.get("incident_id"), field_name="incident_id")
        asset_id = self.validator.require_id(payload.get("asset_id"), field_name="asset_id")

        network_score = self._score_from_incident(payload, kind="network")
        physical_score = self._score_from_incident(payload, kind="physical")
        criticality = self._resolve_criticality(asset_id, asset_criticality)

        self.validator.validate_score(network_score, field_name="network_score")
        self.validator.validate_score(physical_score, field_name="physical_score")
        self.validator.validate_score(criticality, field_name="asset_criticality")

        network_contribution = self.config.network_weight * network_score
        physical_contribution = self.config.physical_weight * physical_score
        base_risk = network_contribution + physical_contribution
        final_risk = base_risk * criticality

        places = self.config.decimal_places
        network_contribution = round(network_contribution, places)
        physical_contribution = round(physical_contribution, places)
        base_risk = round(base_risk, places)
        final_risk = round(final_risk, places)
        network_score = round(float(network_score), places)
        physical_score = round(float(physical_score), places)
        criticality = round(float(criticality), places)

        risk_level = self._classify(final_risk)
        explanation = self._explain(
            network_contribution=network_contribution,
            physical_contribution=physical_contribution,
            criticality=criticality,
            final_risk=final_risk,
            risk_level=risk_level,
        )

        return RiskAssessment(
            incident_id=incident_id,
            asset_id=asset_id,
            network_score=network_score,
            physical_score=physical_score,
            network_weight=self.config.network_weight,
            physical_weight=self.config.physical_weight,
            asset_criticality=criticality,
            base_risk=base_risk,
            final_risk=final_risk,
            risk_level=risk_level,
            explanation=explanation,
        )

    def calculate_risks(
        self,
        incidents: List[Union[Incident, Mapping[str, Any]]],
        asset_criticality: CriticalityInput = None,
    ) -> List[RiskAssessment]:
        """Score many correlated incidents with the same criticality lookup."""
        return [
            self.calculate_risk(incident, asset_criticality=asset_criticality)
            for incident in incidents
        ]

    def _incident_to_payload(
        self, correlated_incident: Union[Incident, Mapping[str, Any]]
    ) -> Dict[str, Any]:
        if isinstance(correlated_incident, Incident):
            return correlated_incident.to_dict()
        if isinstance(correlated_incident, Mapping):
            return dict(correlated_incident)
        raise RiskValidationError(
            "Correlated incident must be an Incident object or a dictionary."
        )

    def _score_from_incident(self, payload: Mapping[str, Any], kind: str) -> float:
        """
        Read one anomaly score from a correlated incident.

        Missing scores (only one detector fired) become 0.0 so the formula
        still works: that source simply contributes nothing.
        """
        explicit_key = f"{kind}_score"
        max_key = f"max_{kind}_score"
        present_key = f"{kind}_present"

        if explicit_key in payload and payload[explicit_key] is not None:
            return payload[explicit_key]
        if max_key in payload and payload[max_key] is not None:
            return payload[max_key]
        if payload.get(present_key) is False:
            return 0.0
        return 0.0

    def _resolve_criticality(self, asset_id: str, asset_criticality: CriticalityInput) -> float:
        if asset_criticality is None:
            return self.config.default_criticality

        if isinstance(asset_criticality, bool) or not isinstance(
            asset_criticality, (int, float, Mapping)
        ):
            raise RiskValidationError(
                "asset_criticality must be a number 0.0–1.0, "
                "a record like {'asset_id': 'PLC_01', 'criticality': 1.0}, "
                "or a map of asset_id to criticality."
            )

        if isinstance(asset_criticality, (int, float)):
            return float(asset_criticality)

        if "criticality" in asset_criticality:
            provided_asset = asset_criticality.get("asset_id")
            if provided_asset is not None and str(provided_asset).strip() != asset_id:
                raise RiskValidationError(
                    f"Asset criticality record is for '{provided_asset}', "
                    f"but the incident asset is '{asset_id}'."
                )
            return asset_criticality["criticality"]

        if asset_id in asset_criticality:
            return asset_criticality[asset_id]

        return self.config.default_criticality

    def _classify(self, final_risk: float) -> str:
        if final_risk < self.config.low_threshold:
            return "LOW"
        if final_risk < self.config.medium_threshold:
            return "MEDIUM"
        if final_risk < self.config.high_threshold:
            return "HIGH"
        return "CRITICAL"

    def _explain(
        self,
        network_contribution: float,
        physical_contribution: float,
        criticality: float,
        final_risk: float,
        risk_level: str,
    ) -> str:
        places = self.config.decimal_places
        return (
            f"Network anomaly contributed {network_contribution:.{places}f} to the risk. "
            f"Physical anomaly contributed {physical_contribution:.{places}f} to the risk. "
            f"Asset criticality was {criticality:.{places}f}. "
            f"Final risk score was {final_risk:.{places}f}. "
            f"Risk level: {risk_level}."
        )
