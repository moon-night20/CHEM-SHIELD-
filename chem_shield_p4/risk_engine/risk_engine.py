"""Canonical transparent risk calculation for correlated incidents."""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any, Dict, List, Optional, Union

from .config import RiskConfig, default_risk_config
from .models import RiskAssessment


class RiskValidationError(ValueError):
    """Correlated incident or score is invalid."""


CriticalityInput = Union[int, float, Mapping[str, Any], None]


class RiskEngine:
    """Apply the established 0-1 weighted formula and threshold boundaries."""

    def __init__(self, config: Optional[RiskConfig] = None) -> None:
        self.config = config or default_risk_config()

    def calculate_risk(
        self,
        correlated_incident: Union[Any, Mapping[str, Any]],
        asset_criticality: CriticalityInput = None,
    ) -> RiskAssessment:
        payload = self._to_payload(correlated_incident)
        incident_id = self._require_id(payload.get("incident_id"), "incident_id")
        asset_id = self._require_id(payload.get("asset_id"), "asset_id")
        network_score = self._extract_score(payload, "network")
        physical_score = self._extract_score(payload, "physical")
        criticality = self._resolve_criticality(asset_id, asset_criticality)
        for name, score in (
            ("network_score", network_score),
            ("physical_score", physical_score),
            ("asset_criticality", criticality),
        ):
            self._validate_score(score, name)

        network_contribution = self.config.network_weight * network_score
        physical_contribution = self.config.physical_weight * physical_score
        base_risk = network_contribution + physical_contribution
        final_risk = base_risk * criticality
        places = self.config.decimal_places
        values = [
            round(float(value), places)
            for value in (
                network_score,
                physical_score,
                criticality,
                network_contribution,
                physical_contribution,
                base_risk,
                final_risk,
            )
        ]
        network_score, physical_score, criticality, net_part, physical_part, base_risk, final_risk = values
        level = self._classify(final_risk)
        explanation = (
            f"Network anomaly contributed {net_part:.{places}f}; "
            f"physical anomaly contributed {physical_part:.{places}f}; "
            f"asset criticality was {criticality:.{places}f}; "
            f"final risk score was {final_risk:.{places}f} on a 0.0-1.0 scale. "
            f"Risk level: {level}."
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
            risk_level=level,
            explanation=explanation,
        )

    def calculate_risks(
        self,
        incidents: List[Union[Any, Mapping[str, Any]]],
        asset_criticality: CriticalityInput = None,
    ) -> List[RiskAssessment]:
        return [
            self.calculate_risk(incident, asset_criticality=asset_criticality)
            for incident in incidents
        ]

    @staticmethod
    def _to_payload(incident: Any) -> Dict[str, Any]:
        if isinstance(incident, Mapping):
            return dict(incident)
        if hasattr(incident, "to_dict"):
            payload = incident.to_dict()
            if isinstance(payload, Mapping):
                return dict(payload)
        raise RiskValidationError("Correlated incident must be a mapping or expose to_dict().")

    @staticmethod
    def _require_id(value: Any, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise RiskValidationError(f"{field} must be a non-empty string.")
        return value.strip()

    @staticmethod
    def _validate_score(value: Any, field: str) -> None:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise RiskValidationError(f"{field} must be a number between 0.0 and 1.0.")
        try:
            score = float(value)
        except OverflowError as exc:
            raise RiskValidationError(
                f"{field} must be a finite number between 0.0 and 1.0."
            ) from exc
        if not math.isfinite(score) or not 0.0 <= score <= 1.0:
            raise RiskValidationError(f"{field} must be a finite number between 0.0 and 1.0.")

    @staticmethod
    def _extract_score(payload: Mapping[str, Any], kind: str) -> float:
        for key in (f"{kind}_score", f"max_{kind}_score"):
            if payload.get(key) is not None:
                return payload[key]
        return 0.0

    def _resolve_criticality(self, asset_id: str, value: CriticalityInput) -> float:
        if value is None:
            return self.config.default_criticality
        if isinstance(value, bool) or not isinstance(value, (int, float, Mapping)):
            raise RiskValidationError("asset_criticality must be a score or asset criticality mapping.")
        if isinstance(value, (int, float)):
            return float(value)
        if "criticality" in value:
            provided_asset = value.get("asset_id")
            if provided_asset is not None and str(provided_asset).strip() != asset_id:
                raise RiskValidationError(
                    f"Asset criticality record is for '{provided_asset}', but incident asset is '{asset_id}'."
                )
            return value["criticality"]
        if asset_id in value:
            return value[asset_id]
        return self.config.default_criticality

    def _classify(self, score: float) -> str:
        if score < self.config.low_threshold:
            return "LOW"
        if score < self.config.medium_threshold:
            return "MEDIUM"
        if score < self.config.high_threshold:
            return "HIGH"
        return "CRITICAL"
