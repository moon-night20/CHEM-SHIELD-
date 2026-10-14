"""Existing experimental risk weights and classification thresholds."""

from __future__ import annotations

import math
from dataclasses import dataclass

NETWORK_WEIGHT = 0.40
PHYSICAL_WEIGHT = 0.60
LOW_THRESHOLD = 0.30
MEDIUM_THRESHOLD = 0.60
HIGH_THRESHOLD = 0.80
DEFAULT_CRITICALITY = 1.0
RISK_DECIMAL_PLACES = 3
WEIGHT_SUM_TOLERANCE = 1e-9


class RiskConfigurationError(ValueError):
    """Risk engine configuration is invalid."""


@dataclass
class RiskConfig:
    network_weight: float = NETWORK_WEIGHT
    physical_weight: float = PHYSICAL_WEIGHT
    low_threshold: float = LOW_THRESHOLD
    medium_threshold: float = MEDIUM_THRESHOLD
    high_threshold: float = HIGH_THRESHOLD
    default_criticality: float = DEFAULT_CRITICALITY
    decimal_places: int = RISK_DECIMAL_PLACES

    def __post_init__(self) -> None:
        for name in (
            "network_weight",
            "physical_weight",
            "low_threshold",
            "medium_threshold",
            "high_threshold",
            "default_criticality",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise RiskConfigurationError(f"{name} must be a finite number between 0.0 and 1.0.")
            try:
                value = float(value)
            except OverflowError as exc:
                raise RiskConfigurationError(
                    f"{name} must be a finite number between 0.0 and 1.0."
                ) from exc
            if not math.isfinite(value) or not 0.0 <= value <= 1.0:
                raise RiskConfigurationError(f"{name} must be a finite number between 0.0 and 1.0.")
            setattr(self, name, value)
        if abs(self.network_weight + self.physical_weight - 1.0) > WEIGHT_SUM_TOLERANCE:
            raise RiskConfigurationError("network_weight + physical_weight must equal 1.0.")
        if not 0.0 <= self.low_threshold < self.medium_threshold < self.high_threshold <= 1.0:
            raise RiskConfigurationError(
                "Thresholds must satisfy 0.0 <= LOW_THRESHOLD < MEDIUM_THRESHOLD < HIGH_THRESHOLD <= 1.0."
            )
        if isinstance(self.decimal_places, bool) or not isinstance(self.decimal_places, int) or self.decimal_places < 0:
            raise RiskConfigurationError("decimal_places must be a non-negative integer.")


def default_risk_config() -> RiskConfig:
    return RiskConfig()
