"""
CHEM-SHIELD Part 4 — experimental Risk Engine settings.

These numbers are project parameters for CHEM-SHIELD.
They are NOT claimed to be official cybersecurity standards.

Change the values here (or pass a RiskConfig object) instead of
hard-coding weights and thresholds inside the calculation code.
"""

from __future__ import annotations

from dataclasses import dataclass


# How much each anomaly type contributes to the weighted base risk.
# These two weights must add up to 1.0.
NETWORK_WEIGHT = 0.40
PHYSICAL_WEIGHT = 0.60

# Experimental risk-level boundaries.
# score < LOW_THRESHOLD              → LOW
# LOW_THRESHOLD <= score < MEDIUM    → MEDIUM
# MEDIUM_THRESHOLD <= score < HIGH   → HIGH
# score >= HIGH_THRESHOLD            → CRITICAL
LOW_THRESHOLD = 0.30
MEDIUM_THRESHOLD = 0.60
HIGH_THRESHOLD = 0.80

# Used when the caller does not provide an asset criticality.
DEFAULT_CRITICALITY = 1.0

# How many decimal places to keep on published risk numbers.
RISK_DECIMAL_PLACES = 3

# Tiny allowance for floating-point rounding when checking weight sums.
WEIGHT_SUM_TOLERANCE = 1e-9


class RiskConfigurationError(ValueError):
    """Raised when Risk Engine settings are invalid."""


@dataclass
class RiskConfig:
    """
    All tunable Risk Engine parameters in one place.

    Create a custom instance to try different experimental values
    without editing the rest of the project.
    """

    network_weight: float = NETWORK_WEIGHT
    physical_weight: float = PHYSICAL_WEIGHT
    low_threshold: float = LOW_THRESHOLD
    medium_threshold: float = MEDIUM_THRESHOLD
    high_threshold: float = HIGH_THRESHOLD
    default_criticality: float = DEFAULT_CRITICALITY
    decimal_places: int = RISK_DECIMAL_PLACES

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        for name, value in (
            ("network_weight", self.network_weight),
            ("physical_weight", self.physical_weight),
            ("low_threshold", self.low_threshold),
            ("medium_threshold", self.medium_threshold),
            ("high_threshold", self.high_threshold),
            ("default_criticality", self.default_criticality),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise RiskConfigurationError(f"{name} must be a number between 0.0 and 1.0.")
            number = float(value)
            if number < 0.0 or number > 1.0:
                raise RiskConfigurationError(
                    f"{name} {number} is outside the allowed range 0.0–1.0."
                )
            setattr(self, name, number)

        weight_sum = self.network_weight + self.physical_weight
        if abs(weight_sum - 1.0) > WEIGHT_SUM_TOLERANCE:
            raise RiskConfigurationError(
                "network_weight + physical_weight must equal 1.0. "
                f"Got {self.network_weight} + {self.physical_weight} = {weight_sum}."
            )

        if not (
            0.0
            <= self.low_threshold
            < self.medium_threshold
            < self.high_threshold
            <= 1.0
        ):
            raise RiskConfigurationError(
                "Thresholds must satisfy "
                "0.0 <= LOW_THRESHOLD < MEDIUM_THRESHOLD < HIGH_THRESHOLD <= 1.0."
            )

        if not isinstance(self.decimal_places, int) or self.decimal_places < 0:
            raise RiskConfigurationError("decimal_places must be a non-negative integer.")


def default_risk_config() -> RiskConfig:
    """Return a fresh copy of the experimental CHEM-SHIELD defaults."""
    return RiskConfig()
