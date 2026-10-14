"""Thin compatibility re-export for the canonical Part 4 risk engine."""

from chem_shield_p4.risk_engine import RiskConfig, RiskConfigurationError, RiskEngine, RiskValidationError, default_risk_config

__all__ = [
    "RiskConfig",
    "RiskConfigurationError",
    "RiskEngine",
    "RiskValidationError",
    "default_risk_config",
]
