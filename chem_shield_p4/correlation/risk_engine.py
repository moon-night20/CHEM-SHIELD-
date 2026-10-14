"""Compatibility imports for the canonical Part 4 risk engine."""

try:
    from ..risk_engine.config import RiskConfig, RiskConfigurationError, default_risk_config
    from ..risk_engine.risk_engine import RiskEngine, RiskValidationError
except ImportError:
    from chem_shield_p4.risk_engine.config import RiskConfig, RiskConfigurationError, default_risk_config
    from chem_shield_p4.risk_engine.risk_engine import RiskEngine, RiskValidationError

__all__ = [
    "RiskConfig",
    "RiskConfigurationError",
    "RiskEngine",
    "RiskValidationError",
    "default_risk_config",
]
