"""Compatibility shim; use chem_shield_p4.risk_engine for new imports."""

from chem_shield_p4.risk_engine.config import RiskConfig, default_risk_config
from chem_shield_p4.risk_engine.models import RiskAssessment
from chem_shield_p4.risk_engine.risk_engine import RiskEngine, RiskValidationError

__all__ = [
    "RiskAssessment",
    "RiskConfig",
    "RiskEngine",
    "RiskValidationError",
    "default_risk_config",
]
