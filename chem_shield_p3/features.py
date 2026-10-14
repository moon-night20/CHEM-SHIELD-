"""Compatibility exports for feature engineering.

New code should import from ``src.features``.
"""

from src.features import (
    BASE_FEATURE_COLUMNS,
    FEATURE_COLUMNS,
    RATE_FEATURE_COLUMNS,
    TelemetryValidationError,
    build_feature_frame,
)

__all__ = [
    "BASE_FEATURE_COLUMNS",
    "FEATURE_COLUMNS",
    "RATE_FEATURE_COLUMNS",
    "TelemetryValidationError",
    "build_feature_frame",
]
