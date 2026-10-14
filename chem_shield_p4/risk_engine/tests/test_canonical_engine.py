"""Boundary and finite-value tests for the canonical risk engine."""

import math
import unittest

from chem_shield_p4.risk_engine import RiskConfig, RiskEngine
from chem_shield_p4.risk_engine.config import RiskConfigurationError
from chem_shield_p4.risk_engine.risk_engine import RiskValidationError


class CanonicalRiskEngineTests(unittest.TestCase):
    def test_threshold_boundaries_remain_backward_compatible(self):
        engine = RiskEngine()
        low = engine.calculate_risk(
            {"incident_id": "a", "asset_id": "p", "network_score": 0.70, "physical_score": 0.0}
        )
        medium = engine.calculate_risk(
            {"incident_id": "b", "asset_id": "p", "network_score": 0.75, "physical_score": 0.0}
        )
        high = engine.calculate_risk(
            {"incident_id": "c", "asset_id": "p", "network_score": 0.0, "physical_score": 1.0}
        )
        critical = engine.calculate_risk(
            {"incident_id": "d", "asset_id": "p", "network_score": 0.5, "physical_score": 1.0}
        )
        self.assertEqual((low.final_risk, low.risk_level), (0.28, "LOW"))
        self.assertEqual((medium.final_risk, medium.risk_level), (0.3, "MEDIUM"))
        self.assertEqual((high.final_risk, high.risk_level), (0.6, "HIGH"))
        self.assertEqual((critical.final_risk, critical.risk_level), (0.8, "CRITICAL"))

    def test_non_finite_scores_and_config_are_rejected(self):
        for invalid in (math.nan, math.inf, -math.inf):
            with self.subTest(score=invalid):
                with self.assertRaises(RiskValidationError):
                    RiskEngine().calculate_risk(
                        {
                            "incident_id": "bad",
                            "asset_id": "p",
                            "network_score": invalid,
                            "physical_score": 0.0,
                        }
                    )
        with self.assertRaises(RiskConfigurationError):
            RiskConfig(network_weight=math.nan)


if __name__ == "__main__":
    unittest.main()
