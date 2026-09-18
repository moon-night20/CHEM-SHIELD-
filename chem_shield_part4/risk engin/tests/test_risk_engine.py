"""Unit tests for the experimental CHEM-SHIELD Risk Engine."""

import sys
import unittest
from pathlib import Path

# Allow "python -m unittest discover -s tests" from this folder in VS Code.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from config import RiskConfig, RiskConfigurationError
from correlation_engine import CorrelationEngine
from risk_engine import RiskEngine
from validator import RiskValidationError


def incident_dict(
    network_score: float,
    physical_score: float,
    incident_id: str = "INC_001",
    asset_id: str = "PLC_01",
) -> dict:
    return {
        "incident_id": incident_id,
        "asset_id": asset_id,
        "network_score": network_score,
        "physical_score": physical_score,
    }


class RiskEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = RiskEngine()

    def test_1_network_and_physical_is_critical(self) -> None:
        assessment = self.engine.calculate_risk(
            incident_dict(network_score=0.70, physical_score=0.91),
            asset_criticality=1.0,
        )

        self.assertEqual(assessment.base_risk, 0.826)
        self.assertEqual(assessment.final_risk, 0.826)
        self.assertEqual(assessment.risk_level, "CRITICAL")
        self.assertIn("0.280", assessment.explanation)
        self.assertIn("0.546", assessment.explanation)

    def test_2_network_only_is_low(self) -> None:
        assessment = self.engine.calculate_risk(
            incident_dict(network_score=0.70, physical_score=0.0),
            asset_criticality=1.0,
        )

        self.assertEqual(assessment.final_risk, 0.280)
        self.assertEqual(assessment.risk_level, "LOW")

    def test_3_physical_only_is_medium(self) -> None:
        assessment = self.engine.calculate_risk(
            incident_dict(network_score=0.0, physical_score=0.80),
            asset_criticality=1.0,
        )

        self.assertEqual(assessment.final_risk, 0.480)
        self.assertEqual(assessment.risk_level, "MEDIUM")

    def test_4_lower_criticality_reduces_final_risk(self) -> None:
        assessment = self.engine.calculate_risk(
            incident_dict(network_score=0.70, physical_score=0.90),
            asset_criticality=0.5,
        )

        self.assertEqual(assessment.base_risk, 0.820)
        self.assertEqual(assessment.final_risk, 0.410)
        self.assertEqual(assessment.risk_level, "MEDIUM")

    def test_5_invalid_network_score_is_rejected(self) -> None:
        with self.assertRaises(RiskValidationError) as ctx:
            self.engine.calculate_risk(
                incident_dict(network_score=1.5, physical_score=0.50),
                asset_criticality=1.0,
            )
        self.assertIn("network_score", str(ctx.exception))

    def test_6_invalid_physical_score_is_rejected(self) -> None:
        with self.assertRaises(RiskValidationError) as ctx:
            self.engine.calculate_risk(
                incident_dict(network_score=0.50, physical_score=-0.2),
                asset_criticality=1.0,
            )
        self.assertIn("physical_score", str(ctx.exception))

    def test_7_weights_that_do_not_add_to_one_are_rejected(self) -> None:
        with self.assertRaises(RiskConfigurationError) as ctx:
            RiskConfig(network_weight=0.40, physical_weight=0.40)
        self.assertIn("must equal 1.0", str(ctx.exception))

    def test_missing_incident_id_is_rejected(self) -> None:
        payload = incident_dict(0.70, 0.91)
        del payload["incident_id"]
        with self.assertRaises(RiskValidationError) as ctx:
            self.engine.calculate_risk(payload, asset_criticality=1.0)
        self.assertIn("incident_id", str(ctx.exception))

    def test_missing_asset_id_is_rejected(self) -> None:
        payload = incident_dict(0.70, 0.91)
        payload["asset_id"] = "  "
        with self.assertRaises(RiskValidationError) as ctx:
            self.engine.calculate_risk(payload, asset_criticality=1.0)
        self.assertIn("asset_id", str(ctx.exception))

    def test_accepts_correlation_engine_incident_objects(self) -> None:
        events = [
            {
                "timestamp": "2026-09-18T09:31:01",
                "asset_id": "PLC_01",
                "event_type": "network",
                "anomaly_score": 0.70,
            },
            {
                "timestamp": "2026-09-18T09:31:04",
                "asset_id": "PLC_01",
                "event_type": "physical",
                "anomaly_score": 0.82,
            },
            {
                "timestamp": "2026-09-18T09:31:08",
                "asset_id": "PLC_01",
                "event_type": "physical",
                "anomaly_score": 0.91,
            },
        ]
        incidents, errors = CorrelationEngine().correlate(events)
        self.assertEqual(errors, [])

        assessment = self.engine.calculate_risk(
            incidents[0],
            asset_criticality={"asset_id": "PLC_01", "criticality": 1.0},
        )

        self.assertEqual(assessment.final_risk, 0.826)
        self.assertEqual(assessment.risk_level, "CRITICAL")
        self.assertEqual(assessment.network_score, 0.700)
        self.assertEqual(assessment.physical_score, 0.910)


if __name__ == "__main__":
    unittest.main()
