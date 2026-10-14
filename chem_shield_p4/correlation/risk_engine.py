"""
CHEM-SHIELD Part 4 — Risk Engine (placeholder).

Correlation and risk are kept separate on purpose.

This file is the interface for a later version.
Do NOT put a risk formula here yet.
The correlation engine should finish first and pass Incident objects in.
"""

from __future__ import annotations

from typing import List

from models import Incident


class RiskEngine:
    """
    Later this class will calculate a final risk score per incident.

    Expected future input: a correlated Incident (from correlation_engine.py).
    Expected future output: a risk result attached to that incident.
    """

    def calculate_risk(self, incident: Incident) -> None:
        """Not implemented in Part 4 Version 1."""
        raise NotImplementedError(
            "Risk scoring is not part of this version. "
            "Pass correlated Incident objects here in a later update."
        )

    def calculate_risks(self, incidents: List[Incident]) -> None:
        """Not implemented in Part 4 Version 1."""
        raise NotImplementedError(
            "Batch risk scoring is not part of this version. "
            "The correlation engine output is ready to be consumed later."
        )
