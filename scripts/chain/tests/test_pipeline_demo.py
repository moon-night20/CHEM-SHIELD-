"""Tests for secure token sharing in the connected fixture demo."""

from unittest.mock import patch

from scripts.run_pipeline_demo import _demo_environment


def test_temporary_demo_hmi_and_publishers_share_a_generated_token() -> None:
    with patch("scripts.run_pipeline_demo.secrets.token_urlsafe", return_value="demo-token"):
        environment = _demo_environment({}, temporary_hmi=True)

    assert environment["CHEM_SHIELD_INGEST_TOKEN"] == "demo-token"


def test_demo_preserves_an_explicit_ingest_token() -> None:
    environment = _demo_environment(
        {"CHEM_SHIELD_INGEST_TOKEN": "configured-demo-token"},
        temporary_hmi=True,
    )

    assert environment["CHEM_SHIELD_INGEST_TOKEN"] == "configured-demo-token"
