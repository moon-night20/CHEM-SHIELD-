"""Tests for secure token sharing in the connected fixture demo."""

from unittest.mock import patch

import pytest

from scripts import run_pipeline_demo
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


def test_hmi_readiness_error_says_to_start_hmi_first(monkeypatch) -> None:
    clock = iter((0.0, 11.0))
    monkeypatch.setattr(run_pipeline_demo.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(run_pipeline_demo.time, "sleep", lambda _delay: None)
    monkeypatch.setattr(
        run_pipeline_demo,
        "_get_risk_summary",
        lambda _url: (_ for _ in ()).throw(ConnectionError("not listening")),
    )

    with pytest.raises(RuntimeError, match="Start the HMI first"):
        run_pipeline_demo._wait_for_hmi("http://127.0.0.1:15000/api/risk", None)


def test_demo_token_error_names_export_command(monkeypatch) -> None:
    monkeypatch.setattr(run_pipeline_demo, "_get_risk_summary", lambda _url: {})
    monkeypatch.delenv("CHEM_SHIELD_INGEST_TOKEN", raising=False)
    monkeypatch.setattr(run_pipeline_demo.os, "environ", {})

    with patch.object(run_pipeline_demo, "_risk_url", return_value=("http://127.0.0.1/risk", 80)):
        with patch.object(run_pipeline_demo, "_correlated_incidents", return_value=[]):
            with pytest.raises(RuntimeError, match="Export CHEM_SHIELD_INGEST_TOKEN"):
                run_pipeline_demo.main([])
