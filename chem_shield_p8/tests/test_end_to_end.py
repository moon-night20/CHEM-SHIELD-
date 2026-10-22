from __future__ import annotations

import pytest

from chem_shield_p8.attack_lab import load_scenarios
from chem_shield_p8.dashboard.app import DashboardRuntime
from chem_shield_p8.reports import generate_incident_report


@pytest.mark.parametrize("scenario", load_scenarios(), ids=lambda item: item["id"])
def test_scenario_runs_through_runtime_and_exports_report(scenario, tmp_path):
    runtime = DashboardRuntime(data_dir=tmp_path, read_existing_hmi=False)
    snapshot = runtime.start_scenario(scenario["id"])

    while not snapshot["scenario"]["complete"]:
        snapshot = runtime.step_scenario()

    result = snapshot["scenario"]["result"]
    assert result["status"] == "COMPLETE"
    assert set(scenario["expected_rules"]).issubset(result["detected_rules"])
    assert result["missed_steps"] == []
    assert result["false_positive_count"] == 0
    assert snapshot["alerts"]
    assert snapshot["scenario"]["playing"] is False
    assert snapshot["sis"]["chain_integrity"]["ok"] is True
    assert snapshot["response"]["log_integrity"]["ok"] is True

    files = generate_incident_report(snapshot, tmp_path / "reports")
    report_html = files.html_path.read_text(encoding="utf-8")
    assert scenario["name"] in report_html
    assert scenario["expected_rules"][0] in report_html
    assert files.pdf_path.read_bytes().startswith(b"%PDF-")
