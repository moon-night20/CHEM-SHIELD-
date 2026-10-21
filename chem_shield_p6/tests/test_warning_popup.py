"""Integration checks for the Part 6 warning popup in the operator HMI."""

from pathlib import Path
from unittest.mock import patch

from chem_shield_p1.hmi.app import create_app


def test_warning_popup_assets_are_served_from_part6_and_loaded_by_hmi(tmp_path):
    with patch("chem_shield_p1.hmi.app.DeviceConnection.connect"):
        app = create_app(plc_port=1, database=str(tmp_path / "hmi.db"))
    app.config.update(TESTING=True)
    client = app.test_client()

    page = client.get("/")
    assert page.status_code == 200
    assert b'/p6/static/warning_popup.css' in page.data
    assert b'/p6/static/warning_popup.js' in page.data
    assert b'id="warning-toasts"' in page.data

    stylesheet = client.get("/p6/static/warning_popup.css")
    script = client.get("/p6/static/warning_popup.js")
    assert stylesheet.status_code == 200
    assert b".warning-toast.critical" in stylesheet.data
    assert script.status_code == 200
    assert b"MACHINE CONDITION WARNING" in script.data
    assert b"ChemShieldP6WarningPopup" in script.data


def test_hmi_forwards_machine_event_and_risk_updates_to_part6_popup():
    app_js = (
        Path(__file__).parents[2]
        / "chem_shield_p1"
        / "hmi"
        / "static"
        / "app.js"
    ).read_text(encoding="utf-8")
    assert "ChemShieldP6WarningPopup.machineState(state)" in app_js
    assert "ChemShieldP6WarningPopup.eventWarnings(events)" in app_js
    assert "ChemShieldP6WarningPopup.riskWarnings(summary)" in app_js
    assert "const riskRank = {MEDIUM: 1, HIGH: 2, CRITICAL: 3}" in app_js
    assert "incident.warning_details" in app_js
    assert "risk-alert-trigger" in app_js

    warning_js = (
        Path(__file__).parents[1] / "static" / "warning_popup.js"
    ).read_text(encoding="utf-8")
    assert "incident.warning_details" in warning_js
    assert "warning.comparison" in warning_js
    assert "warning.timestamp" in warning_js
