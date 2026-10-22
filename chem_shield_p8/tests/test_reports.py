from __future__ import annotations

from chem_shield_p8.reports import generate_incident_report


def test_generate_html_and_pdf_with_evidence_and_escaped_content(tmp_path):
    snapshot = {
        "timestamp": "2025-02-03T04:05:06+00:00",
        "threat_level": "CRITICAL",
        "plant": {
            "temperature_c": 97.0,
            "pressure_bar": 8.4,
            "level_pct": 61.0,
            "flow_l_min": 7.5,
            "coolant_valve_pct": 90.0,
            "feed_pump_on": False,
            "relief_valve_open": True,
        },
        "physics_guard": {"physics_score": 0.8, "ml_score": 0.7},
        "compliance": {"score": 72},
        "alerts": [{
            "timestamp": "2025-02-03T04:05:07+00:00",
            "severity": "CRITICAL",
            "rule_id": "DIRECT_IT_TO_CONTROL",
            "message": "<script>alert('not executable')</script>",
            "techniques": [{"id": "T0886", "name": "Remote Services"}],
        }],
        "timeline": [{
            "timestamp": "2025-02-03T04:05:07+00:00",
            "event_type": "SYNTHETIC_OT_EVENT",
            "detail": {"source_ip": "203.0.113.20", "destination_ip": "192.0.2.20"},
            "techniques": [{"id": "T0886", "name": "Remote Services"}],
        }],
        "assets": [{
            "device_id": "PLC-01",
            "role": "controller",
            "ip_address": "192.0.2.20",
            "first_seen": "2025-02-03T04:05:07+00:00",
            "last_seen": "2025-02-03T04:05:07+00:00",
        }],
        "scenario": {
            "result": {
                "scenario_name": "Synthetic lateral movement",
                "missed_steps": [],
            },
        },
        "response": {
            "decisions": [{
                "playbook_id": "switch-to-safe-state",
                "status": "APPROVED",
                "proposed_by": "operator-a",
                "approved_by": "operator-b",
                "result": {"feed_pump_on": False},
            }],
        },
    }

    files = generate_incident_report(snapshot, tmp_path)
    html_report = files.html_path.read_text(encoding="utf-8")

    assert files.html_path.is_file()
    assert files.pdf_path.is_file()
    assert "INCIDENT" in files.html_path.name.upper()
    assert "DIRECT_IT_TO_CONTROL" in html_report
    assert "T0886 Remote Services" in html_report
    assert "PLC-01" in html_report
    assert "switch-to-safe-state" in html_report
    assert "&lt;script&gt;" in html_report
    assert "<script>alert" not in html_report
    assert files.pdf_path.read_bytes().startswith(b"%PDF-")


def test_generate_report_with_empty_snapshot_has_safe_recommendation(tmp_path):
    files = generate_incident_report({}, tmp_path)
    html_report = files.html_path.read_text(encoding="utf-8")

    assert "No scenario alerts were present" in html_report
    assert "live process-safety" in html_report
    assert files.pdf_path.read_bytes().startswith(b"%PDF-")
