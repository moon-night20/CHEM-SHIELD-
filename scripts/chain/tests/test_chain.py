from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from chem_shield_p3.src.detector import PhysicalAnomalyDetector
from scripts.chain import p2, p4, p5
from scripts.chain.contracts import (
    ContractError,
    validate_event_list,
    validate_p2_handoff,
    validate_p4_incidents,
    validate_p5_report,
)
from scripts.run_chain import main


ROOT = Path(__file__).resolve().parents[3]
DEMO_NETWORK = ROOT / "chem_shield_p2" / "fixtures" / "demo_network_events.json"
TELEMETRY = ROOT / "chem_shield_p5" / "ot_monitor" / "samples" / "abnormal_telemetry.csv"
def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_full_chain_outputs_valid_handoffs_and_correlated_risk(tmp_path: Path, capsys) -> None:
    output_dir = tmp_path / "out"
    result = main(["--network-input", str(DEMO_NETWORK), "--out-dir", str(output_dir), "--step-by-step"])
    captured = capsys.readouterr()

    assert result == 0, captured.err
    assert "[P2]" in captured.out
    assert "[P3]" in captured.out
    assert "[P4]" in captured.out
    assert "[P5]" in captured.out
    assert [
        captured.out.index(f"[{stage}]") for stage in ("P2", "P3", "P4", "P5")
    ] == sorted(captured.out.index(f"[{stage}]") for stage in ("P2", "P3", "P4", "P5"))

    p2_data = json.loads((output_dir / "p2_events.json").read_text(encoding="utf-8"))
    p3_data = json.loads((output_dir / "p3_events.json").read_text(encoding="utf-8"))
    p4_data = json.loads((output_dir / "p4_incidents.json").read_text(encoding="utf-8"))
    p5_data = json.loads((output_dir / "p5_report.json").read_text(encoding="utf-8"))
    validate_p2_handoff(p2_data)
    validate_event_list(p3_data, "P3", "physical")
    validate_p4_incidents(p4_data)
    validate_p5_report(p5_data)

    combined = [
        incident for incident in p4_data
        if {event["event_type"] for event in incident["events"]} == {"network", "physical"}
    ]
    assert len(combined) == 1
    assert combined[0]["risk_score"] is not None
    assert combined[0]["risk_level"]
    report = next(item for item in p5_data if item["incident_id"] == combined[0]["incident_id"])
    assert report["rule_confirmation"] is bool(report["rule_alerts"])
    assert sorted(path.name for path in output_dir.iterdir()) == [
        "p2_events.json",
        "p3_events.json",
        "p4_incidents.json",
        "p5_report.json",
    ]


def test_p4_without_p3_handoff_fails_with_named_stage(tmp_path: Path) -> None:
    p2_path = tmp_path / "p2_events.json"
    p2.run(DEMO_NETWORK, p2_path)

    with pytest.raises(ContractError, match="P3 handoff file is missing"):
        p4.run(p2_path, tmp_path / "p3_events.json", tmp_path / "p4_incidents.json")


def test_no_p2_anomalies_write_empty_p3_and_report_no_network_trigger(
    tmp_path: Path, capsys
) -> None:
    network_path = tmp_path / "empty-network.json"
    _write_json(network_path, [])
    out_dir = tmp_path / "out"

    result = main([
        "--network-input",
        str(network_path),
        "--telemetry",
        str(TELEMETRY),
        "--out-dir",
        str(out_dir),
    ])
    output = capsys.readouterr()

    assert result == 0, output.err
    assert "no network trigger" in output.out
    assert json.loads((out_dir / "p3_events.json").read_text(encoding="utf-8")) == []
    assert json.loads((out_dir / "p4_incidents.json").read_text(encoding="utf-8")) == []
    assert json.loads((out_dir / "p5_report.json").read_text(encoding="utf-8")) == []


def test_p4_does_not_merge_events_outside_correlation_window(tmp_path: Path) -> None:
    p2_path = tmp_path / "p2_events.json"
    p3_path = tmp_path / "p3_events.json"
    p4_path = tmp_path / "p4_incidents.json"
    network = {
        "event_id": "network-1",
        "timestamp": "2026-10-14T10:00:14Z",
        "source": "network_model",
        "asset_id": "PLC-01",
        "event_type": "network",
        "anomaly_score": 0.9,
        "severity": "high",
        "evidence": {},
    }
    physical = {
        "event_id": "physical-1",
        "timestamp": "2026-10-14T10:00:30Z",
        "source": "physical_ml",
        "asset_id": "PLC-01",
        "event_type": "physical",
        "anomaly_score": 0.9,
        "severity": "high",
        "evidence": {},
    }
    _write_json(p2_path, {
        "events": [network],
        "handoff": {
            "asset_ids": ["PLC-01"],
            "window": {"start": network["timestamp"], "end": network["timestamp"]},
            "threshold": 0.5,
            "anomalous_event_count": 1,
        },
    })
    _write_json(p3_path, [physical])

    incidents = p4.run(p2_path, p3_path, p4_path)

    assert len(incidents) == 2
    assert all(len(incident["events"]) == 1 for incident in incidents)
    assert not any(
        {event["event_type"] for event in incident["events"]} == {"network", "physical"}
        for incident in incidents
    )
    validate_p4_incidents(json.loads(p4_path.read_text(encoding="utf-8")))


def test_orchestrator_stops_before_p5_if_both_event_types_do_not_correlate(
    tmp_path: Path, capsys
) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    network = {
        "event_id": "network-1",
        "timestamp": "2026-10-14T10:00:14Z",
        "source": "network_model",
        "asset_id": "PLC-01",
        "event_type": "network",
        "anomaly_score": 0.9,
        "severity": "high",
        "evidence": {},
    }
    physical = {
        "event_id": "physical-1",
        "timestamp": "2026-10-14T10:00:30Z",
        "source": "physical_ml",
        "asset_id": "PLC-01",
        "event_type": "physical",
        "anomaly_score": 0.9,
        "severity": "high",
        "evidence": {},
    }
    _write_json(out_dir / "p2_events.json", {
        "events": [network],
        "handoff": {
            "asset_ids": ["PLC-01"],
            "window": {"start": network["timestamp"], "end": network["timestamp"]},
            "threshold": 0.5,
            "anomalous_event_count": 1,
        },
    })
    _write_json(out_dir / "p3_events.json", [physical])

    result = main([
        "--from-stage",
        "3",
        "--to-stage",
        "4",
        "--out-dir",
        str(out_dir),
    ])
    output = capsys.readouterr()

    assert result != 0
    assert "P4 returned no incident containing both network and physical events" in output.err
    assert not (out_dir / "p5_report.json").exists()


def test_p5_uses_no_model_or_persistence_adapters(tmp_path: Path) -> None:
    p4_path = tmp_path / "p4_incidents.json"
    output_path = tmp_path / "p5_report.json"
    _write_json(p4_path, [{
        "incident_id": "INC-0001",
        "asset_id": "PLC-01",
        "start_time": "2026-10-14T10:00:20Z",
        "end_time": "2026-10-14T10:00:20Z",
        "risk_level": "HIGH",
        "risk_score": 0.75,
        "events": [{
            "event_id": "network-1",
            "timestamp": "2026-10-14T10:00:20Z",
            "source": "network_model",
            "asset_id": "PLC-01",
            "event_type": "network",
            "anomaly_score": 0.9,
            "severity": "high",
            "evidence": {},
        }],
    }])

    with (
        patch.object(PhysicalAnomalyDetector, "load", side_effect=AssertionError("P5 loaded P3 model")),
        patch.object(PhysicalAnomalyDetector, "predict", side_effect=AssertionError("P5 predicted")),
        patch(
            "chem_shield_p5.ot_monitor.sqlite_adapter.persist_ot_events",
            side_effect=AssertionError("P5 persisted to database"),
        ),
    ):
        report = p5.run(p4_path, TELEMETRY, output_path)

    assert report[0]["rule_confirmation"] is bool(report[0]["rule_alerts"])
    assert validate_p5_report(json.loads(output_path.read_text(encoding="utf-8"))) == report
    assert not list(tmp_path.glob("*.db"))


def test_admin_console_hint_is_printed_only_after_p5(tmp_path: Path, capsys) -> None:
    completed = main([
        "--network-input",
        str(DEMO_NETWORK),
        "--out-dir",
        str(tmp_path / "complete"),
        "--admin-console",
    ])
    completed_output = capsys.readouterr()
    assert completed == 0
    assert "Admin console: python -m admin_part.app -> http://127.0.0.1:5000" in completed_output.out

    partial = main([
        "--network-input",
        str(DEMO_NETWORK),
        "--out-dir",
        str(tmp_path / "partial"),
        "--to-stage",
        "3",
        "--admin-console",
    ])
    partial_output = capsys.readouterr()
    assert partial == 0
    assert "Admin console:" not in partial_output.out
