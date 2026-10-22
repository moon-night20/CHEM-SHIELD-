from __future__ import annotations

from unittest.mock import patch

import pytest

from chem_shield_p7.notifier import queue_critical_message
from chem_shield_p7.report.generator import generate_report


def test_report_is_self_contained_escaped_and_confined(tmp_path):
    run = {
        "run_id": "a" * 32,
        "scenario_name": '<img src=x onerror="alert(1)">',
        "status": "COMPLETED",
        "outcome": "<script>unsafe()</script>",
        "started_at": "2026-01-01T00:00:00+00:00",
        "ended_at": "2026-01-01T00:00:02+00:00",
        "detected_at": "2026-01-01T00:00:01+00:00",
        "responded_at": "2026-01-01T00:00:01.500000+00:00",
        "automatic_stop": False,
        "events": [{
            "timestamp": "2026-01-01T00:00:01+00:00",
            "event_type": "DETECTED",
            "source": "HMI",
            "detector": "",
            "detail": {"message": "<script>event()</script>"},
            "mitre": [],
        }],
    }
    path = generate_report(
        "b" * 32,
        run,
        output_dir=tmp_path / "reports",
        limits={"temperature": 70, "pressure": 4, "power": 12, "speed": 1500},
        peak_readings={"temperature": 90},
        audit_status={"ok": True, "records": 1},
    )
    text = path.read_text(encoding="utf-8")
    assert "<script>" not in text
    assert "&lt;script&gt;" in text
    assert "@media print" in text
    assert "PLC" not in text or "loopback" in text
    with pytest.raises(ValueError, match="identifier"):
        generate_report(
            "../outside",
            run,
            output_dir=tmp_path,
            limits={},
            peak_readings={},
            audit_status={"ok": True},
        )


def test_mock_notifier_writes_local_outbox_without_network(tmp_path):
    target = tmp_path / "out" / "outbox.log"
    with patch.dict("os.environ", {}, clear=True):
        with patch("chem_shield_p7.notifier.urlopen") as urlopen:
            message = queue_critical_message(
                target,
                sensor="temperature",
                value=92,
                unit="°C",
                countdown="00:20",
            )
            urlopen.assert_not_called()
    assert message == "CRITICAL: temperature 92 °C on PLC-01. Auto-stop in 00:20."
    assert message in target.read_text(encoding="utf-8")
