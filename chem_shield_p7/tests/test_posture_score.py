from chem_shield_p7.command_center import calculate_posture_score


def test_posture_score_formula_and_breakdown():
    run = {
        "started_at": "2026-01-01T00:00:00+00:00",
        "detected_at": "2026-01-01T00:00:30+00:00",
        "responded_at": "2026-01-01T00:00:45+00:00",
        "automatic_stop": True,
    }
    result = calculate_posture_score(run, {"ok": True})
    assert result["score"] == 81
    assert result["breakdown"] == {
        "detection_speed": 12.5,
        "operator_response": 18.8,
        "automatic_stop": 25.0,
        "audit_integrity": 25.0,
    }
    assert result["maximum"] == 100
    assert result["is_industry_standard"] is False
