from chem_shield_p6.response import response_decision


def test_critical_active_incident_requires_operator_confirmation():
    decision = response_decision({
        "incident_id": "INC-0001",
        "risk_level": "CRITICAL",
        "status": "ACTIVE",
    })

    assert decision == {
        "incident_id": "INC-0001",
        "action": "simulated_stop",
        "requires_operator_confirmation": True,
        "simulation_only": True,
        "executed": False,
    }


def test_noncritical_or_inactive_incidents_never_offer_a_stop():
    for incident in (
        {"incident_id": "INC-1", "risk_level": "HIGH", "status": "ACTIVE"},
        {"incident_id": "INC-2", "risk_level": "CRITICAL", "status": "CLOSED"},
    ):
        decision = response_decision(incident)

        assert decision["action"] == "monitor_only"
        assert decision["requires_operator_confirmation"] is False
        assert decision["executed"] is False
