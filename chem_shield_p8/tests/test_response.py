from __future__ import annotations

import json
from pathlib import Path

import pytest

from chem_shield_p8.response import ResponseManager, ResponseState, load_playbooks

PLAYBOOKS = Path(__file__).resolve().parents[1] / "config" / "playbooks.yaml"


@pytest.fixture
def manager(tmp_path):
    return ResponseManager(
        playbooks=load_playbooks(PLAYBOOKS),
        log_path=tmp_path / "response.jsonl",
        state=ResponseState(),
    )


@pytest.mark.parametrize(
    "playbook_id, state_field, expected_value",
    [
        ("isolate-zone", "isolated_zones", "control"),
        ("block-conduit", "blocked_conduits", "engineering_to_control"),
    ],
)
def test_zone_and_conduit_responses_require_approval(manager, playbook_id, state_field, expected_value):
    pending = manager.propose(playbook_id, proposed_by="analyst")
    assert pending.status == "PENDING_APPROVAL"
    assert not getattr(manager.state, state_field)

    approved = manager.approve(pending.action_id, approved_by="operator")
    assert approved.status == "APPROVED"
    assert getattr(manager.state, state_field) == {expected_value}
    assert approved.result["simulated"] is True
    assert approved.result["network_changed"] is False


def test_safe_state_is_local_and_never_sends_a_plc_command(manager):
    pending = manager.propose("switch-to-safe-state", proposed_by="analyst")
    assert manager.state.controls["feed_pump_on"] is False
    assert manager.state.controls["coolant_valve_pct"] == 35.0

    approved = manager.approve(pending.action_id, approved_by="operator")
    assert approved.result["controls"] == {
        "feed_pump_on": False,
        "coolant_valve_pct": 100.0,
        "relief_valve_open": None,
    }
    assert approved.result["plc_command_sent"] is False


def test_notification_is_stored_locally_without_external_delivery(manager):
    pending = manager.propose("notify-operator", proposed_by="analyst")
    approved = manager.approve(pending.action_id, approved_by="operator")
    assert manager.state.notifications == [
        "Review the reactor alert and confirm process state."
    ]
    assert approved.result["external_message_sent"] is False


def test_rejected_action_is_logged_and_has_no_simulated_effect(manager):
    pending = manager.propose("isolate-zone", proposed_by="analyst")
    rejected = manager.reject(
        pending.action_id,
        rejected_by="operator",
        reason="Confirm process conditions first.",
    )
    assert rejected.status == "REJECTED"
    assert manager.state.isolated_zones == set()
    assert manager.verify_log() == {"ok": True, "records": 2}
    assert [record["decision"] for record in manager.list_log()] == ["PROPOSED", "REJECTED"]


def test_all_decisions_are_hash_chained_and_reloadable(manager, tmp_path):
    pending = manager.propose("notify-operator", proposed_by="analyst", context={"alert": "A-1"})
    manager.approve(pending.action_id, approved_by="operator", note="Approved for simulation.")
    log_path = tmp_path / "response.jsonl"
    records = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert [record["decision"] for record in records] == [
        "PROPOSED", "APPROVED", "SIMULATED"
    ]
    assert manager.verify_log() == {"ok": True, "records": 3}
    assert records[1]["previous_hash"] == records[0]["hash"]

    records[-1]["result"]["external_message_sent"] = True
    log_path.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="decision log is invalid"):
        ResponseManager(
            playbooks=load_playbooks(PLAYBOOKS),
            log_path=log_path,
        )


def test_duplicate_decision_unknown_action_and_unsafe_parameters_are_rejected(manager):
    with pytest.raises(ValueError, match="Unknown response playbook"):
        manager.propose("../command", proposed_by="analyst")
    with pytest.raises(ValueError, match="configured zone_id"):
        manager.propose(
            "isolate-zone",
            proposed_by="analyst",
            parameters={"zone_id": "external-network"},
        )
    pending = manager.propose("notify-operator", proposed_by="analyst")
    approved = manager.approve(pending.action_id, approved_by="operator")
    with pytest.raises(ValueError, match="already approved"):
        manager.approve(pending.action_id, approved_by="operator")
