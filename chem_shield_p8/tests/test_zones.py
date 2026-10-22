from __future__ import annotations

from pathlib import Path

import pytest

from chem_shield_p8.ot_monitor.events import parse_event
from chem_shield_p8.zones import ZonePolicy, compute_compliance

CONFIG = Path(__file__).resolve().parents[1] / "config" / "zones.yaml"


def flow(
    event_id="flow-1",
    source="192.0.2.10",
    destination="192.0.2.20",
    protocol="modbus-tcp",
):
    return parse_event({
        "event_id": event_id,
        "timestamp": "2026-10-22T10:00:00Z",
        "protocol": protocol,
        "source_ip": source,
        "destination_ip": destination,
        "function_code": 3 if protocol == "modbus-tcp" else None,
    }) if protocol == "modbus-tcp" else parse_event({
        "event_id": event_id,
        "timestamp": "2026-10-22T10:00:00Z",
        "protocol": "opcua",
        "source_ip": source,
        "destination_ip": destination,
        "message": {"type": "Read", "node_id": "temperature"},
    })


def test_zone_policy_covers_purdue_levels_and_rfc_documentation_ranges():
    policy = ZonePolicy.load(CONFIG)
    assert {zone.level for zone in policy.zones} == {"0", "1", "2", "3", "3.5", "4", "5"}
    assert policy.zone_for("192.0.2.20").zone_id == "control"
    assert policy.zone_for("192.0.2.10").zone_id == "engineering"
    assert policy.zone_for("8.8.8.8") is None


def test_explicit_engineering_and_supervisory_conduits_allow_expected_flows():
    policy = ZonePolicy.load(CONFIG)
    engineering = policy.evaluate(flow())
    supervisory = policy.evaluate(flow(
        "hmi-poll",
        source="192.0.2.30",
    ))
    assert engineering.allowed
    assert engineering.conduit_id == "engineering_to_control"
    assert supervisory.allowed
    assert supervisory.conduit_id == "supervisory_to_control"


def test_level_four_it_direct_to_level_one_plc_is_critical_violation():
    decision = ZonePolicy.load(CONFIG).evaluate(flow(
        "it-to-plc",
        source="203.0.113.20",
    ))
    assert not decision.allowed
    assert decision.rule_id == "DIRECT_IT_TO_CONTROL"
    assert decision.severity == "CRITICAL"


def test_conduit_rejects_wrong_protocol_and_unlisted_host():
    policy = ZonePolicy.load(CONFIG)
    protocol = policy.evaluate(flow("wrong-protocol", protocol="opcua"))
    endpoint = policy.evaluate(flow("unlisted-engineer", source="192.0.2.11"))
    assert protocol.rule_id == "PROTOCOL_NOT_ALLOWED"
    assert endpoint.rule_id == "ENDPOINT_NOT_ALLOWED"


def test_unknown_or_unmapped_endpoint_is_flagged():
    decision = ZonePolicy.load(CONFIG).evaluate(flow(
        "unknown-zone",
        source="203.0.113.50",
    ))
    assert decision.rule_id == "UNKNOWN_ZONE_FLOW"
    assert not decision.allowed


def test_compliance_score_is_transparent_and_drops_for_policy_violations():
    policy = ZonePolicy.load(CONFIG)
    healthy = compute_compliance(policy)
    violated = compute_compliance(policy, [flow(
        "direct-it",
        source="203.0.113.20",
    )])
    assert healthy.score == 100
    assert violated.score < healthy.score
    assert "not IEC 62443/NIST certification" in healthy.disclaimer
    assert any(not check.passed for check in violated.checks)


def test_invalid_network_and_unknown_conduit_zone_are_rejected(tmp_path):
    invalid_network = tmp_path / "zones.yaml"
    invalid_network.write_text(
        "zones:\n  - id: bad\n    name: Bad\n    level: 1\n"
        "    networks: [not-a-network]\n    allowed_protocols: [modbus-tcp]\n"
        "conduits: []\ncompliance: {}\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="invalid network"):
        ZonePolicy.load(invalid_network)
