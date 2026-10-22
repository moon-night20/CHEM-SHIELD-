from __future__ import annotations

from chem_shield_p7.scenarios.library import SCENARIOS
from chem_shield_p7.timeline.mitre_map import SCENARIO_TECHNIQUES, TECHNIQUES, techniques_for, validate_map
from chem_shield_p7.timeline.store import TimelineStore


def test_timeline_events_preserve_insert_order(tmp_path):
    store = TimelineStore(tmp_path / "timeline.db")
    store.create_run("a" * 32, "overheat", "Overheat", "2026-01-01T00:00:00+00:00")
    store.append_event("a" * 32, "SCENARIO_STARTED", source="runner")
    store.append_event("a" * 32, "ABNORMAL_READING", source="console")
    store.append_event("a" * 32, "DETECTED", source="HMI")
    run = store.get_run("a" * 32)
    assert [event["event_type"] for event in run["events"]] == [
        "SCENARIO_STARTED",
        "ABNORMAL_READING",
        "DETECTED",
    ]


def test_every_scenario_has_complete_mitre_mapping():
    validate_map()
    assert set(SCENARIO_TECHNIQUES) == {scenario["id"] for scenario in SCENARIOS}
    for scenario in SCENARIOS:
        assert techniques_for(scenario["id"])
    for technique in TECHNIQUES.values():
        assert all(technique.get(field) for field in ("id", "name", "tactic", "url"))
        assert technique["verify"] is False
