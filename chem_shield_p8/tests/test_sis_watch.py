from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from chem_shield_p8.sis_watch import (
    SISHashChain,
    SISState,
    SISWatch,
    create_baseline,
    load_or_create_key,
    verify_baseline,
)


def baseline_state():
    return SISState(
        trip_setpoints={"reactor_temperature_high_c": 95.0, "reactor_pressure_high_bar": 9.0},
        bypass_flags={"high_temperature_trip": False, "high_pressure_trip": False},
        safety_valve_states={"reactor_relief": False},
        configuration={"logic_revision": "1.0", "plc_id": "SIS-01"},
    )


def test_baseline_key_is_created_once_and_baseline_is_signed(tmp_path):
    key_path = tmp_path / "private" / "sis.key"
    first_key = load_or_create_key(key_path)
    assert len(first_key) == 32
    assert load_or_create_key(key_path) == first_key

    baseline_path = tmp_path / "sis-baseline.json"
    document = create_baseline(baseline_path, baseline_state(), first_key)
    assert verify_baseline(document, first_key)
    assert json.loads(baseline_path.read_text(encoding="utf-8")) == document
    with pytest.raises(FileExistsError, match="refusing to replace"):
        create_baseline(baseline_path, baseline_state(), first_key)


def test_signature_rejects_changed_state_and_wrong_key(tmp_path):
    key = b"k" * 32
    document = create_baseline(tmp_path / "baseline.json", baseline_state(), key)
    tampered = json.loads(json.dumps(document))
    tampered["payload"]["bypass_flags"]["high_temperature_trip"] = True
    assert not verify_baseline(tampered, key)
    assert not verify_baseline(document, b"x" * 32)
    with pytest.raises(ValueError, match="signature or hash is invalid"):
        SISWatch(tampered, key)


def test_sis_watch_reports_any_baseline_deviation_as_critical(tmp_path):
    key = b"s" * 32
    document = create_baseline(tmp_path / "baseline.json", baseline_state(), key)
    chain = SISHashChain(tmp_path / "sis-chain.jsonl")
    watch = SISWatch(document, key, chain)

    intact = watch.check(baseline_state(), timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc))
    altered_state = SISState(
        trip_setpoints={"reactor_temperature_high_c": 90.0, "reactor_pressure_high_bar": 9.0},
        bypass_flags={"high_temperature_trip": True, "high_pressure_trip": False},
        safety_valve_states={"reactor_relief": True},
        configuration={"logic_revision": "1.1", "plc_id": "SIS-01"},
    )
    altered = watch.check(altered_state)

    assert intact.status == "INTACT"
    assert altered.status == "CRITICAL"
    assert altered.changed_fields == [
        "bypass_flags",
        "configuration",
        "safety_valve_states",
        "trip_setpoints",
    ]
    assert altered.as_dict()["severity"] == "CRITICAL"
    assert chain.verify() == {"ok": True, "records": 2}


def test_hash_chain_survives_reload_and_detects_tampering(tmp_path):
    path = tmp_path / "chain.jsonl"
    chain = SISHashChain(path)
    chain.append(
        status="INTACT",
        baseline_hash="a" * 64,
        observed_hash="a" * 64,
        changed_fields=[],
    )
    assert SISHashChain(path).verify() == {"ok": True, "records": 1}

    row = json.loads(path.read_text(encoding="utf-8"))
    row["status"] = "CRITICAL"
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="chain is invalid"):
        SISHashChain(path)


def test_hash_chain_refuses_to_extend_invalid_memory_chain():
    chain = SISHashChain()
    chain.append(
        status="INTACT",
        baseline_hash="a" * 64,
        observed_hash="a" * 64,
        changed_fields=[],
    )
    chain._records[0]["status"] = "CRITICAL"
    assert chain.verify()["ok"] is False
    with pytest.raises(ValueError, match="Refusing to append"):
        chain.append(
            status="INTACT",
            baseline_hash="a" * 64,
            observed_hash="a" * 64,
            changed_fields=[],
        )


def test_invalid_sis_state_is_rejected():
    with pytest.raises(ValueError, match="finite number"):
        SISState(
            trip_setpoints={"high": float("nan")},
            bypass_flags={},
            safety_valve_states={},
        ).as_payload()
    with pytest.raises(ValueError, match="booleans"):
        SISState(
            trip_setpoints={},
            bypass_flags={"bypass": 1},
            safety_valve_states={},
        ).as_payload()
