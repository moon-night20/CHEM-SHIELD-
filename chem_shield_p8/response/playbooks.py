"""Approval-gated response actions that only mutate local demo state."""

from __future__ import annotations

import hashlib
import json
import math
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from chem_shield_p8.zones.policy import ZonePolicy

DEFAULT_PLAYBOOKS = Path(__file__).resolve().parents[1] / "config" / "playbooks.yaml"
SUPPORTED_ACTIONS = {
    "isolate_zone",
    "block_conduit",
    "switch_to_safe_state",
    "notify_operator",
}
GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class Playbook:
    """Validated operator-selectable simulation response."""

    playbook_id: str
    name: str
    description: str
    action: str
    parameters: dict[str, Any]


@dataclass
class ResponseState:
    """Local-only effects of approved simulated responses."""

    isolated_zones: set[str] = field(default_factory=set)
    blocked_conduits: set[str] = field(default_factory=set)
    controls: dict[str, Any] = field(default_factory=lambda: {
        "feed_pump_on": False,
        "coolant_valve_pct": 35.0,
        "relief_valve_open": None,
    })
    notifications: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ResponseDecision:
    """Status and history reference for one requested response action."""

    action_id: str
    playbook_id: str
    status: str
    created_at: str
    updated_at: str
    proposed_by: str
    approved_by: str | None
    parameters: dict[str, Any]
    result: dict[str, Any] | None
    log_hash: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "playbook_id": self.playbook_id,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "proposed_by": self.proposed_by,
            "approved_by": self.approved_by,
            "parameters": dict(self.parameters),
            "result": dict(self.result) if self.result is not None else None,
            "log_hash": self.log_hash,
        }


def load_playbooks(path: str | Path = DEFAULT_PLAYBOOKS) -> dict[str, Playbook]:
    """Load and validate only the four explicitly simulated action types."""
    config_path = Path(path)
    try:
        with config_path.open(encoding="utf-8") as stream:
            document = yaml.safe_load(stream)
    except OSError as error:
        raise ValueError(f"Could not read response playbooks {config_path}: {error}") from error
    except yaml.YAMLError as error:
        raise ValueError(f"Invalid response playbook YAML {config_path}: {error}") from error
    if not isinstance(document, dict) or not isinstance(document.get("playbooks"), list):
        raise ValueError("Response config must define a playbooks list.")
    result: dict[str, Playbook] = {}
    for raw in document["playbooks"]:
        if not isinstance(raw, dict):
            raise ValueError("Every response playbook must be a mapping.")
        playbook_id = _non_empty(raw.get("id"), "playbook id")
        name = _non_empty(raw.get("name"), "playbook name")
        description = _non_empty(raw.get("description"), "playbook description")
        action = _non_empty(raw.get("action"), "playbook action")
        parameters = raw.get("parameters")
        if action not in SUPPORTED_ACTIONS:
            raise ValueError(f"Unsupported response action: {action}")
        if not isinstance(parameters, dict):
            raise ValueError(f"Playbook {playbook_id} parameters must be a mapping.")
        if playbook_id in result:
            raise ValueError(f"Duplicate response playbook id: {playbook_id}")
        result[playbook_id] = Playbook(
            playbook_id=playbook_id,
            name=name,
            description=description,
            action=action,
            parameters=dict(parameters),
        )
    required = {"isolate_zone", "block_conduit", "switch_to_safe_state", "notify_operator"}
    if {playbook.action for playbook in result.values()} != required:
        raise ValueError("Playbooks must provide each of the four supported simulation actions.")
    return result


class ResponseManager:
    """Require operator approval and audit every simulated response decision."""

    def __init__(
        self,
        *,
        playbooks: dict[str, Playbook] | None = None,
        policy: ZonePolicy | None = None,
        log_path: str | Path | None = None,
        state: ResponseState | None = None,
    ) -> None:
        self.playbooks = playbooks or load_playbooks()
        self.policy = policy or ZonePolicy.load()
        self.log_path = Path(log_path) if log_path is not None else None
        self.state = state or ResponseState()
        self._lock = threading.RLock()
        self._decisions: dict[str, ResponseDecision] = {}
        self._log_records: list[dict[str, Any]] = []
        if self.log_path is not None and self.log_path.exists():
            self._log_records = self._read_log()
            verification = self.verify_log()
            if not verification["ok"]:
                raise ValueError(
                    f"Response decision log is invalid: {verification['reason']}"
                )

    def propose(
        self,
        playbook_id: str,
        *,
        proposed_by: str,
        parameters: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ) -> ResponseDecision:
        """Create a pending proposal; no simulated effect occurs before approval."""
        operator = _non_empty(proposed_by, "proposed_by")
        playbook = self.playbooks.get(playbook_id)
        if playbook is None:
            raise ValueError(f"Unknown response playbook: {playbook_id}")
        selected = dict(playbook.parameters)
        if parameters:
            selected.update(parameters)
        self._validate_parameters(playbook, selected)
        now = datetime.now(timezone.utc).isoformat()
        action_id = uuid.uuid4().hex
        with self._lock:
            decision = ResponseDecision(
                action_id=action_id,
                playbook_id=playbook_id,
                status="PENDING_APPROVAL",
                created_at=now,
                updated_at=now,
                proposed_by=operator,
                approved_by=None,
                parameters=selected,
                result=None,
                log_hash=None,
            )
            log_record = self._append_log({
                "decision": "PROPOSED",
                "action_id": action_id,
                "playbook_id": playbook_id,
                "operator": operator,
                "parameters": selected,
                "context": context or {},
                "timestamp": now,
            })
            decision = ResponseDecision(
                **{
                    **decision.__dict__,
                    "log_hash": log_record["hash"],
                }
            )
            self._decisions[action_id] = decision
            return decision

    def approve(
        self,
        action_id: str,
        *,
        approved_by: str,
        note: str = "",
    ) -> ResponseDecision:
        """Approve a pending proposal and apply its local simulated effect."""
        operator = _non_empty(approved_by, "approved_by")
        with self._lock:
            decision = self._get_pending(action_id)
            playbook = self.playbooks[decision.playbook_id]
            timestamp = datetime.now(timezone.utc).isoformat()
            approval_log = self._append_log({
                "decision": "APPROVED",
                "action_id": action_id,
                "playbook_id": playbook.playbook_id,
                "operator": operator,
                "note": note,
                "timestamp": timestamp,
            })
            try:
                result = self._simulate(playbook, decision.parameters)
            except (KeyError, TypeError, ValueError) as error:
                self._append_log({
                    "decision": "SIMULATION_FAILED",
                    "action_id": action_id,
                    "playbook_id": playbook.playbook_id,
                    "operator": operator,
                    "error": f"{type(error).__name__}: {error}",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                updated = ResponseDecision(
                    **{
                        **decision.__dict__,
                        "status": "FAILED",
                        "updated_at": datetime.now(timezone.utc).isoformat(),
                        "approved_by": operator,
                        "result": {"error": str(error)},
                        "log_hash": approval_log["hash"],
                    }
                )
                self._decisions[action_id] = updated
                raise RuntimeError(f"Approved simulation action failed: {error}") from error
            completion = self._append_log({
                "decision": "SIMULATED",
                "action_id": action_id,
                "playbook_id": playbook.playbook_id,
                "operator": operator,
                "result": result,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            updated = ResponseDecision(
                **{
                    **decision.__dict__,
                    "status": "APPROVED",
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                    "approved_by": operator,
                    "result": result,
                    "log_hash": completion["hash"],
                }
            )
            self._decisions[action_id] = updated
            return updated

    def reject(
        self,
        action_id: str,
        *,
        rejected_by: str,
        reason: str,
    ) -> ResponseDecision:
        """Reject a pending proposal without changing simulated plant state."""
        operator = _non_empty(rejected_by, "rejected_by")
        rejection_reason = _non_empty(reason, "reason")
        with self._lock:
            decision = self._get_pending(action_id)
            timestamp = datetime.now(timezone.utc).isoformat()
            log_record = self._append_log({
                "decision": "REJECTED",
                "action_id": action_id,
                "playbook_id": decision.playbook_id,
                "operator": operator,
                "reason": rejection_reason,
                "timestamp": timestamp,
            })
            updated = ResponseDecision(
                **{
                    **decision.__dict__,
                    "status": "REJECTED",
                    "updated_at": timestamp,
                    "approved_by": operator,
                    "result": {"reason": rejection_reason},
                    "log_hash": log_record["hash"],
                }
            )
            self._decisions[action_id] = updated
            return updated

    def decision(self, action_id: str) -> ResponseDecision | None:
        return self._decisions.get(action_id)

    def list_decisions(self) -> list[ResponseDecision]:
        return list(self._decisions.values())

    def list_log(self) -> list[dict[str, Any]]:
        return [dict(record) for record in self._log_records]

    def verify_log(self) -> dict[str, Any]:
        previous_hash = GENESIS_HASH
        for sequence, record in enumerate(self._log_records, start=1):
            body = {key: value for key, value in record.items() if key not in {"hash", "previous_hash"}}
            expected = hashlib.sha256(
                (previous_hash + _canonical_json(body)).encode("utf-8")
            ).hexdigest()
            if record.get("sequence") != sequence:
                return {"ok": False, "first_broken_index": sequence, "reason": "Response log sequence changed."}
            if record.get("previous_hash") != previous_hash:
                return {"ok": False, "first_broken_index": sequence, "reason": "Response log hash link changed."}
            if record.get("hash") != expected:
                return {"ok": False, "first_broken_index": sequence, "reason": "Response log record hash is invalid."}
            previous_hash = expected
        return {"ok": True, "records": len(self._log_records)}

    def _get_pending(self, action_id: str) -> ResponseDecision:
        decision = self._decisions.get(action_id)
        if decision is None:
            raise ValueError(f"Unknown response action: {action_id}")
        if decision.status != "PENDING_APPROVAL":
            raise ValueError(f"Response action is already {decision.status.lower()}.")
        return decision

    def _validate_parameters(self, playbook: Playbook, params: dict[str, Any]) -> None:
        if playbook.action == "isolate_zone":
            zone_id = params.get("zone_id")
            if not isinstance(zone_id, str) or zone_id not in {zone.zone_id for zone in self.policy.zones}:
                raise ValueError("isolate_zone requires a configured zone_id.")
        elif playbook.action == "block_conduit":
            conduit_id = params.get("conduit_id")
            if not isinstance(conduit_id, str) or conduit_id not in {
                conduit.conduit_id for conduit in self.policy.conduits
            }:
                raise ValueError("block_conduit requires a configured conduit_id.")
        elif playbook.action == "switch_to_safe_state":
            pump = params.get("feed_pump_on")
            valve = params.get("coolant_valve_pct")
            relief = params.get("relief_valve_open")
            if not isinstance(pump, bool):
                raise ValueError("Safe-state feed_pump_on must be boolean.")
            if (
                isinstance(valve, bool)
                or not isinstance(valve, (int, float))
                or not math.isfinite(float(valve))
                or not 0.0 <= float(valve) <= 100.0
            ):
                raise ValueError("Safe-state coolant_valve_pct must be between 0 and 100.")
            if relief is not None and not isinstance(relief, bool):
                raise ValueError("Safe-state relief_valve_open must be boolean or automatic (null).")
        elif playbook.action == "notify_operator":
            message = params.get("message")
            if not isinstance(message, str) or not message.strip():
                raise ValueError("notify_operator requires a non-empty message.")

    def _simulate(self, playbook: Playbook, params: dict[str, Any]) -> dict[str, Any]:
        """Apply a whitelisted action only to ResponseState local to this process."""
        self._validate_parameters(playbook, params)
        if playbook.action == "isolate_zone":
            zone_id = str(params["zone_id"])
            self.state.isolated_zones.add(zone_id)
            return {"simulated": True, "isolated_zone": zone_id, "network_changed": False}
        if playbook.action == "block_conduit":
            conduit_id = str(params["conduit_id"])
            self.state.blocked_conduits.add(conduit_id)
            return {"simulated": True, "blocked_conduit": conduit_id, "network_changed": False}
        if playbook.action == "switch_to_safe_state":
            self.state.controls = {
                "feed_pump_on": params["feed_pump_on"],
                "coolant_valve_pct": float(params["coolant_valve_pct"]),
                "relief_valve_open": params["relief_valve_open"],
            }
            return {"simulated": True, "controls": dict(self.state.controls), "plc_command_sent": False}
        if playbook.action == "notify_operator":
            message = str(params["message"]).strip()
            self.state.notifications.append(message)
            return {"simulated": True, "message": message, "external_message_sent": False}
        raise ValueError(f"Unsupported simulated action: {playbook.action}")

    def _append_log(self, body: dict[str, Any]) -> dict[str, Any]:
        previous_hash = (
            self._log_records[-1]["hash"] if self._log_records else GENESIS_HASH
        )
        record_body = {"sequence": len(self._log_records) + 1, **body}
        digest = hashlib.sha256(
            (previous_hash + _canonical_json(record_body)).encode("utf-8")
        ).hexdigest()
        record = {
            **record_body,
            "previous_hash": previous_hash,
            "hash": digest,
        }
        encoded = _canonical_json(record) + "\n"
        if self.log_path is not None:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as stream:
                stream.write(encoded)
        self._log_records.append(record)
        return dict(record)

    def _read_log(self) -> list[dict[str, Any]]:
        if self.log_path is None:
            return []
        records: list[dict[str, Any]] = []
        try:
            lines = self.log_path.read_text(encoding="utf-8").splitlines()
        except OSError as error:
            raise ValueError(f"Could not read response decision log: {error}") from error
        for index, line in enumerate(lines, start=1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"Invalid response log JSON at line {index}: {error}") from error
            if not isinstance(record, dict):
                raise ValueError(f"Invalid response log record at line {index}.")
            records.append(record)
        return records


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise ValueError(f"Response decision is not valid JSON: {error}") from error


def _non_empty(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string.")
    return value.strip()
