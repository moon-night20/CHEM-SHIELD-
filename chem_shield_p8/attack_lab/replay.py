"""Deterministic replay engine for defensive, synthetic event timelines."""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from chem_shield_p8.ot_monitor import MonitorConfig, OTEvent, OTMonitor
from chem_shield_p8.sis_watch import SISState, SISWatch
from chem_shield_p8.sis_watch.baseline import sign_baseline
from chem_shield_p8.zones import ZonePolicy
from chem_shield_p8.zones.policy import FlowDecision

from .mitre import techniques_for_alert, techniques_for_scenario

DEFAULT_SCENARIOS = Path(__file__).with_name("scenarios.json")
LOSS_OF_VIEW_RULE = "LOSS_OF_VIEW"
BASE_SIS_STATE = SISState(
    trip_setpoints={"reactor_temperature_high_c": 95.0, "reactor_pressure_high_bar": 9.0},
    bypass_flags={"high_temperature_trip": False, "high_pressure_trip": False},
    safety_valve_states={"reactor_relief": False},
    configuration={"logic_revision": "1.0", "plc_id": "SIS-01"},
)


@dataclass(frozen=True)
class ScenarioAlert:
    """Alert with its evidence and applicable MITRE technique metadata."""

    timestamp: datetime
    rule_id: str
    severity: str
    message: str
    evidence: dict[str, Any]
    techniques: list[dict[str, str]]

    def as_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "evidence": self.evidence,
            "techniques": self.techniques,
        }


@dataclass(frozen=True)
class TimelineEntry:
    """One scenario step, detector decision, or synthetic alert."""

    timestamp: datetime
    event_type: str
    detail: dict[str, Any]
    techniques: list[dict[str, str]]

    def as_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "detail": self.detail,
            "techniques": self.techniques,
        }


@dataclass(frozen=True)
class ScenarioResult:
    """Completed replay with detection latency, missed rules, and false positives."""

    scenario_id: str
    scenario_name: str
    status: str
    started_at: datetime
    ended_at: datetime
    detection_time_seconds: float | None
    expected_rules: list[str]
    detected_rules: list[str]
    missed_steps: list[str]
    false_positive_count: int
    alerts: list[ScenarioAlert]
    timeline: list[TimelineEntry]

    def as_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "scenario_name": self.scenario_name,
            "status": self.status,
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat(),
            "detection_time_seconds": self.detection_time_seconds,
            "expected_rules": self.expected_rules,
            "detected_rules": self.detected_rules,
            "missed_steps": self.missed_steps,
            "false_positive_count": self.false_positive_count,
            "alerts": [alert.as_dict() for alert in self.alerts],
            "timeline": [entry.as_dict() for entry in self.timeline],
        }


def load_scenarios(path: str | Path = DEFAULT_SCENARIOS) -> list[dict[str, Any]]:
    """Load and validate the six local JSON scenario timelines."""
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Could not load synthetic scenario definitions: {error}") from error
    if not isinstance(document, list):
        raise ValueError("Scenario file must contain a JSON list.")
    seen: set[str] = set()
    for scenario in document:
        if not isinstance(scenario, dict):
            raise ValueError("Every scenario must be a JSON object.")
        scenario_id = scenario.get("id")
        if not isinstance(scenario_id, str) or not scenario_id or scenario_id in seen:
            raise ValueError("Scenario ids must be unique non-empty strings.")
        seen.add(scenario_id)
        if not isinstance(scenario.get("name"), str) or not scenario.get("name"):
            raise ValueError(f"Scenario {scenario_id} requires a name.")
        if not isinstance(scenario.get("steps"), list) or not scenario["steps"]:
            raise ValueError(f"Scenario {scenario_id} requires at least one step.")
        expected = scenario.get("expected_rules")
        if not isinstance(expected, list) or not all(isinstance(item, str) for item in expected):
            raise ValueError(f"Scenario {scenario_id} expected_rules must be a string list.")
        scenario_techniques = scenario.get("techniques")
        if not isinstance(scenario_techniques, list):
            raise ValueError(f"Scenario {scenario_id} requires ATT&CK technique IDs.")
        techniques_for_scenario(scenario_techniques)
        previous_at = -1.0
        for step in scenario["steps"]:
            if not isinstance(step, dict):
                raise ValueError(f"Scenario {scenario_id} steps must be JSON objects.")
            at_seconds = step.get("at_seconds")
            if (
                isinstance(at_seconds, bool)
                or not isinstance(at_seconds, (int, float))
                or at_seconds < previous_at
            ):
                raise ValueError(f"Scenario {scenario_id} steps must be time ordered.")
            previous_at = float(at_seconds)
            if step.get("type") not in {"ot_event", "telemetry_gap", "sis_change"}:
                raise ValueError(f"Scenario {scenario_id} has an unsupported step type.")
    if len(document) != 6:
        raise ValueError("The local attack lab must define all six required scenarios.")
    return document


class ReplayRunner:
    """Construct independent replay sessions; never sends network traffic."""

    def __init__(self, scenarios: list[dict[str, Any]] | None = None) -> None:
        self.scenarios = scenarios or load_scenarios()
        self._scenario_index = {item["id"]: item for item in self.scenarios}

    def start(
        self,
        scenario_id: str,
        *,
        started_at: datetime | None = None,
    ) -> "ReplaySession":
        scenario = self._scenario_index.get(scenario_id)
        if scenario is None:
            raise ValueError(f"Unknown synthetic scenario: {scenario_id}")
        return ReplaySession(scenario, started_at=started_at)

    def run(
        self,
        scenario_id: str,
        *,
        started_at: datetime | None = None,
    ) -> ScenarioResult:
        """Convenience method to replay all steps and return final metrics."""
        session = self.start(scenario_id, started_at=started_at)
        while not session.complete:
            session.step()
        return session.result()


class ReplaySession:
    """Step-capable scenario replay for dashboard Play/Pause/Step controls."""

    def __init__(
        self,
        scenario: dict[str, Any],
        *,
        started_at: datetime | None = None,
    ) -> None:
        self.scenario = scenario
        self.started_at = (started_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
        self._steps = list(scenario["steps"])
        self._step_index = 0
        self._monitor = OTMonitor(MonitorConfig.load())
        self._zones = ZonePolicy.load()
        key = secrets.token_bytes(32)
        baseline = sign_baseline(BASE_SIS_STATE, key)
        self._sis_watch = SISWatch(baseline, key)
        self._alerts: list[ScenarioAlert] = []
        self._timeline: list[TimelineEntry] = []
        self._events: list[OTEvent] = []
        self._detection_time: float | None = None
        self._seen_rules: set[str] = set()
        self._end_at = self.started_at

    @property
    def complete(self) -> bool:
        return self._step_index >= len(self._steps)

    @property
    def current_step(self) -> int:
        return self._step_index

    def assets(self) -> list[dict[str, Any]]:
        """Expose a copy of endpoints discovered by this replay session."""
        return [asset.as_dict() for asset in self._monitor.inventory.list_assets()]

    def events(self) -> list[OTEvent]:
        """Expose normalized protocol events observed during this session."""
        return list(self._events)

    def step(self) -> dict[str, Any]:
        """Process one synthetic timeline step and return its new observations."""
        if self.complete:
            raise RuntimeError("Scenario replay is already complete.")
        raw_step = self._steps[self._step_index]
        self._step_index += 1
        at_seconds = float(raw_step["at_seconds"])
        timestamp = self.started_at + timedelta(seconds=at_seconds)
        self._end_at = max(self._end_at, timestamp)
        event_type = raw_step["type"]
        new_alerts: list[ScenarioAlert] = []
        step_details: dict[str, Any]

        if event_type == "ot_event":
            record = dict(raw_step["record"])
            record["event_id"] = f"{self.scenario['id']}-{self._step_index}"
            record["timestamp"] = timestamp.isoformat()
            alerts = self._monitor.process(record)
            event = self._event_from_record(record)
            self._events.append(event)
            decision = self._zones.evaluate(event)
            if not decision.allowed:
                alerts.append(self._zone_alert(decision, event.event_id, timestamp))
            new_alerts = [
                self._wrap_alert(alert.rule_id, alert.severity, alert.message, alert.evidence, timestamp)
                for alert in alerts
            ]
            step_details = {
                "protocol": event.protocol,
                "operation": event.operation,
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "tag": event.tag,
                "value": event.value,
                "zone_decision": decision.rule_id,
            }
            self._timeline.append(TimelineEntry(
                timestamp,
                "SYNTHETIC_OT_EVENT",
                step_details,
                techniques_for_scenario(self.scenario["techniques"]),
            ))
        elif event_type == "telemetry_gap":
            duration = float(raw_step.get("duration_seconds", 0))
            threshold = float(raw_step.get("threshold_seconds", 0))
            if duration < 0 or threshold <= 0:
                raise ValueError("Telemetry gap duration must be non-negative and threshold positive.")
            if duration > threshold:
                detected_at = timestamp + timedelta(seconds=threshold)
                new_alerts = [self._wrap_alert(
                    LOSS_OF_VIEW_RULE,
                    "CRITICAL",
                    f"No process telemetry arrived for {duration:g}s; visibility threshold is {threshold:g}s.",
                    {"gap_seconds": duration, "threshold_seconds": threshold},
                    detected_at,
                )]
                self._end_at = max(self._end_at, timestamp + timedelta(seconds=duration))
            step_details = {
                "gap_seconds": duration,
                "threshold_seconds": threshold,
            }
            self._timeline.append(TimelineEntry(
                timestamp,
                "TELEMETRY_GAP",
                step_details,
                techniques_for_scenario(self.scenario["techniques"]),
            ))
        else:
            state = SISState.from_payload(raw_step["state"])
            sis_result = self._sis_watch.check(state, timestamp=timestamp)
            if sis_result.status == "CRITICAL":
                new_alerts = [self._wrap_alert(
                    "SIS_BASELINE_CHANGE",
                    "CRITICAL",
                    sis_result.message,
                    {
                        "changed_fields": sis_result.changed_fields,
                        "baseline_hash": sis_result.baseline_hash,
                        "observed_hash": sis_result.observed_hash,
                    },
                    timestamp,
                )]
            step_details = sis_result.as_dict()
            self._timeline.append(TimelineEntry(
                timestamp,
                "SIS_BASELINE_CHECK",
                step_details,
                techniques_for_scenario(self.scenario["techniques"]),
            ))

        for alert in new_alerts:
            self._alerts.append(alert)
            self._seen_rules.add(alert.rule_id)
            if self._detection_time is None:
                self._detection_time = max(
                    0.0, (alert.timestamp - self.started_at).total_seconds()
                )
            self._timeline.append(TimelineEntry(
                alert.timestamp,
                "ALERT",
                alert.as_dict(),
                alert.techniques,
            ))
        return {
            "step": self._step_index,
            "total_steps": len(self._steps),
            "complete": self.complete,
            "timestamp": timestamp.isoformat(),
            "details": step_details,
            "alerts": [alert.as_dict() for alert in new_alerts],
        }

    def result(self) -> ScenarioResult:
        """Return current metrics; final status is COMPLETE or IN_PROGRESS."""
        expected = list(self.scenario["expected_rules"])
        missed = [rule for rule in expected if rule not in self._seen_rules]
        false_positives = sum(
            1 for alert in self._alerts if alert.rule_id not in expected
        )
        return ScenarioResult(
            scenario_id=self.scenario["id"],
            scenario_name=self.scenario["name"],
            status="COMPLETE" if self.complete else "IN_PROGRESS",
            started_at=self.started_at,
            ended_at=self._end_at,
            detection_time_seconds=self._detection_time,
            expected_rules=expected,
            detected_rules=sorted(self._seen_rules),
            missed_steps=missed,
            false_positive_count=false_positives,
            alerts=list(self._alerts),
            timeline=list(self._timeline),
        )

    def _wrap_alert(
        self,
        rule_id: str,
        severity: str,
        message: str,
        evidence: dict[str, Any],
        timestamp: datetime,
    ) -> ScenarioAlert:
        techniques = techniques_for_alert(rule_id)
        return ScenarioAlert(
            timestamp=timestamp,
            rule_id=rule_id,
            severity=severity,
            message=message,
            evidence=evidence,
            techniques=techniques,
        )

    @staticmethod
    def _event_from_record(record: dict[str, Any]) -> OTEvent:
        from chem_shield_p8.ot_monitor.events import parse_event

        return parse_event(record)

    @staticmethod
    def _zone_alert(
        decision: FlowDecision, event_id: str, timestamp: datetime
    ):
        from chem_shield_p8.ot_monitor.rules import Alert

        digest = json.dumps(
            [event_id, decision.rule_id], separators=(",", ":")
        ).encode("utf-8")
        import hashlib

        return Alert(
            alert_id=hashlib.sha256(digest).hexdigest()[:16],
            event_id=event_id,
            timestamp=timestamp,
            rule_id=decision.rule_id,
            severity=decision.severity,
            message=decision.message,
            source_ip=str(decision.evidence["source_ip"]),
            destination_ip=str(decision.evidence["destination_ip"]),
            evidence=decision.evidence,
        )
