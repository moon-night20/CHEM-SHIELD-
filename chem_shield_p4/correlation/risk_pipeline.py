"""Normalize, correlate, score, and persist alert events for the HMI."""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any, Dict, List, Optional

try:
    from .correlation_engine import CorrelationEngine
    from .incident_store import IncidentStore, is_fresh
    from .validator import EventValidator
except ImportError:
    from correlation_engine import CorrelationEngine
    from incident_store import IncidentStore, is_fresh
    from validator import EventValidator

try:
    from ..risk_engine.risk_engine import RiskEngine
except ImportError:
    from chem_shield_p4.risk_engine.risk_engine import RiskEngine


class RiskPipeline:
    """Risk alerts remain independent from physical telemetry and PLC controls."""

    def __init__(
        self,
        store: IncidentStore,
        correlation_window_seconds: float = 10.0,
        criticality_by_asset: Optional[Dict[str, float]] = None,
    ) -> None:
        self.store = store
        self.correlation_window_seconds = correlation_window_seconds
        self.criticality_by_asset = criticality_by_asset or {}
        self.risk_engine = RiskEngine()
        self.validator = EventValidator()

    def ingest(self, raw_events: Any) -> dict:
        if not isinstance(raw_events, list):
            raise ValueError("Request must contain an event object or a list of event objects.")
        normalized: List[dict] = []
        errors: List[dict] = []
        local_ids: set[str] = set()
        duplicate_count = 0
        for index, raw in enumerate(raw_events):
            try:
                item = self._normalize(raw)
                if item["event_id"] in local_ids:
                    duplicate_count += 1
                    continue
                local_ids.add(item["event_id"])
                normalized.append(item)
            except (TypeError, ValueError) as exc:
                errors.append({"index": index, "message": str(exc)})

        already_seen = self.store.seen_event_ids(item["event_id"] for item in normalized)
        candidates = [item for item in normalized if item["event_id"] not in already_seen]
        raw_correlation_events = [dict(item) for item in candidates]
        validated, validation_errors = self.validator.validate_many(
            raw_correlation_events, require_anomaly_score=False
        )
        for error in validation_errors:
            errors.append({"index": error.index, "message": error.message})
        groups = CorrelationEngine(self.correlation_window_seconds).correlate_events(validated)

        saved_incidents: List[dict] = []
        accepted_ids: List[str] = []
        for group in groups:
            new_events = [event.to_dict() for event in group.events]
            old_start = group.start_time.isoformat().replace("+00:00", "Z")
            old_end = group.end_time.isoformat().replace("+00:00", "Z")
            existing = self.store.matching_active(
                group.asset_id, old_start, old_end, self.correlation_window_seconds
            )
            incident_id = existing["incident_id"] if existing else f"INC-{uuid.uuid4().hex[:12].upper()}"
            merged_events = list(existing["events"]) if existing else []
            existing_ids = {event["event_id"] for event in merged_events}
            merged_events.extend(
                event for event in new_events if event["event_id"] not in existing_ids
            )
            merged_events.sort(key=lambda event: (event["timestamp"], event["event_id"]))

            network_scores = [
                event["anomaly_score"]
                for event in merged_events
                if event["event_type"] == "network" and event.get("anomaly_score") is not None
            ]
            physical_scores = [
                event["anomaly_score"]
                for event in merged_events
                if event["event_type"] == "physical" and event.get("anomaly_score") is not None
            ]
            assessment = None
            if network_scores or physical_scores:
                assessment = self.risk_engine.calculate_risk(
                    {
                        "incident_id": incident_id,
                        "asset_id": group.asset_id,
                        "max_network_score": max(network_scores) if network_scores else None,
                        "max_physical_score": max(physical_scores) if physical_scores else None,
                    },
                    self.criticality_by_asset,
                ).to_dict()
            incident = {
                "incident_id": incident_id,
                "asset_id": group.asset_id,
                "start_time": min(event["timestamp"] for event in merged_events),
                "end_time": max(event["timestamp"] for event in merged_events),
                "last_event_time": max(event["timestamp"] for event in merged_events),
                "risk_level": assessment["risk_level"] if assessment else "UNASSESSED",
                "risk_score": assessment["final_risk"] if assessment else None,
                "risk_assessment": assessment,
                "events": merged_events,
            }
            incident["status"] = "ACTIVE" if is_fresh(incident) else "HISTORICAL"
            saved_ids = self.store.save_incident(incident, new_events)
            if saved_ids:
                accepted_ids.extend(saved_ids)
                stored = self.store.get_incident(incident_id)
                if stored:
                    saved_incidents.append(stored)

        self.store.record_ingest(accepted=len(accepted_ids), rejected=len(errors))
        return {
            "accepted": len(accepted_ids),
            "duplicates": duplicate_count + len(normalized) - len(candidates),
            "rejected": len(errors),
            "errors": errors,
            "incidents": saved_incidents,
        }

    def _normalize(self, raw: Any) -> dict:
        if not isinstance(raw, dict):
            raise ValueError("Event must be a JSON object.")
        source = raw.get("source")
        if not isinstance(source, str) or not source.strip():
            raise ValueError("source must be a non-empty string.")
        source = source.strip()
        asset_id = raw.get("asset_id", raw.get("machine_id"))
        if not isinstance(asset_id, str) or not asset_id.strip():
            raise ValueError("asset_id (or machine_id) must be a non-empty string.")
        timestamp = raw.get("timestamp")
        detection_type = raw.get("event_type")
        if not isinstance(detection_type, str) or not detection_type.strip():
            raise ValueError("event_type must be a non-empty string.")
        category = self._category(source, raw.get("event_category"), detection_type)
        score = raw.get("anomaly_score")
        model = raw.get("model")
        if score is None and isinstance(model, dict):
            score = model.get("anomaly_score")
        correlation_input = {
            "timestamp": timestamp,
            "asset_id": asset_id.strip(),
            "event_type": category,
            "anomaly_score": score,
            "event_id": raw.get("event_id"),
            "source": source,
            "severity": raw.get("severity"),
            "evidence": raw.get("evidence"),
        }
        correlation_event = self.validator.validate_one(
            correlation_input, require_anomaly_score=False
        )
        normalized = correlation_event.to_dict()
        normalized["detection_type"] = detection_type.strip()
        for key, value in raw.items():
            if key not in {
                "timestamp", "asset_id", "machine_id", "event_type",
                "event_category", "anomaly_score", "event_id", "source",
                "severity", "evidence",
            }:
                normalized[key] = value
        try:
            canonical = json.dumps(
                raw, sort_keys=True, separators=(",", ":"), allow_nan=False
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Event must contain only finite JSON values: {exc}") from exc
        if normalized.get("event_id") is None:
            digest = hashlib.sha256(f"{source}:{canonical}".encode("utf-8")).hexdigest()[:24]
            normalized["event_id"] = f"EVT-{digest.upper()}"
        return normalized

    @staticmethod
    def _category(source: str, explicit: Any, detection_type: str) -> str:
        if explicit is not None:
            if explicit in ("network", "physical"):
                return explicit
            raise ValueError("event_category must be 'network' or 'physical'.")
        if detection_type.strip().lower() in ("network", "physical"):
            return detection_type.strip().lower()
        normalized_source = source.lower().replace("-", "_")
        if normalized_source.startswith(
            ("network", "zeek", "suricata", "modbus", "os_security")
        ):
            return "network"
        if normalized_source.startswith(("ot", "physical", "plc", "process")):
            return "physical"
        raise ValueError(
            "Cannot infer event category from source; provide event_category='network' or 'physical'."
        )
