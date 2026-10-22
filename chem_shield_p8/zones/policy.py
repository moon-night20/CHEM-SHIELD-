"""Policy checks for synthetic flows across configured Purdue zones."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml

from chem_shield_p8.ot_monitor.events import OTEvent

DEFAULT_ZONES = Path(__file__).resolve().parents[1] / "config" / "zones.yaml"
PURDUE_LEVELS = {"0", "1", "2", "3", "3.5", "4", "5"}


@dataclass(frozen=True)
class Zone:
    """One local policy zone."""

    zone_id: str
    name: str
    level: str
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    allowed_protocols: frozenset[str]


@dataclass(frozen=True)
class Conduit:
    """Explicit permitted path between two zones."""

    conduit_id: str
    name: str
    source_zone: str
    destination_zone: str
    allowed_protocols: frozenset[str]
    allowed_source_ips: frozenset[str]
    allowed_destination_ips: frozenset[str]


@dataclass(frozen=True)
class FlowDecision:
    """Policy verdict for one supplied flow event."""

    allowed: bool
    source_zone: str | None
    destination_zone: str | None
    conduit_id: str | None
    rule_id: str
    severity: str
    message: str
    evidence: dict[str, Any]


@dataclass(frozen=True)
class ComplianceCheck:
    """One scored policy posture check."""

    check_id: str
    passed: bool
    points: int
    evidence: str


@dataclass(frozen=True)
class ComplianceResult:
    """Transparent demo score based on policy structure and supplied flows."""

    score: int
    checks: list[ComplianceCheck]
    disclaimer: str = "Illustrative policy score; not IEC 62443/NIST certification."

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "checks": [
                {
                    "check_id": check.check_id,
                    "passed": check.passed,
                    "points": check.points,
                    "evidence": check.evidence,
                }
                for check in self.checks
            ],
            "disclaimer": self.disclaimer,
        }


class ZonePolicy:
    """Load and evaluate a local Purdue zone/conduit policy."""

    def __init__(
        self,
        zones: list[Zone],
        conduits: list[Conduit],
        penalties: dict[str, int],
        baseline_points: int = 100,
    ) -> None:
        self.zones = tuple(zones)
        self.conduits = tuple(conduits)
        self.penalties = dict(penalties)
        self.baseline_points = baseline_points
        self._validate_topology()

    @classmethod
    def load(cls, path: str | Path = DEFAULT_ZONES) -> "ZonePolicy":
        config_path = Path(path)
        try:
            with config_path.open(encoding="utf-8") as stream:
                document = yaml.safe_load(stream)
        except OSError as error:
            raise ValueError(f"Could not read zone policy {config_path}: {error}") from error
        except yaml.YAMLError as error:
            raise ValueError(f"Invalid zone policy YAML {config_path}: {error}") from error
        if not isinstance(document, dict):
            raise ValueError("Zone policy must contain a YAML mapping.")
        raw_zones = document.get("zones")
        raw_conduits = document.get("conduits")
        compliance = document.get("compliance", {})
        if not isinstance(raw_zones, list) or not isinstance(raw_conduits, list):
            raise ValueError("Zone policy must define zones and conduits lists.")
        if not isinstance(compliance, dict):
            raise ValueError("Zone policy compliance section must be a mapping.")

        zones = [_parse_zone(raw) for raw in raw_zones]
        conduits = [_parse_conduit(raw) for raw in raw_conduits]
        baseline = _integer(compliance.get("baseline_points", 100), "baseline_points")
        raw_penalties = compliance.get("penalties", {})
        if not isinstance(raw_penalties, dict):
            raise ValueError("Compliance penalties must be a mapping.")
        penalties = {
            str(name): _integer(value, f"penalties.{name}")
            for name, value in raw_penalties.items()
        }
        return cls(zones, conduits, penalties, baseline)

    def zone_for(self, address: str) -> Zone | None:
        """Find the unique policy zone containing an IP address."""
        ip = ipaddress.ip_address(address)
        matches = [
            zone
            for zone in self.zones
            if any(ip.version == network.version and ip in network for network in zone.networks)
        ]
        if len(matches) > 1:
            raise ValueError(f"IP address {address} maps to overlapping zones.")
        return matches[0] if matches else None

    def evaluate(self, event: OTEvent) -> FlowDecision:
        """Allow only same-zone policy traffic or an explicitly listed conduit."""
        source = self.zone_for(event.source_ip)
        destination = self.zone_for(event.destination_ip)
        evidence = {
            "source_ip": event.source_ip,
            "destination_ip": event.destination_ip,
            "protocol": event.protocol,
        }
        if source is None or destination is None:
            return FlowDecision(
                False,
                source.zone_id if source else None,
                destination.zone_id if destination else None,
                None,
                "UNKNOWN_ZONE_FLOW",
                "HIGH",
                "Flow endpoint is outside every configured Purdue zone.",
                evidence,
            )

        if source.zone_id == destination.zone_id:
            allowed = event.protocol in source.allowed_protocols
            return FlowDecision(
                allowed,
                source.zone_id,
                destination.zone_id,
                None,
                "SAME_ZONE_PROTOCOL" if allowed else "PROTOCOL_NOT_ALLOWED",
                "INFO" if allowed else "HIGH",
                (
                    f"Protocol {event.protocol} is permitted within {source.name}."
                    if allowed
                    else f"Protocol {event.protocol} is not permitted within {source.name}."
                ),
                evidence,
            )

        matching = [
            conduit
            for conduit in self.conduits
            if conduit.source_zone == source.zone_id
            and conduit.destination_zone == destination.zone_id
        ]
        if not matching:
            direct_it_to_control = (
                float(source.level) >= 4
                and float(destination.level) <= 1
            )
            rule_id = "DIRECT_IT_TO_CONTROL" if direct_it_to_control else "MISSING_CONDUIT"
            return FlowDecision(
                False,
                source.zone_id,
                destination.zone_id,
                None,
                rule_id,
                "CRITICAL" if direct_it_to_control else "HIGH",
                (
                    "Direct IT/enterprise communication to a control-level endpoint violates zone policy."
                    if direct_it_to_control
                    else f"No conduit permits traffic from {source.name} to {destination.name}."
                ),
                evidence,
            )

        conduit = matching[0]
        if event.protocol not in conduit.allowed_protocols:
            return FlowDecision(
                False,
                source.zone_id,
                destination.zone_id,
                conduit.conduit_id,
                "PROTOCOL_NOT_ALLOWED",
                "HIGH",
                f"Protocol {event.protocol} is not allowed on conduit {conduit.name}.",
                evidence,
            )
        if (
            conduit.allowed_source_ips
            and event.source_ip not in conduit.allowed_source_ips
        ) or (
            conduit.allowed_destination_ips
            and event.destination_ip not in conduit.allowed_destination_ips
        ):
            return FlowDecision(
                False,
                source.zone_id,
                destination.zone_id,
                conduit.conduit_id,
                "ENDPOINT_NOT_ALLOWED",
                "HIGH",
                f"Endpoint is not allowlisted on conduit {conduit.name}.",
                evidence,
            )
        return FlowDecision(
            True,
            source.zone_id,
            destination.zone_id,
            conduit.conduit_id,
            "CONDUIT_ALLOWED",
            "INFO",
            f"Flow is allowed by conduit {conduit.name}.",
            evidence,
        )

    def compliance(self, observed_flows: Iterable[OTEvent] = ()) -> ComplianceResult:
        """Calculate the explanatory policy score and list every scored check."""
        checks: list[ComplianceCheck] = []
        present_levels = {zone.level for zone in self.zones}
        missing_levels = sorted(PURDUE_LEVELS - present_levels, key=float)
        checks.append(ComplianceCheck(
            "PURDUE_LEVEL_COVERAGE",
            not missing_levels,
            15,
            "All Purdue levels 0-5 and the industrial DMZ are represented."
            if not missing_levels
            else f"Missing Purdue levels: {', '.join(missing_levels)}.",
        ))
        overlaps = self._overlapping_networks()
        checks.append(ComplianceCheck(
            "NON_OVERLAPPING_ZONES",
            not overlaps,
            20,
            "Configured zone subnets do not overlap."
            if not overlaps
            else f"Overlapping zone subnets: {', '.join(overlaps)}.",
        ))
        engineering_conduits = [
            conduit
            for conduit in self.conduits
            if conduit.source_zone == "engineering" and conduit.destination_zone == "control"
        ]
        restricted = bool(engineering_conduits) and all(
            conduit.allowed_source_ips and conduit.allowed_destination_ips
            for conduit in engineering_conduits
        )
        checks.append(ComplianceCheck(
            "RESTRICTED_ENGINEERING_CONDUIT",
            restricted,
            20,
            "Engineering-to-control conduit is constrained to explicit endpoint addresses."
            if restricted
            else "Engineering-to-control conduit is missing or does not restrict endpoints.",
        ))
        unsafe_conduits = [
            conduit.conduit_id
            for conduit in self.conduits
            if self._direct_high_to_low(conduit.source_zone, conduit.destination_zone)
        ]
        checks.append(ComplianceCheck(
            "NO_DIRECT_IT_TO_CONTROL_CONDUIT",
            not unsafe_conduits,
            20,
            "No conduit directly connects IT/enterprise levels to Level 0 or 1."
            if not unsafe_conduits
            else f"Unsafe direct conduits: {', '.join(unsafe_conduits)}.",
        ))

        decisions = [self.evaluate(event) for event in observed_flows]
        violations = [decision for decision in decisions if not decision.allowed]
        penalties_by_rule = {
            "UNKNOWN_ZONE_FLOW": "unknown_zone_flow",
            "DIRECT_IT_TO_CONTROL": "direct_it_to_control",
            "MISSING_CONDUIT": "missing_conduit",
            "PROTOCOL_NOT_ALLOWED": "protocol_not_allowed",
            "ENDPOINT_NOT_ALLOWED": "endpoint_not_allowed",
        }
        observed_penalty = sum(
            self.penalties.get(penalties_by_rule[decision.rule_id], 0)
            for decision in violations
            if decision.rule_id in penalties_by_rule
        )
        checks.append(ComplianceCheck(
            "OBSERVED_FLOW_POLICY",
            not violations,
            25,
            "All supplied synthetic flow events comply with configured zones/conduits."
            if not violations
            else f"{len(violations)} of {len(decisions)} supplied flows violate policy; "
            f"score penalty {observed_penalty} points.",
        ))
        max_points = sum(check.points for check in checks)
        passed_points = sum(check.points for check in checks if check.passed)
        flow_penalty = min(checks[-1].points, observed_penalty)
        score = max(
            0,
            min(100, round(self.baseline_points * passed_points / max_points) - flow_penalty),
        )
        return ComplianceResult(score=score, checks=checks)

    def _overlapping_networks(self) -> list[str]:
        entries = [
            (zone.zone_id, network)
            for zone in self.zones
            for network in zone.networks
        ]
        overlaps: list[str] = []
        for index, (zone_id, network) in enumerate(entries):
            for other_zone_id, other_network in entries[index + 1 :]:
                if zone_id != other_zone_id and network.version == other_network.version and network.overlaps(other_network):
                    overlaps.append(f"{zone_id}:{network} / {other_zone_id}:{other_network}")
        return overlaps

    def _validate_topology(self) -> None:
        ids = [zone.zone_id for zone in self.zones]
        if len(ids) != len(set(ids)) or any(not zone.zone_id for zone in self.zones):
            raise ValueError("Zone ids must be unique and non-empty.")
        known = set(ids)
        conduit_ids = [conduit.conduit_id for conduit in self.conduits]
        if len(conduit_ids) != len(set(conduit_ids)):
            raise ValueError("Conduit ids must be unique.")
        for conduit in self.conduits:
            if conduit.source_zone not in known or conduit.destination_zone not in known:
                raise ValueError(f"Conduit {conduit.conduit_id} references an unknown zone.")
            source_zone = next(zone for zone in self.zones if zone.zone_id == conduit.source_zone)
            destination_zone = next(
                zone for zone in self.zones if zone.zone_id == conduit.destination_zone
            )
            for address in conduit.allowed_source_ips:
                if not any(
                    ipaddress.ip_address(address).version == network.version
                    and ipaddress.ip_address(address) in network
                    for network in source_zone.networks
                ):
                    raise ValueError(
                        f"Conduit {conduit.conduit_id} allowlists a source outside its source zone."
                    )
            for address in conduit.allowed_destination_ips:
                if not any(
                    ipaddress.ip_address(address).version == network.version
                    and ipaddress.ip_address(address) in network
                    for network in destination_zone.networks
                ):
                    raise ValueError(
                        f"Conduit {conduit.conduit_id} allowlists a destination outside its destination zone."
                    )
        if self._overlapping_networks():
            raise ValueError("Configured zone networks must not overlap.")
        if self.baseline_points < 0 or self.baseline_points > 100:
            raise ValueError("Compliance baseline_points must be between 0 and 100.")

    def _direct_high_to_low(self, source_zone: str, destination_zone: str) -> bool:
        zones = {zone.zone_id: zone for zone in self.zones}
        source = zones[source_zone]
        destination = zones[destination_zone]
        source_level = float(source.level)
        destination_level = float(destination.level)
        return source_level >= 4 and destination_level <= 1


def compute_compliance(
    policy: ZonePolicy,
    observed_flows: Iterable[OTEvent] = (),
) -> ComplianceResult:
    """Public helper for the transparent non-certification demo score."""
    return policy.compliance(observed_flows)


def _parse_zone(raw: Any) -> Zone:
    if not isinstance(raw, dict):
        raise ValueError("Each zone must be a mapping.")
    zone_id = _non_empty_string(raw.get("id"), "zone.id")
    name = _non_empty_string(raw.get("name"), f"zone {zone_id} name")
    level = str(raw.get("level"))
    if level not in PURDUE_LEVELS:
        raise ValueError(f"Zone {zone_id} has invalid Purdue level {level}.")
    networks_value = raw.get("networks")
    protocols_value = raw.get("allowed_protocols")
    if not isinstance(networks_value, list) or not networks_value:
        raise ValueError(f"Zone {zone_id} must contain at least one network.")
    if not isinstance(protocols_value, list) or not all(isinstance(item, str) for item in protocols_value):
        raise ValueError(f"Zone {zone_id} allowed_protocols must be a string list.")
    try:
        networks = tuple(ipaddress.ip_network(item, strict=True) for item in networks_value)
    except ValueError as error:
        raise ValueError(f"Zone {zone_id} contains an invalid network: {error}") from error
    return Zone(zone_id, name, level, networks, frozenset(item.casefold() for item in protocols_value))


def _parse_conduit(raw: Any) -> Conduit:
    if not isinstance(raw, dict):
        raise ValueError("Each conduit must be a mapping.")
    conduit_id = _non_empty_string(raw.get("id"), "conduit.id")
    name = _non_empty_string(raw.get("name"), f"conduit {conduit_id} name")
    source = _non_empty_string(raw.get("source_zone"), f"conduit {conduit_id} source_zone")
    destination = _non_empty_string(
        raw.get("destination_zone"), f"conduit {conduit_id} destination_zone"
    )
    protocols = raw.get("allowed_protocols")
    if not isinstance(protocols, list) or not protocols or not all(isinstance(item, str) for item in protocols):
        raise ValueError(f"Conduit {conduit_id} must define allowed_protocols.")
    return Conduit(
        conduit_id=conduit_id,
        name=name,
        source_zone=source,
        destination_zone=destination,
        allowed_protocols=frozenset(item.casefold() for item in protocols),
        allowed_source_ips=_ip_set(raw.get("allowed_source_ips", []), conduit_id),
        allowed_destination_ips=_ip_set(raw.get("allowed_destination_ips", []), conduit_id),
    )


def _ip_set(values: Any, conduit_id: str) -> frozenset[str]:
    if not isinstance(values, list):
        raise ValueError(f"Conduit {conduit_id} IP allowlist must be a list.")
    try:
        return frozenset(str(ipaddress.ip_address(value)) for value in values)
    except (ValueError, TypeError) as error:
        raise ValueError(f"Conduit {conduit_id} contains an invalid IP allowlist.") from error


def _integer(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer.")
    return value


def _non_empty_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string.")
    return value.strip()
