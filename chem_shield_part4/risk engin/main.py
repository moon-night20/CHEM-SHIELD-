"""
CHEM-SHIELD Part 4 — command-line demonstration.

Shows:
    INPUT EVENTS
    → CORRELATION ENGINE
    → CORRELATED INCIDENTS
    → RISK ENGINE
    → RISK ASSESSMENT

Usage (from this folder, in VS Code or a terminal):
    python main.py
    python main.py --window 10
    python main.py --input sample_data.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from correlation_engine import DEFAULT_TIME_WINDOW_SECONDS, CorrelationEngine
from risk_engine import RiskEngine


def load_sample_file(path: Path) -> tuple:
    """Return (events, criticality_lookup) from the demo JSON file."""
    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if isinstance(data, list):
        return data, {}

    if not isinstance(data, dict):
        raise ValueError("JSON must be a list of events or an object with an 'events' list.")

    if "events" not in data:
        raise ValueError("JSON object must contain an 'events' list.")

    lookup = {}
    for asset in data.get("assets", []):
        lookup[asset["asset_id"]] = asset["criticality"]
    return data["events"], lookup


def print_divider(title: str) -> None:
    print()
    print("=" * 60)
    print(title)
    print("=" * 60)


def format_optional_score(score) -> str:
    if score is None:
        return "n/a (no events of this type)"
    return f"{score:.2f}"


def print_risk_assessment(assessment) -> None:
    print()
    print(f"Incident: {assessment.incident_id}")
    print(f"Asset: {assessment.asset_id}")
    print()
    print(f"Network score: {assessment.network_score:.2f}")
    print(f"Physical score: {assessment.physical_score:.2f}")
    print(f"Asset criticality: {assessment.asset_criticality:.1f}")
    print()
    print(f"Base risk: {assessment.base_risk:.3f}")
    print(f"Final risk: {assessment.final_risk:.3f}")
    print()
    print(f"Risk level: {assessment.risk_level}")
    print()
    print(assessment.explanation)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CHEM-SHIELD Part 4 — correlate events, then score incident risk."
    )
    parser.add_argument(
        "--input",
        default="sample_data.json",
        help="Path to JSON file with detector events (default: sample_data.json)",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=DEFAULT_TIME_WINDOW_SECONDS,
        help=f"Correlation time window in seconds (default: {DEFAULT_TIME_WINDOW_SECONDS})",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    raw_events, criticality_lookup = load_sample_file(input_path)

    correlation_engine = CorrelationEngine(time_window_seconds=args.window)
    incidents, errors = correlation_engine.correlate(raw_events)

    print_divider("INPUT EVENTS")
    print(f"File: {input_path}")
    print(f"Correlation window: {correlation_engine.time_window_seconds} seconds")
    print(f"Raw event count: {len(raw_events)}")
    print()
    for index, event in enumerate(raw_events, start=1):
        print(
            f"  {index}. {event.get('timestamp', '?')} | "
            f"{event.get('asset_id', '?')} | "
            f"{event.get('event_type', '?')} | "
            f"score={event.get('anomaly_score', '?')}"
        )

    if errors:
        print_divider("VALIDATION PROBLEMS (skipped, not correlated)")
        for error in errors:
            print(f"  Event index {error.index}: {error.message}")
            print(f"    raw = {error.raw_event}")

    print_divider("CORRELATED INCIDENTS")
    print(f"Incident count: {len(incidents)}")
    if not incidents:
        print("  No valid events to correlate.")
    else:
        for incident in incidents:
            print(
                f"  {incident.incident_id}: asset={incident.asset_id} "
                f"events={incident.number_of_events} "
                f"network={incident.network_present} "
                f"physical={incident.physical_present} "
                f"start={incident.start_time.isoformat()} "
                f"end={incident.end_time.isoformat()}"
            )

    print_divider("INCIDENT DETAILS")
    for incident in incidents:
        print()
        print(f"Incident ID:           {incident.incident_id}")
        print(f"Asset:                 {incident.asset_id}")
        print(f"Events:                {incident.number_of_events}")
        print(f"Network present:       {incident.network_present}")
        print(f"Physical present:      {incident.physical_present}")
        print(f"Start:                 {incident.start_time.isoformat()}")
        print(f"End:                   {incident.end_time.isoformat()}")
        print(f"Duration:              {incident.duration_seconds:.0f} seconds")
        print(f"Max network score:     {format_optional_score(incident.max_network_score)}")
        print(f"Max physical score:    {format_optional_score(incident.max_physical_score)}")
        print("Event list:")
        for event in incident.events:
            print(
                f"  - {event.timestamp.isoformat()} | {event.asset_id} | "
                f"{event.event_type} | {event.anomaly_score:.2f}"
            )

    # Correlation finished first. Risk only consumes that output.
    print_divider("RISK ENGINE")
    risk_engine = RiskEngine()
    assessments = risk_engine.calculate_risks(incidents, asset_criticality=criticality_lookup)
    if not assessments:
        print("No correlated incidents to score.")
    else:
        for assessment in assessments:
            print_risk_assessment(assessment)


if __name__ == "__main__":
    main()
