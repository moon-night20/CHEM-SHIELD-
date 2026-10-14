"""
CHEM-SHIELD Part 4 — command-line demonstration.

Shows:
    INPUT EVENTS
    → CORRELATED INCIDENTS
    → INCIDENT DETAILS

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


def load_events(path: Path) -> list:
    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)
    if isinstance(data, dict) and "events" in data:
        return data["events"]
    if isinstance(data, list):
        return data
    raise ValueError("JSON must be a list of events or an object with an 'events' list.")


def print_divider(title: str) -> None:
    print()
    print("=" * 60)
    print(title)
    print("=" * 60)


def format_optional_score(score) -> str:
    if score is None:
        return "n/a (no events of this type)"
    return f"{score:.2f}"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CHEM-SHIELD Part 4 — correlate network and physical anomalies."
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
    raw_events = load_events(input_path)

    engine = CorrelationEngine(time_window_seconds=args.window)
    incidents, errors = engine.correlate(raw_events)

    print_divider("INPUT EVENTS")
    print(f"File: {input_path}")
    print(f"Correlation window: {engine.time_window_seconds} seconds")
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

    print_divider("RISK ENGINE")
    risk_engine = RiskEngine()
    print("Risk calculation is intentionally not implemented in this version.")
    print("Later, call: RiskEngine().calculate_risk(incident)")
    print(f"Interface ready. Incidents available for risk: {len(incidents)}")
    # Keep a reference so the future interface is obvious in the demo.
    _ = risk_engine


if __name__ == "__main__":
    main()
