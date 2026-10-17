"""Run the strict sequential P2 -> P3 -> P4 -> P5 simulation chain."""

from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path
from typing import Any, Callable

from chem_shield_common.publisher import DEFAULT_HMI_URL, publish_events

from scripts.chain import p2, p3, p4, p5
from scripts.chain.contracts import (
    ContractError,
    load_json,
    validate_event_list,
    validate_p2_handoff,
    validate_p4_incidents,
    validate_p5_report,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TELEMETRY = (
    REPO_ROOT / "chem_shield_p5" / "ot_monitor" / "samples" / "abnormal_telemetry.csv"
)
STAGE_LABELS = {1: "P2", 2: "P3", 3: "P4", 4: "P5"}


def _read_stage_json(
    path: Path, producer: str, validator: Callable[[Any], Any]
) -> Any:
    return validator(load_json(path, producer))


def _print_p2_summary(payload: dict[str, Any]) -> None:
    events = payload["events"]
    handoff = payload["handoff"]
    if handoff["window"] is None:
        window_text = "none"
    else:
        window_text = f"{handoff['window']['start']}..{handoff['window']['end']}"
    print(
        f"[P2] {len(events)} events, {handoff['anomalous_event_count']} above threshold, "
        f"window {window_text}"
    )


def _print_p3_summary(payload: dict[str, Any], p2_payload: dict[str, Any]) -> None:
    event_count = len(payload["events"])
    if not p2_payload["handoff"]["asset_ids"]:
        print("[P3] no network trigger; 0 telemetry rows scored, 0 physical anomalies")
    else:
        print(f"[P3] {payload['rows_scored']} telemetry rows scored, {event_count} physical anomalies")


def _print_p4_summary(incidents: list[dict[str, Any]]) -> None:
    if incidents:
        highest = max(
            incidents,
            key=lambda item: float(item["risk_score"]),
        )
        print(
            f"[P4] {len(incidents)} incidents, highest risk "
            f"{highest['risk_level']} ({highest['risk_score']})"
        )
    else:
        print("[P4] 0 incidents, highest risk NONE (n/a)")


def _pause_for_step(stage: int, enabled: bool) -> None:
    if not enabled:
        return
    label = STAGE_LABELS[stage]
    if sys.stdin.isatty():
        input(f"[{label}] ready; press Enter to run this stage...")
    else:
        print(f"[step-by-step] starting {label}")


def _combined_incident_exists(incidents: list[dict[str, Any]]) -> bool:
    for incident in incidents:
        event_types = {event["event_type"] for event in incident["events"]}
        if {"network", "physical"}.issubset(event_types):
            return True
    return False


def _verify_combined_when_expected(
    p2_payload: dict[str, Any],
    p3_events: list[dict[str, Any]],
    incidents: list[dict[str, Any]],
) -> None:
    if (
        p2_payload["handoff"]["anomalous_event_count"] > 0
        and p3_events
        and not _combined_incident_exists(incidents)
    ):
        raise ContractError(
            "P4 returned no incident containing both network and physical events "
            "although both stages produced qualifying events; check the 10-second "
            "correlation window and shared asset_id"
        )


def _publish_if_requested(
    enabled: bool,
    hmi_url: str,
    p2_path: Path,
    p3_path: Path,
) -> None:
    if not enabled:
        return
    p2_payload = _read_stage_json(p2_path, "P2", validate_p2_handoff)
    p3_events = _read_stage_json(
        p3_path,
        "P3",
        lambda value: validate_event_list(value, "P3", "physical"),
    )
    result = publish_events([*p2_payload["events"], *p3_events], url=hmi_url)
    if result["failed_batches"] or result["rejected"]:
        raise RuntimeError(
            "HMI publish failed: "
            f"{result['failed_batches']} failed batch(es), "
            f"{result['rejected']} rejected event(s); {result['errors']}"
        )
    print(
        f"[HMI] published P2/P3 events to loopback endpoint: "
        f"{result['accepted']} accepted"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the sequential, file-backed P2 -> P3 -> P4 -> P5 chain"
    )
    parser.add_argument(
        "--network-input",
        default=str(p2.DEFAULT_NETWORK_INPUT),
        help="P2 network fixture in JSON or JSONL format",
    )
    parser.add_argument("--telemetry", default=str(DEFAULT_TELEMETRY), help="Telemetry CSV for P3 and P5")
    parser.add_argument("--out-dir", default="out/", help="Directory for stage handoff JSON files")
    parser.add_argument("--threshold", type=float, default=0.5, help="P2 anomaly threshold in [0, 1]")
    parser.add_argument("--publish", action="store_true", help="Publish P2/P3 events to the loopback HMI")
    parser.add_argument("--hmi-url", default=DEFAULT_HMI_URL, help="Loopback HMI event endpoint")
    parser.add_argument("--from-stage", type=int, default=1, help="First chain stage to execute (1=P2, 4=P5)")
    parser.add_argument("--to-stage", type=int, default=4, help="Last chain stage to execute (1=P2, 4=P5)")
    parser.add_argument(
        "--step-by-step",
        action="store_true",
        help="Pause before each stage in an interactive terminal; show boundaries otherwise",
    )
    args = parser.parse_args(argv)

    if not math.isfinite(args.threshold) or not 0.0 <= args.threshold <= 1.0:
        parser.error("--threshold must be a finite number within [0, 1]")
    if not 1 <= args.from_stage <= 4 or not 1 <= args.to_stage <= 4:
        parser.error("--from-stage and --to-stage must be between 1 and 4")
    if args.from_stage > args.to_stage:
        parser.error("--from-stage must not be greater than --to-stage")

    output_dir = Path(args.out_dir)
    paths = {
        1: output_dir / "p2_events.json",
        2: output_dir / "p3_events.json",
        3: output_dir / "p4_incidents.json",
        4: output_dir / "p5_report.json",
    }
    telemetry_path = Path(args.telemetry)

    try:
        p2_payload = None
        p3_events = None
        p4_incidents = None
        for stage in range(args.from_stage, args.to_stage + 1):
            _pause_for_step(stage, args.step_by_step)
            label = STAGE_LABELS[stage]
            try:
                if stage == 1:
                    result = p2.run(
                        args.network_input,
                        paths[1],
                        threshold=args.threshold,
                    )
                    p2_payload = _read_stage_json(paths[1], "P2", validate_p2_handoff)
                    _print_p2_summary(p2_payload)
                elif stage == 2:
                    p2_payload = _read_stage_json(paths[1], "P2", validate_p2_handoff)
                    result = p3.run(paths[1], telemetry_path, paths[2])
                    p3_events = _read_stage_json(
                        paths[2],
                        "P3",
                        lambda value: validate_event_list(value, "P3", "physical"),
                    )
                    _print_p3_summary(result, p2_payload)
                elif stage == 3:
                    p2_payload = _read_stage_json(paths[1], "P2", validate_p2_handoff)
                    p3_events = _read_stage_json(
                        paths[2],
                        "P3",
                        lambda value: validate_event_list(value, "P3", "physical"),
                    )
                    p4_incidents = p4.run(paths[1], paths[2], paths[3])
                    p4_incidents = _read_stage_json(
                        paths[3], "P4", validate_p4_incidents
                    )
                    _verify_combined_when_expected(p2_payload, p3_events, p4_incidents)
                    _print_p4_summary(p4_incidents)
                else:
                    p4_incidents = _read_stage_json(
                        paths[3], "P4", validate_p4_incidents
                    )
                    p2_payload = _read_stage_json(paths[1], "P2", validate_p2_handoff)
                    p3_events = _read_stage_json(
                        paths[2],
                        "P3",
                        lambda value: validate_event_list(value, "P3", "physical"),
                    )
                    _verify_combined_when_expected(p2_payload, p3_events, p4_incidents)
                    reports = p5.run(paths[3], telemetry_path, paths[4])
                    _read_stage_json(paths[4], "P5", validate_p5_report)
                    confirmations = sum(report["rule_confirmation"] for report in reports)
                    print(f"[P5] {confirmations} rule-confirmed incidents")
            except (ContractError, OSError, ValueError, RuntimeError, TypeError, KeyError) as exc:
                raise RuntimeError(f"Stage {stage} ({label}) failed: {exc}") from exc

        _publish_if_requested(args.publish, args.hmi_url, paths[1], paths[2])
    except (ContractError, OSError, ValueError, RuntimeError, TypeError, KeyError) as exc:
        print(f"CHAIN FAILED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
