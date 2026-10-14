#!/usr/bin/env python3
"""Offline replay and normalization for OT and network security log fixtures."""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from chem_shield_common.publisher import DEFAULT_HMI_URL, publish_events
from chem_shield_p2.adapters import replay_events
from chem_shield_p2.network_scoring import (
    DEFAULT_MODEL,
    load_or_train_network_model,
    score_to_part4_events,
)


BASE_DIR = Path(__file__).resolve().parent
LOGGER = logging.getLogger(__name__)
DEFAULT_INPUTS = [
    str(BASE_DIR / "fixtures" / "sample_network_events.json"),
    str(BASE_DIR / "fixtures" / "zeek_conn.jsonl"),
    str(BASE_DIR / "fixtures" / "suricata_eve.jsonl"),
    str(BASE_DIR / "fixtures" / "modbus_monitor.json"),
    str(BASE_DIR / "fixtures" / "os_security.json"),
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay offline network logs and normalize them to a common schema")
    parser.add_argument("--input", dest="inputs", action="append", default=[], help="Path to a JSON or JSONL fixture. Repeat to include multiple files.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print the normalized output")
    parser.add_argument("--output", help="Optional JSON output path for normalized records")
    parser.add_argument(
        "--publish",
        action="store_true",
        help="Score events and publish them to the loopback Part 1 HMI",
    )
    parser.add_argument(
        "--hmi-url",
        default=DEFAULT_HMI_URL,
        help=f"Loopback Part 1 HMI risk endpoint (default: {DEFAULT_HMI_URL})",
    )
    args = parser.parse_args()

    inputs = args.inputs or DEFAULT_INPUTS
    normalized = replay_events(inputs)
    if args.publish:
        with (BASE_DIR / "config.example.json").open(encoding="utf-8") as stream:
            config = json.load(stream)
        model = load_or_train_network_model(DEFAULT_MODEL)
        normalized = score_to_part4_events(normalized, model, config)
        publish_events(normalized, url=args.hmi_url)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as handle:
            json.dump(normalized, handle, indent=2 if args.pretty else None)
            handle.write("\n")

    print(json.dumps(normalized, indent=2 if args.pretty else None))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
