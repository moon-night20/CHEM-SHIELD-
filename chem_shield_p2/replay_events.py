#!/usr/bin/env python3
"""Offline replay and normalization for OT and network security log fixtures."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from chem_shield_p2.adapters import replay_events


BASE_DIR = Path(__file__).resolve().parent
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
    args = parser.parse_args()

    inputs = args.inputs or DEFAULT_INPUTS
    normalized = replay_events(inputs)

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
