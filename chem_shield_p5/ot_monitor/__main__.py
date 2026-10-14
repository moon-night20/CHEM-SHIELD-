"""Run the Part 5 OT monitor against CSV or the Part 1 SQLite store."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional, Sequence

from chem_shield_p1.ot_monitor.ot_monitor import main as _monitor_main


DEFAULT_CONFIG = Path(__file__).resolve().parent / "config.example.json"


def main(argv: Optional[Sequence[str]] = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if "--config" not in arguments:
        arguments.extend(["--config", str(DEFAULT_CONFIG)])
    return _monitor_main(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
