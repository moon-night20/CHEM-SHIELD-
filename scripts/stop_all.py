"""Stop CHEM-SHIELD services listening on their local demo ports."""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time

if __package__:
    from .run_all import (
        ADMIN_PORT,
        HMI_PORT,
        OT_CONSOLE_PORT,
        PLC_PORT,
        _all_processes,
        _is_chem_shield_process,
        _listener_details,
        _port_number,
    )
else:
    from run_all import (
        ADMIN_PORT,
        HMI_PORT,
        OT_CONSOLE_PORT,
        PLC_PORT,
        _all_processes,
        _is_chem_shield_process,
        _listener_details,
        _port_number,
    )

SHUTDOWN_TIMEOUT = 5.0


def stop_all(admin_port: int = ADMIN_PORT) -> int:
    """Terminate only CHEM-SHIELD processes bound to known service ports."""

    ports = tuple(dict.fromkeys((PLC_PORT, HMI_PORT, ADMIN_PORT, OT_CONSOLE_PORT, admin_port)))
    services: dict[int, str] = {}
    for pid, command in _all_processes():
        if _is_chem_shield_process(command):
            services[pid] = command
    for port in ports:
        for pid, command in _listener_details(port):
            if _is_chem_shield_process(command):
                services[pid] = command
            else:
                print(
                    f"Leaving unrelated process PID {pid} on port {port}: "
                    f"{command or 'process command unavailable'}",
                    file=sys.stderr,
                )

    if not services:
        print("No CHEM-SHIELD services are listening on the demo ports.")
        return 0

    for pid, command in services.items():
        print(f"Stopping CHEM-SHIELD process {pid}: {command}")
        try:
            if os.name == "nt":
                import subprocess

                subprocess.run(
                    ["taskkill", "/PID", str(pid), "/T"],
                    check=False,
                    capture_output=True,
                    text=True,
                )
            else:
                try:
                    process_group = os.getpgid(pid)
                except (AttributeError, ProcessLookupError, PermissionError):
                    process_group = -1
                if process_group == pid:
                    os.killpg(pid, signal.SIGTERM)
                else:
                    os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            continue

    deadline = time.monotonic() + SHUTDOWN_TIMEOUT
    remaining = set(services)
    while remaining and time.monotonic() < deadline:
        current_processes = dict(_all_processes())
        for pid in tuple(remaining):
            command = current_processes.get(pid, "")
            if not _is_chem_shield_process(command):
                remaining.remove(pid)
        if remaining:
            time.sleep(0.1)
    if remaining:
        print(
            "Timed out waiting for CHEM-SHIELD process(es): "
            + ", ".join(str(pid) for pid in sorted(remaining)),
            file=sys.stderr,
        )
        return 1
    print("CHEM-SHIELD services stopped.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Stop CHEM-SHIELD services on the local demo ports only."
    )
    parser.add_argument(
        "--admin-port",
        type=int,
        default=None,
        help="Admin console port (defaults to CHEM_SHIELD_ADMIN_PORT or 5000).",
    )
    args = parser.parse_args(argv)
    try:
        admin_port = _port_number(
            args.admin_port
            if args.admin_port is not None
            else os.environ.get("CHEM_SHIELD_ADMIN_PORT", ADMIN_PORT)
        )
    except ValueError as error:
        parser.error(str(error))
    return stop_all(admin_port)


if __name__ == "__main__":
    raise SystemExit(main())
