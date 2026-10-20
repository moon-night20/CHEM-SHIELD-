"""Start the complete CHEM-SHIELD simulation on loopback."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import ipaddress
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TextIO
import socket


REPO_ROOT = Path(__file__).resolve().parents[1]
LOOPBACK_HOST = "127.0.0.1"
PLC_PORT = 15020
HMI_PORT = 15000
PLC_READY_TIMEOUT = 30.0
SHUTDOWN_TIMEOUT = 5.0


@dataclass
class ChildProcess:
    name: str
    process: subprocess.Popen
    log_thread: threading.Thread


def _loopback_host(host: str) -> str:
    if host.lower() == "localhost":
        return LOOPBACK_HOST
    try:
        address = ipaddress.ip_address(host)
    except ValueError as error:
        raise ValueError("host must be the loopback address 127.0.0.1") from error
    if not address.is_loopback:
        raise ValueError("refusing non-loopback host; use 127.0.0.1")
    if str(address) != LOOPBACK_HOST:
        raise ValueError("this demo is configured to bind specifically to 127.0.0.1")
    return LOOPBACK_HOST


def build_commands(
    python_executable: str = sys.executable,
    host: str = LOOPBACK_HOST,
) -> list[tuple[str, list[str]]]:
    """Return the four server commands in README startup order."""

    safe_host = _loopback_host(host)
    return [
        (
            "PLC",
            [
                python_executable,
                "-m",
                "chem_shield_p1.plc.modbus_plc",
                "--host",
                safe_host,
                "--port",
                str(PLC_PORT),
            ],
        ),
        (
            "Process",
            [
                python_executable,
                "-m",
                "chem_shield_p1.process.main",
                "--host",
                safe_host,
                "--port",
                str(PLC_PORT),
                "--database",
                "chem_shield_p1/data/telemetry.db",
            ],
        ),
        (
            "HMI",
            [
                python_executable,
                "-m",
                "chem_shield_p1.hmi.app",
                "--host",
                safe_host,
                "--port",
                str(HMI_PORT),
                "--plc-port",
                str(PLC_PORT),
                "--database",
                "chem_shield_p1/data/telemetry.db",
            ],
        ),
        ("Admin", [python_executable, "-m", "admin_part.app"]),
    ]


def wait_for_port(
    host: str,
    port: int,
    process: subprocess.Popen,
    timeout: float = PLC_READY_TIMEOUT,
) -> None:
    """Wait until the loopback PLC port accepts a connection."""

    deadline = time.monotonic() + timeout
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("PLC process exited before its port became ready")
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError as error:
            last_error = error
            time.sleep(0.2)
    raise TimeoutError(
        f"PLC did not become ready at {host}:{port} within {timeout:g}s: {last_error}"
    )


def _stream_logs(name: str, output: TextIO, stream: TextIO, lock: threading.Lock) -> None:
    for line in iter(output.readline, ""):
        with lock:
            print(f"[{name}] {line}", end="", file=stream, flush=True)
    output.close()


def start_services(
    host: str = LOOPBACK_HOST,
    *,
    python_executable: str = sys.executable,
    process_factory: Callable[..., subprocess.Popen] = subprocess.Popen,
    readiness_probe: Callable[..., None] = wait_for_port,
    stream: TextIO = sys.stdout,
) -> list[ChildProcess]:
    """Start children in dependency order, after the PLC is accepting connections."""

    safe_host = _loopback_host(host)
    children: list[ChildProcess] = []
    log_lock = threading.Lock()
    try:
        for index, (name, command) in enumerate(
            build_commands(python_executable, safe_host)
        ):
            process = process_factory(
                command,
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            if process.stdout is None:
                raise RuntimeError(f"{name} process did not provide a log stream")
            log_thread = threading.Thread(
                target=_stream_logs,
                args=(name, process.stdout, stream, log_lock),
                daemon=True,
            )
            child = ChildProcess(name, process, log_thread)
            children.append(child)
            log_thread.start()
            if index == 0:
                readiness_probe(safe_host, PLC_PORT, process, PLC_READY_TIMEOUT)
    except BaseException:
        stop_services(children)
        raise
    return children


def stop_services(children: Sequence[ChildProcess]) -> None:
    """Stop children in reverse startup order and wait for clean termination."""

    for child in reversed(children):
        if child.process.poll() is None:
            child.process.terminate()
    for child in reversed(children):
        try:
            child.process.wait(timeout=SHUTDOWN_TIMEOUT)
        except subprocess.TimeoutExpired:
            child.process.kill()
            child.process.wait()
        child.log_thread.join(timeout=SHUTDOWN_TIMEOUT)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Start the loopback-only CHEM-SHIELD PLC, simulator, HMI, and admin console."
    )
    parser.add_argument(
        "--host",
        default=LOOPBACK_HOST,
        help="Loopback bind address (only 127.0.0.1 is supported).",
    )
    args = parser.parse_args(argv)

    children: list[ChildProcess] = []
    try:
        children = start_services(args.host)
        print(
            f"All services started on loopback. HMI: http://{LOOPBACK_HOST}:{HMI_PORT} "
            f"Admin: http://{LOOPBACK_HOST}:5000. Press Ctrl+C to stop.",
            flush=True,
        )
        while True:
            for child in children:
                return_code = child.process.poll()
                if return_code is not None:
                    raise RuntimeError(
                        f"{child.name} process exited unexpectedly with status {return_code}"
                    )
            time.sleep(0.2)
    except KeyboardInterrupt:
        print("Stopping CHEM-SHIELD demo...", flush=True)
        return 0
    finally:
        stop_services(children)


if __name__ == "__main__":
    raise SystemExit(main())
