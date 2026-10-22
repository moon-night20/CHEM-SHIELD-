"""Start the complete CHEM-SHIELD simulation on loopback."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import ipaddress
import os
import signal
import secrets
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
OT_CONSOLE_PORT = 5001
ADMIN_PORT = 5000
SERVICE_PORTS = (PLC_PORT, HMI_PORT, ADMIN_PORT, OT_CONSOLE_PORT)
SERVICE_COMMANDS = (
    "chem_shield_p1.plc.modbus_plc",
    "chem_shield_p1.process.main",
    "chem_shield_p1.hmi.app",
    "admin_part.app",
    "the_attack.app",
)
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


def _port_number(value: str | int) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError("Admin port must be an integer from 1 to 65535") from error
    if not 1 <= port <= 65535:
        raise ValueError("Admin port must be an integer from 1 to 65535")
    return port


def _port_pids(port: int) -> list[int]:
    if os.name == "nt":
        result = subprocess.run(
            ["netstat", "-ano", "-p", "tcp"],
            check=False,
            capture_output=True,
            text=True,
        )
        pids = set()
        for line in result.stdout.splitlines():
            fields = line.split()
            if (
                len(fields) >= 5
                and fields[0].upper() == "TCP"
                and fields[1].rsplit(":", 1)[-1] == str(port)
                and fields[3].upper() == "LISTENING"
            ):
                try:
                    pids.add(int(fields[4]))
                except ValueError:
                    continue
        return sorted(pids)
    try:
        result = subprocess.run(
            ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-t"],
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return []
    pids = set()
    for value in result.stdout.splitlines():
        try:
            pids.add(int(value.strip()))
        except ValueError:
            continue
    return sorted(pids)


def _process_command(pid: int) -> str:
    if os.name == "nt":
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"(Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}').CommandLine",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    else:
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "command="],
            check=False,
            capture_output=True,
            text=True,
        )
    return result.stdout.strip()


def _all_processes() -> list[tuple[int, str]]:
    if os.name == "nt":
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-CimInstance Win32_Process | ForEach-Object "
                "{ \"$($_.ProcessId)`t$($_.CommandLine)\" }",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    else:
        result = subprocess.run(
            ["ps", "-axo", "pid=,command="],
            check=False,
            capture_output=True,
            text=True,
        )
    processes = []
    for line in result.stdout.splitlines():
        fields = line.strip().split(maxsplit=1)
        if len(fields) < 2:
            continue
        try:
            processes.append((int(fields[0]), fields[1]))
        except ValueError:
            continue
    return processes


def _is_chem_shield_process(command: str) -> bool:
    normalized = command.casefold()
    return any(module in normalized for module in SERVICE_COMMANDS)


def _listener_details(port: int) -> list[tuple[int, str]]:
    return [(pid, _process_command(pid)) for pid in _port_pids(port)]


def ensure_ports_available(
    admin_port: int = ADMIN_PORT,
    *,
    kill_old: bool = False,
    stream: TextIO | None = None,
) -> None:
    """Report busy service ports and optionally stop only identified lab services."""

    output = stream or sys.stderr
    admin_port = _port_number(admin_port)
    ports = tuple(dict.fromkeys((*SERVICE_PORTS, admin_port)))
    blocked: list[int] = []
    if kill_old:
        old_services = [
            (pid, command)
            for pid, command in _all_processes()
            if pid != os.getpid() and _is_chem_shield_process(command)
        ]
        for pid, command in old_services:
            print(f"Stopping old CHEM-SHIELD service PID {pid}: {command}", file=output)
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                continue
        if old_services:
            deadline = time.monotonic() + SHUTDOWN_TIMEOUT
            while time.monotonic() < deadline and any(
                pid != os.getpid() and _is_chem_shield_process(command)
                for pid, command in _all_processes()
            ):
                time.sleep(0.1)
    for port in ports:
        listeners = _listener_details(port)
        if not listeners:
            continue
        for pid, command in listeners:
            if (
                port == ADMIN_PORT
                and sys.platform == "darwin"
                and any(token in command.casefold() for token in ("controlcenter", "airplay"))
            ):
                print(
                    "Port 5000 is used by macOS AirPlay Receiver — turn it off in "
                    "System Settings → General → AirDrop & Handoff, or start Admin "
                    "on another port.",
                    file=output,
                )
            print(
                f"Port {port} is in use by PID {pid}: {command or 'process command unavailable'}",
                file=output,
            )
            if kill_old and _is_chem_shield_process(command):
                print(f"Stopping CHEM-SHIELD process {pid}.", file=output)
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    continue
            elif port != ADMIN_PORT or admin_port == ADMIN_PORT:
                blocked.append(port)
                if not kill_old:
                    print(
                        "If this is an old CHEM-SHIELD service, rerun with --kill-old; "
                        "unrelated programs will not be stopped.",
                        file=output,
                    )
        if kill_old and any(
            _is_chem_shield_process(command) for _, command in listeners
        ):
            deadline = time.monotonic() + SHUTDOWN_TIMEOUT
            while time.monotonic() < deadline and _port_pids(port):
                time.sleep(0.1)
            remaining = _listener_details(port)
            if remaining and (port != ADMIN_PORT or admin_port == ADMIN_PORT):
                blocked.append(port)
                for pid, command in remaining:
                    print(
                        f"Port {port} remains in use by PID {pid}: {command}",
                        file=output,
                    )
    if blocked:
        raise RuntimeError(
            "Cannot start CHEM-SHIELD while required ports are occupied: "
            + ", ".join(str(port) for port in sorted(set(blocked)))
        )


def build_commands(
    python_executable: str = sys.executable,
    host: str = LOOPBACK_HOST,
    admin_port: int | None = None,
) -> list[tuple[str, list[str]]]:
    """Return the local demo service commands in README startup order."""

    safe_host = _loopback_host(host)
    selected_admin_port = _port_number(
        admin_port
        if admin_port is not None
        else os.environ.get("CHEM_SHIELD_ADMIN_PORT", ADMIN_PORT)
    )
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
        (
            "Admin",
            [
                python_executable,
                "-m",
                "admin_part.app",
                "--port",
                str(selected_admin_port),
            ],
        ),
        (
            "OT Console",
            [
                python_executable,
                "-m",
                "the_attack.app",
                "--host",
                safe_host,
                "--port",
                str(OT_CONSOLE_PORT),
                "--plc-port",
                str(PLC_PORT),
                "--database",
                "chem_shield_p1/data/telemetry.db",
            ],
        ),
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
    admin_port: int | None = None,
) -> list[ChildProcess]:
    """Start children in dependency order, after the PLC is accepting connections."""

    safe_host = _loopback_host(host)
    child_environment = dict(os.environ)
    child_environment.setdefault(
        "CHEM_SHIELD_INGEST_TOKEN",
        secrets.token_urlsafe(32),
    )
    selected_admin_port = _port_number(
        admin_port
        if admin_port is not None
        else child_environment.get("CHEM_SHIELD_ADMIN_PORT", ADMIN_PORT)
    )
    child_environment["CHEM_SHIELD_ADMIN_PORT"] = str(selected_admin_port)
    children: list[ChildProcess] = []
    log_lock = threading.Lock()
    try:
        for index, (name, command) in enumerate(
            build_commands(python_executable, safe_host, selected_admin_port)
        ):
            process = process_factory(
                command,
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=child_environment,
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
    parser.add_argument(
        "--admin-port",
        type=int,
        default=None,
        help="Admin console port (defaults to CHEM_SHIELD_ADMIN_PORT or 5000).",
    )
    parser.add_argument(
        "--kill-old",
        action="store_true",
        help="Stop only old CHEM-SHIELD processes holding required service ports.",
    )
    args = parser.parse_args(argv)

    children: list[ChildProcess] = []
    try:
        admin_port = _port_number(
            args.admin_port
            if args.admin_port is not None
            else os.environ.get("CHEM_SHIELD_ADMIN_PORT", ADMIN_PORT)
        )
        ensure_ports_available(admin_port, kill_old=args.kill_old)
        children = start_services(args.host, admin_port=admin_port)
        print(
            f"All services started on loopback. HMI: http://{LOOPBACK_HOST}:{HMI_PORT} "
            f"Admin: http://{LOOPBACK_HOST}:{admin_port} OT Console: "
            f"http://{LOOPBACK_HOST}:{OT_CONSOLE_PORT}. Press Ctrl+C to stop.",
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
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Startup failed: {error}", file=sys.stderr, flush=True)
        return 1
    finally:
        stop_services(children)


if __name__ == "__main__":
    raise SystemExit(main())
