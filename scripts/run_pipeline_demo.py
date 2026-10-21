"""Run the fixture-based P2/P5 pipeline against the loopback Part 1 HMI."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import urlopen

from chem_shield_common.publisher import DEFAULT_HMI_URL


REPO_ROOT = Path(__file__).resolve().parents[1]


def _risk_url(hmi_url: str) -> tuple[str, int]:
    parsed = urlsplit(hmi_url)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1":
        raise ValueError("--hmi-url must use http://127.0.0.1")
    port = parsed.port or 80
    return (
        urlunsplit((parsed.scheme, parsed.netloc, "/api/risk", "", "")),
        port,
    )


def _get_risk_summary(url: str) -> dict:
    with urlopen(url, timeout=2.0) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict) or "recent_incidents" not in payload:
        raise ValueError("HMI /api/risk response has an unexpected shape")
    return payload


def _wait_for_hmi(url: str, process: subprocess.Popen | None) -> None:
    deadline = time.monotonic() + 10.0
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError("HMI process exited before becoming ready")
        try:
            _get_risk_summary(url)
            return
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
            last_error = exc
            time.sleep(0.2)
    raise RuntimeError(
        f"HMI did not become ready at {url}: {last_error}. "
        "Start the HMI first, then export CHEM_SHIELD_INGEST_TOKEN with the "
        "same token configured for the HMI."
    )


def _demo_environment(
    environ: dict[str, str] | None = None,
    *,
    temporary_hmi: bool = False,
) -> dict[str, str]:
    environment = dict(os.environ if environ is None else environ)
    if temporary_hmi and not environment.get("CHEM_SHIELD_INGEST_TOKEN"):
        environment["CHEM_SHIELD_INGEST_TOKEN"] = secrets.token_urlsafe(32)
    return environment


def _run_producer(command: list[str], env: dict[str, str]) -> None:
    completed = subprocess.run(
        command,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    if completed.returncode:
        raise RuntimeError(
            f"Producer command failed ({completed.returncode}): {' '.join(command)}\n"
            f"{completed.stderr or completed.stdout}"
        )


def _correlated_incidents(summary: dict) -> list[dict]:
    results = []
    for incident in summary.get("recent_incidents", []):
        events = incident.get("events", [])
        event_types = sorted({
            event.get("event_type")
            for event in events
            if event.get("event_type") in {"network", "physical"}
        })
        if event_types == ["network", "physical"] and incident.get("risk_score") is not None:
            results.append({
                "incident_id": incident.get("incident_id"),
                "asset_id": incident.get("asset_id"),
                "risk_level": incident.get("risk_level"),
                "risk_score": incident.get("risk_score"),
                "event_types": event_types,
                "event_count": len(events),
            })
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run fixture-based P2 network and P5 physical events through the Part 1 HMI"
    )
    parser.add_argument(
        "--hmi-url",
        default=DEFAULT_HMI_URL,
        help=f"Loopback HMI risk-event URL (default: {DEFAULT_HMI_URL})",
    )
    parser.add_argument(
        "--start-hmi",
        action="store_true",
        help="Start a temporary Part 1 HMI if one is not already responding",
    )
    args = parser.parse_args(argv)
    risk_url, port = _risk_url(args.hmi_url)

    process = None
    temp_dir = tempfile.TemporaryDirectory(prefix="chem-shield-pipeline-")
    try:
        try:
            _get_risk_summary(risk_url)
            hmi_responding = True
        except (HTTPError, URLError, TimeoutError, OSError, ValueError):
            hmi_responding = False
        if hmi_responding and not os.environ.get("CHEM_SHIELD_INGEST_TOKEN"):
            raise RuntimeError(
                "An existing HMI requires its configured CHEM_SHIELD_INGEST_TOKEN "
                "for publishing. Export CHEM_SHIELD_INGEST_TOKEN with the same "
                "token configured for the HMI, then restart the runner."
            )
        child_environment = _demo_environment(
            temporary_hmi=not hmi_responding and args.start_hmi
        )
        if not hmi_responding:
            if not args.start_hmi:
                _wait_for_hmi(risk_url, None)
            else:
                database = str(Path(temp_dir.name) / "pipeline-demo.db")
                process = subprocess.Popen(
                    [
                        sys.executable,
                        "-m",
                        "chem_shield_p1.hmi.app",
                        "--host",
                        "127.0.0.1",
                        "--port",
                        str(port),
                        "--plc-port",
                        "15020",
                        "--database",
                        database,
                    ],
                    cwd=REPO_ROOT,
                    env=child_environment,
                )
                _wait_for_hmi(risk_url, process)

        _run_producer([
            sys.executable,
            "-m",
            "chem_shield_p2.replay_events",
            "--input",
            "chem_shield_p2/fixtures/sample_network_events.json",
            "--publish",
            "--hmi-url",
            args.hmi_url,
        ], env=child_environment)
        _run_producer([
            sys.executable,
            "-m",
            "chem_shield_p5.ot_monitor",
            "--csv",
            "chem_shield_p5/ot_monitor/samples/abnormal_telemetry.csv",
            "--config",
            "chem_shield_p5/ot_monitor/config.example.json",
            "--publish",
            "--hmi-url",
            args.hmi_url,
        ], env=child_environment)

        summary = _get_risk_summary(risk_url)
        correlated = _correlated_incidents(summary)
        print(json.dumps({
            "correlated_incidents": correlated,
            "hmi_summary_risk_level": summary.get("risk_level"),
            "hmi_summary_risk_score": summary.get("risk_score"),
        }, indent=2))
        if not correlated:
            raise RuntimeError(
                "No scored incident containing both network and physical events "
                "was returned; check event timestamps, asset mappings, and HMI logs."
            )
        return 0
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        temp_dir.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
