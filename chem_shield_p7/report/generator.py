"""Generate safe, self-contained HTML incident reports."""

from __future__ import annotations

import html
import re
from pathlib import Path
from string import Template
from typing import Any

REPORT_ID_PATTERN = re.compile(r"^[a-f0-9]{32}$")


def _text(value: Any) -> str:
    """Escape every dynamic value before placing it in HTML."""
    return html.escape(str(value if value is not None else "Not recorded"), quote=True)


def _duration(started_at: str, ended_at: str | None) -> str:
    from datetime import datetime

    if not ended_at:
        return "Not recorded"
    try:
        start = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        end = datetime.fromisoformat(ended_at.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return "Not recorded"
    return f"{max(0.0, (end - start).total_seconds()):.2f} s"


def generate_report(
    report_id: str,
    run: dict[str, Any],
    *,
    output_dir: str | Path,
    limits: dict[str, float],
    peak_readings: dict[str, float],
    audit_status: dict[str, Any],
) -> Path:
    """Write one report under output_dir using a generated UUID-like identifier."""
    if not REPORT_ID_PATTERN.fullmatch(report_id):
        raise ValueError("Report identifier is invalid.")
    output = Path(output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    target = (output / f"{report_id}.html").resolve()
    if target.parent != output:
        raise ValueError("Report path is outside the report directory.")

    started = run.get("started_at", "")
    events = run.get("events", [])
    rows = []
    for event in events:
        detail = event.get("detail") or {}
        tags = ", ".join(
            f"{item.get('id', '')} {item.get('name', '')}"
            for item in event.get("mitre", [])
            if isinstance(item, dict)
        )
        offset = "Not available"
        if started and event.get("timestamp"):
            offset = _duration(started, event["timestamp"])
        rows.append(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                _text(offset),
                _text(event.get("event_type")),
                _text(event.get("detector") or event.get("source")),
                _text(detail.get("message") or detail),
                _text(tags or "Not mapped"),
            )
        )
    if not rows:
        rows.append('<tr><td colspan="5">No timeline events were recorded.</td></tr>')

    reading_rows = []
    for sensor in ("temperature", "pressure", "power", "speed"):
        value = peak_readings.get(sensor)
        limit = limits.get(sensor)
        reading_rows.append(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                _text(sensor.title()),
                _text(value if value is not None else "Not recorded"),
                _text(limit if limit is not None else "Not configured"),
            )
        )

    detection_latency = "Not detected"
    if run.get("detected_at") and started:
        detection_latency = _duration(started, run["detected_at"])
    response_time = "No operator response recorded"
    if run.get("detected_at") and run.get("responded_at"):
        response_time = _duration(run["detected_at"], run["responded_at"])

    scenario_name = _text(run.get("scenario_name"))
    run_id_text = _text(run.get("run_id"))
    outcome = _text(run.get("outcome") or run.get("status"))
    integrity = "INTACT" if audit_status.get("ok") else "TAMPERED / UNAVAILABLE"
    audit_count = audit_status.get("records", 0)
    summary = (
        f"The {run.get('scenario_name', 'scenario')} simulation was run against the local virtual PLC. "
        f"The system outcome was {run.get('outcome') or run.get('status')}. "
        f"Detection latency was {detection_latency}; operator response was {response_time}. "
        "Review sensor limits, response timing, and the audit integrity result before repeating the demo."
    )

    document = Template("""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CHEM-SHIELD Incident Report</title>
<style>
:root{color-scheme:light}body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:#172033;margin:2rem auto;max-width:1100px;padding:0 1.25rem;line-height:1.5}
h1,h2{color:#10213a}.meta,.summary{border:1px solid #c8d3e1;border-radius:8px;padding:1rem;margin:1rem 0}
table{width:100%;border-collapse:collapse;margin:1rem 0}th,td{border:1px solid #b8c3d1;padding:.55rem;text-align:left;vertical-align:top}th{background:#e9eff6}
.status{font-weight:700}.print{padding:.65rem 1rem;font:inherit}@media print{body{max-width:none;margin:0;padding:0}.print{display:none}.meta,.summary{break-inside:avoid}tr{break-inside:avoid}}
</style></head><body>
<p class="print">Use the browser Print command and choose Save as PDF.</p>
<h1>CHEM-SHIELD Incident Report</h1>
<section class="meta"><p><strong>Run ID:</strong> $run_id</p><p><strong>Scenario:</strong> $scenario</p>
<p><strong>Outcome:</strong> <span class="status">$outcome</span></p>
<p><strong>Started:</strong> $started</p><p><strong>Duration:</strong> $duration</p></section>
<h2>What happened / What the system did / Recommended follow-up</h2><section class="summary">$summary</section>
<h2>Timeline</h2><table><thead><tr><th>Offset</th><th>Event</th><th>Source / detector</th><th>Details</th><th>MITRE ATT&amp;CK for ICS</th></tr></thead><tbody>$timeline</tbody></table>
<h2>Peak readings vs. configured limits</h2><table><thead><tr><th>Sensor</th><th>Peak reading</th><th>Limit</th></tr></thead><tbody>$readings</tbody></table>
<h2>Response and integrity</h2><ul><li>Detection latency: $latency</li>
<li>Operator response time: $response_time</li><li>Machine stopped automatically: $automatic_stop</li>
<li>Audit-chain integrity at generation: $integrity ($audit_count records verified)</li></ul>
<p>This report describes a loopback-only simulation and is not a physical safety assessment.</p>
</body></html>""").substitute(
        run_id=run_id_text,
        scenario=scenario_name,
        outcome=outcome,
        started=_text(started or "Not recorded"),
        duration=_text(_duration(started, run.get("ended_at"))),
        summary=_text(summary),
        timeline="".join(rows),
        readings="".join(reading_rows),
        latency=_text(detection_latency),
        response_time=_text(response_time),
        automatic_stop=_text("Yes" if run.get("automatic_stop") else "No"),
        integrity=_text(integrity),
        audit_count=_text(audit_count),
    )
    with target.open("w", encoding="utf-8", newline="") as stream:
        stream.write(document)
    return target
