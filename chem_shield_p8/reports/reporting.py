"""Generate self-contained HTML and PDF incident reports from dashboard data."""

from __future__ import annotations

import html
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


@dataclass(frozen=True)
class ReportFiles:
    """Generated report artifacts and their shared identifier."""

    report_id: str
    html_path: Path
    pdf_path: Path


def generate_incident_report(
    snapshot: dict[str, Any],
    output_dir: str | Path,
) -> ReportFiles:
    """Write HTML and PDF exports using only the supplied local snapshot."""
    if not isinstance(snapshot, dict):
        raise ValueError("Incident report snapshot must be an object.")
    report_id, created_at = _report_identity()
    target_dir = Path(output_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    html_path = target_dir / f"incident-{report_id}.html"
    pdf_path = target_dir / f"incident-{report_id}.pdf"
    html_path.write_text(_render_html(snapshot, report_id, created_at), encoding="utf-8")
    _render_pdf(snapshot, report_id, created_at, pdf_path)
    return ReportFiles(report_id, html_path, pdf_path)


def _report_identity() -> tuple[str, datetime]:
    created_at = datetime.now(timezone.utc)
    report_id = created_at.strftime("%Y%m%dT%H%M%S_%fZ")
    return report_id, created_at


def _list_items(snapshot: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = snapshot.get(key, [])
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _section(title: str, body: str) -> str:
    return f"<section><h2>{html.escape(title)}</h2>{body}</section>"


def _html_table(headers: list[str], rows: list[list[Any]], empty: str) -> str:
    if not rows:
        rows = [[empty] + [""] * (len(headers) - 1)]
    head = "".join(f"<th>{html.escape(header)}</th>" for header in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in row) + "</tr>"
        for row in rows
    )
    return f"<div class=\"table-wrap\"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"


def _render_html(snapshot: dict[str, Any], report_id: str, created_at: datetime) -> str:
    plant = snapshot.get("plant") if isinstance(snapshot.get("plant"), dict) else {}
    physics = snapshot.get("physics_guard") if isinstance(snapshot.get("physics_guard"), dict) else {}
    compliance = snapshot.get("compliance") if isinstance(snapshot.get("compliance"), dict) else {}
    alerts = _list_items(snapshot, "alerts")
    timeline = _list_items(snapshot, "timeline")
    assets = _list_items(snapshot, "assets")
    response = snapshot.get("response") if isinstance(snapshot.get("response"), dict) else {}
    decisions = response.get("decisions", [])
    if not isinstance(decisions, list):
        decisions = []
    decisions = [item for item in decisions if isinstance(item, dict)]
    scenario = snapshot.get("scenario") if isinstance(snapshot.get("scenario"), dict) else {}
    result = scenario.get("result") if isinstance(scenario.get("result"), dict) else {}

    alert_rows = [
        [
            item.get("timestamp", ""),
            item.get("severity", ""),
            item.get("rule_id", ""),
            f"{item.get('message', '')}; {_detail_summary(item.get('evidence'))}",
            ", ".join(
                f"{technique.get('id', '')} {technique.get('name', '')}"
                for technique in item.get("techniques", [])
                if isinstance(technique, dict)
            ),
        ]
        for item in alerts
    ]
    timeline_rows = [
        [
            item.get("timestamp", ""),
            item.get("event_type", ""),
            _detail_summary(item.get("detail")),
            ", ".join(
                str(technique.get("id", ""))
                for technique in item.get("techniques", [])
                if isinstance(technique, dict)
            ),
        ]
        for item in timeline
    ]
    asset_rows = [
        [
            item.get("device_id", ""),
            item.get("role", ""),
            item.get("ip_address", ""),
            item.get("first_seen", ""),
            item.get("last_seen", ""),
        ]
        for item in assets
    ]
    response_rows = [
        [
            item.get("playbook_id", ""),
            item.get("status", ""),
            item.get("proposed_by", ""),
            item.get("approved_by") or "—",
            _detail_summary(item.get("result")),
        ]
        for item in decisions
    ]

    recommendations = _recommendations(alerts, result, decisions)
    recommendation_html = "<ul>" + "".join(
        f"<li>{html.escape(item)}</li>" for item in recommendations
    ) + "</ul>"
    sections = [
        _section(
            "Executive summary",
            "<p>This report summarizes the current local CHEM-SHIELD Part 8 simulation snapshot. "
            "It does not represent a live plant assessment.</p>"
            f"<p><strong>Threat level:</strong> {html.escape(str(snapshot.get('threat_level', 'NORMAL')))}"
            f" &nbsp; <strong>Scenario:</strong> {html.escape(str(result.get('scenario_name', 'No scenario active')))}"
            f" &nbsp; <strong>Alerts:</strong> {len(alerts)}"
            f" &nbsp; <strong>Snapshot:</strong> {html.escape(str(snapshot.get('timestamp', '—')))}</p>",
        ),
        _section(
            "Process state",
            _html_table(
                ["Tag", "Value"],
                [
                    ["Temperature", f"{plant.get('temperature_c', '—')} °C"],
                    ["Pressure", f"{plant.get('pressure_bar', '—')} bar"],
                    ["Level", f"{plant.get('level_pct', '—')} %"],
                    ["Flow", f"{plant.get('flow_l_min', '—')} L/min"],
                    ["Coolant valve", f"{plant.get('coolant_valve_pct', '—')} %"],
                    ["Feed pump", plant.get("feed_pump_on", "—")],
                    ["Relief valve", plant.get("relief_valve_open", "—")],
                    ["Physics score", physics.get("physics_score", "—")],
                    ["ML deviation score", physics.get("ml_score", "—")],
                    ["Zone posture score", compliance.get("score", "—")],
                ],
                "No process values available.",
            ),
        ),
        _section(
            "Alert evidence and ATT&CK for ICS",
            _html_table(
                ["Time", "Severity", "Detection", "Evidence summary", "Technique"],
                alert_rows,
                "No alerts were present in this snapshot.",
            ),
        ),
        _section(
            "Incident timeline",
            _html_table(
                ["Time", "Event", "Details", "ATT&CK IDs"],
                timeline_rows,
                "No timeline entries were present in this snapshot.",
            ),
        ),
        _section(
            "Affected assets",
            _html_table(
                ["Asset", "Role", "Address", "First seen", "Last seen"],
                asset_rows,
                "No assets were discovered in this replay.",
            ),
        ),
        _section(
            "Response actions",
            _html_table(
                ["Playbook", "Decision", "Proposed by", "Approved by", "Simulated result"],
                response_rows,
                "No response actions were proposed.",
            ),
        ),
        _section("Recommendations", recommendation_html),
    ]
    styles = """
      :root{color-scheme:light;--ink:#172a30;--muted:#53676c;--line:#d5e0e2;--accent:#176b59}
      *{box-sizing:border-box}body{margin:0;background:#edf2f2;color:var(--ink);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
      main{max-width:1120px;margin:28px auto;padding:34px;background:#fff;border:1px solid var(--line);border-radius:14px}
      header{border-bottom:3px solid var(--accent);padding-bottom:18px}h1{margin:0;font-size:28px}h2{font-size:18px;margin:0 0 12px;color:var(--accent)}
      .meta{color:var(--muted);font-size:12px;margin-top:8px}section{margin:24px 0}p{margin:8px 0}
      .table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:12px}th,td{padding:8px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line);overflow-wrap:anywhere}
      th{background:#f1f6f5;color:#28443e}li{margin:7px 0}.notice{margin-top:22px;padding:12px;background:#fff6e7;border-left:4px solid #ce8a23;color:#684817;font-size:12px}
      @media print{body{background:#fff}main{max-width:none;margin:0;border:0;padding:10mm;border-radius:0}section{break-inside:avoid}}
    """
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>CHEM-SHIELD incident report {html.escape(report_id)}</title><style>{styles}</style></head><body><main>"
        "<header><h1>CHEM-SHIELD · Incident Report</h1>"
        f"<div class=\"meta\">Report {html.escape(report_id)} · Generated {html.escape(created_at.isoformat())} · Part 8 local simulation</div></header>"
        + "".join(sections)
        + "<p class=\"notice\">Simulation evidence only. Do not use this report as a live process-safety or compliance certification.</p>"
        "</main></body></html>"
    )


def _render_pdf(
    snapshot: dict[str, Any],
    report_id: str,
    created_at: datetime,
    output_path: Path,
) -> None:
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        textColor=colors.HexColor("#176b59"),
        spaceAfter=5 * mm,
    ))
    styles.add(ParagraphStyle(
        name="ReportSection",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#176b59"),
        spaceBefore=5 * mm,
        spaceAfter=2 * mm,
    ))
    styles.add(ParagraphStyle(
        name="ReportSmall",
        parent=styles["BodyText"],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#354b50"),
    ))
    story: list[Any] = [
        Paragraph("CHEM-SHIELD · Incident Report", styles["ReportTitle"]),
        Paragraph(
            f"Report {html.escape(report_id)} · Generated {html.escape(created_at.isoformat())} · "
            "Part 8 local simulation",
            styles["ReportSmall"],
        ),
        Spacer(1, 4 * mm),
    ]
    _append_pdf_section(
        story,
        "Executive summary",
        [["Metric", "Value"], [
            "Threat level",
            snapshot.get("threat_level", "NORMAL"),
        ], [
            "Scenario",
            _scenario_name(snapshot),
        ], [
            "Alert count",
            len(_list_items(snapshot, "alerts")),
        ], [
            "Snapshot time",
            snapshot.get("timestamp", "—"),
        ]],
        styles,
    )
    plant = snapshot.get("plant") if isinstance(snapshot.get("plant"), dict) else {}
    physics = snapshot.get("physics_guard") if isinstance(snapshot.get("physics_guard"), dict) else {}
    compliance = snapshot.get("compliance") if isinstance(snapshot.get("compliance"), dict) else {}
    _append_pdf_section(
        story,
        "Process state",
        [
            ["Tag", "Value"],
            ["Temperature", f"{plant.get('temperature_c', '—')} °C"],
            ["Pressure", f"{plant.get('pressure_bar', '—')} bar"],
            ["Level", f"{plant.get('level_pct', '—')} %"],
            ["Flow", f"{plant.get('flow_l_min', '—')} L/min"],
            ["Coolant valve", f"{plant.get('coolant_valve_pct', '—')} %"],
            ["Feed pump", plant.get("feed_pump_on", "—")],
            ["Relief valve", plant.get("relief_valve_open", "—")],
            ["Physics score", physics.get("physics_score", "—")],
            ["ML deviation score", physics.get("ml_score", "—")],
            ["Zone posture score", compliance.get("score", "—")],
        ],
        styles,
    )
    alerts = _list_items(snapshot, "alerts")
    _append_pdf_section(
        story,
        "Alert evidence and ATT&CK for ICS",
        [["Time", "Severity", "Detection / evidence", "Technique IDs"]]
        + [
            [
                item.get("timestamp", ""),
                item.get("severity", ""),
                f"{item.get('rule_id', '')}: {item.get('message', '')}; "
                f"{_detail_summary(item.get('evidence'))}",
                ", ".join(
                    str(technique.get("id", ""))
                    for technique in item.get("techniques", [])
                    if isinstance(technique, dict)
                ),
            ]
            for item in alerts
        ],
        styles,
        empty="No alerts were present in this snapshot.",
    )
    timeline = _list_items(snapshot, "timeline")
    _append_pdf_section(
        story,
        "Incident timeline",
        [["Time", "Event", "Details", "ATT&CK IDs"]]
        + [
            [
                item.get("timestamp", ""),
                item.get("event_type", ""),
                _detail_summary(item.get("detail")),
                ", ".join(
                    str(technique.get("id", ""))
                    for technique in item.get("techniques", [])
                    if isinstance(technique, dict)
                ),
            ]
            for item in timeline
        ],
        styles,
        empty="No timeline entries were present in this snapshot.",
    )
    assets = _list_items(snapshot, "assets")
    _append_pdf_section(
        story,
        "Affected assets",
        [["Asset", "Role", "Address", "First seen", "Last seen"]]
        + [
            [
                item.get("device_id", ""),
                item.get("role", ""),
                item.get("ip_address", ""),
                item.get("first_seen", ""),
                item.get("last_seen", ""),
            ]
            for item in assets
        ],
        styles,
        empty="No assets were discovered in this replay.",
    )
    response = snapshot.get("response") if isinstance(snapshot.get("response"), dict) else {}
    decisions = response.get("decisions", [])
    if not isinstance(decisions, list):
        decisions = []
    _append_pdf_section(
        story,
        "Response actions",
        [["Playbook", "Decision", "Proposed by", "Approved by", "Simulated result"]]
        + [
            [
                item.get("playbook_id", ""),
                item.get("status", ""),
                item.get("proposed_by", ""),
                item.get("approved_by") or "—",
                _detail_summary(item.get("result")),
            ]
            for item in decisions
            if isinstance(item, dict)
        ],
        styles,
        empty="No response actions were proposed.",
    )
    result = _scenario_result(snapshot)
    _append_pdf_section(
        story,
        "Recommendations",
        [["Recommendation"]]
        + [[item] for item in _recommendations(alerts, result, decisions)],
        styles,
    )
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph(
        "Simulation evidence only. This report is not a live process-safety assessment or compliance certification.",
        styles["ReportSmall"],
    ))
    document = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
        title=f"CHEM-SHIELD Incident Report {report_id}",
        author="CHEM-SHIELD Part 8 Simulation",
    )
    document.build(story)


def _append_pdf_section(
    story: list[Any],
    title: str,
    rows: list[list[Any]],
    styles: Any,
    *,
    empty: str = "No data available.",
) -> None:
    story.append(Paragraph(html.escape(title), styles["ReportSection"]))
    if len(rows) <= 1:
        rows = [["Details"], [empty]]
    safe_rows = [
        [
            Paragraph(html.escape(_display(value)), styles["ReportSmall"])
            for value in row
        ]
        for row in rows
    ]
    column_count = max(len(row) for row in safe_rows)
    table = Table(
        safe_rows,
        repeatRows=1,
        colWidths=[(A4[0] - 30 * mm) / column_count] * column_count,
        hAlign="LEFT",
    )
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eaf2f0")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#173d34")),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d5e0e2")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.extend([table, Spacer(1, 2 * mm)])


def _detail_summary(value: Any) -> str:
    if isinstance(value, dict):
        return "; ".join(f"{key}: {item}" for key, item in value.items())
    if isinstance(value, list):
        return "; ".join(_display(item) for item in value)
    return _display(value)


def _display(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, (dict, list)):
        return _detail_summary(value)
    return str(value)


def _scenario_result(snapshot: dict[str, Any]) -> dict[str, Any]:
    scenario = snapshot.get("scenario")
    if not isinstance(scenario, dict) or not isinstance(scenario.get("result"), dict):
        return {}
    return scenario["result"]


def _scenario_name(snapshot: dict[str, Any]) -> str:
    return str(_scenario_result(snapshot).get("scenario_name", "No scenario active"))


def _recommendations(
    alerts: list[dict[str, Any]],
    scenario_result: dict[str, Any],
    decisions: list[Any],
) -> list[str]:
    recommendations: list[str] = []
    if not alerts:
        recommendations.append(
            "No scenario alerts were present in this snapshot; continue monitoring the simulated process."
        )
    else:
        high_alerts = [
            item for item in alerts
            if str(item.get("severity", "")).upper() in {"HIGH", "CRITICAL"}
        ]
        if high_alerts:
            recommendations.append(
                "Review HIGH/CRITICAL detection evidence and confirm the simulated process state with the operator."
            )
        recommendations.append(
            "Validate alert evidence and ATT&CK mappings against the selected synthetic scenario before tuning detection rules."
        )
    if scenario_result.get("missed_steps"):
        recommendations.append(
            "Investigate missed expected detection rules before using this scenario to evaluate detector coverage."
        )
    if any(
        isinstance(item, dict) and item.get("status") == "PENDING_APPROVAL"
        for item in decisions
    ):
        recommendations.append(
            "Review pending response proposals; no response action takes effect until an operator approves it."
        )
    recommendations.append(
        "All telemetry, responses, and process values in this report are simulated and local to CHEM-SHIELD Part 8."
    )
    return recommendations
