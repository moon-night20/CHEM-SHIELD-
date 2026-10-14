# Part 4: Event Correlation, Risk, and HMI Integration

Part 4 consumes already-normalized detections from the separate network and
physical-process detectors. It groups events and computes a transparent
experimental risk score. It does not operate a PLC, infer that an event is an
attack, or automatically remediate anything.

## Compatibility and architecture

The canonical risk implementation is
[`../risk_engine/`](../risk_engine/). The thin compatibility wrapper in
[`risk_engine.py`](./risk_engine.py) re-exports the canonical package and keeps
older imports working. Existing correlation, physical telemetry, and Part 1
SQLite tables remain in place.

```text
P1 simulated telemetry -> P5 validation/rules + P3 physical model ─┐
P2 fixture replay + network model ─────────────────────────────────┤
                                                                   └─ shared publisher
                                                                      -> POST /api/risk/events
                                                                      -> normalize/correlate/score
                                                                      -> SQLite + HMI dashboard
```

## Data flow

P2 and P5 publish only when explicitly run with `--publish`; these are
foreground fixture/monitor commands, not background services. The publisher is
restricted to `127.0.0.1`. Part 4 groups events by asset and time at the HMI.
No detector or Part 4 component actuates equipment or performs mitigation.

## Event input

Submit one event or `{"events": [...]}` to `POST /api/risk/events`:

```json
{
  "event_id": "demo-physical-01",
  "timestamp": "2026-10-14T09:30:04Z",
  "source": "ot_monitor",
  "asset_id": "PLC-01",
  "event_type": "physical",
  "severity": "high",
  "evidence": {
    "adapter_event_type": "temperature_high",
    "note": "Synthetic demonstration only"
  },
  "anomaly_score": 0.90,
  "measurements": {"temperature": 92.0, "unit": "degC"}
}
```

The normalized `event_type` must be exactly `"network"` or `"physical"`.
Producer-specific types such as `temperature_high` belong in evidence.
`asset_id` may be supplied as `machine_id`. ISO-8601 timestamps are normalized
to UTC. The event category may also be set explicitly using
`event_category: "network"` or `"physical"`; otherwise it is inferred from
recognized source names (`zeek`, `suricata`, `modbus`, `os_security`,
`network_*`, `ot_*`, `physical_*`, or `plc_*`). Evidence, measurements,
severity, and other JSON details are retained.

An optional detector score must be finite and in `[0, 1]`. It is a detector
score, **not an attack probability**. If a rule event has no score, it is still
correlated and persisted, but its incident is `UNASSESSED`; the pipeline does
not manufacture a zero score. P2/P5 publishing sends scored events only.
Missing modalities in an otherwise scored incident continue to contribute
zero under the pre-existing Part 4 formula.
That formula does not establish whether a detector/source is healthy; the
input status is reported separately.

Duplicate event IDs are suppressed across request batches. Events are grouped
by asset when adjacent timestamps are no more than 10 seconds apart. An event
close to an active incident extends that incident; the stored score is
recomputed using the maximum available score per modality. A later score may
escalate the incident. Acknowledgement is recorded separately and does not
lower risk or resolve an incident. There is intentionally no automatic
resolution path.

## Existing risk calculation

The canonical `RiskEngine` preserves the existing project parameters:

```text
base_risk  = 0.40 * network_score + 0.60 * physical_score
final_risk = base_risk * asset_criticality
```

Default criticality is `1.0`. The classification boundaries remain:

| Final score | Classification |
| --- | --- |
| `< 0.30` | LOW |
| `0.30` to `< 0.60` | MEDIUM |
| `0.60` to `< 0.80` | HIGH |
| `>= 0.80` | CRITICAL |

These weights, boundaries, and default criticality are experimental CHEM-SHIELD
settings, not validated safety limits or cybersecurity standards. Scores are
bounded to `[0, 1]`; high scores are not calibrated probabilities.

## API and persistence

- `GET /api/risk` — highest active assessed risk, active/recent incidents,
  ingest status, score scale, and explicit non-probability declaration.
- `POST /api/risk/events` — validate, normalize, correlate, score, and persist
  submitted events. Mixed valid/invalid batches return per-event errors.
- `GET /api/incidents?limit=50&active=true` — incident history.
- `GET /api/incidents/<incident_id>` — incident evidence and lifecycle state.
- `POST /api/incidents/<incident_id>/acknowledge` — record the operator and
  timestamp; does not clear the alert.

The HMI adds `risk_incidents`, `risk_events`, and `risk_ingest_state` tables to
the configured SQLite file. Its existing `telemetry` and `events` schemas are
unchanged. The risk register stores evidence and survives HMI restarts.

The Flask application has no authentication layer. Bind it to `127.0.0.1` and
use sanitized fixtures only; do not expose it to production networks.

## Run the local HMI and send a synthetic example

From the repository root, use the combined project environment:

```bash
.venv/bin/python -m chem_shield_p1.hmi.app \
  --host 127.0.0.1 --port 15000 --plc-port 5020 \
  --database chem_shield_p1/data/telemetry.db
```

The HMI can report an unavailable PLC independently of the Part 4 risk API. For
a local synthetic event test:

```bash
curl -X POST http://127.0.0.1:15000/api/risk/events \
  -H 'Content-Type: application/json' \
  -d '{"events":[{"event_id":"demo-net-01","timestamp":"2026-10-14T09:30:00Z","source":"network_model","asset_id":"PLC-01","event_type":"network","anomaly_score":0.9,"evidence":{"fixture":"synthetic"}},{"event_id":"demo-ot-01","timestamp":"2026-10-14T09:30:04Z","source":"ot_monitor","asset_id":"PLC-01","event_type":"physical","anomaly_score":0.9,"evidence":{"fixture":"synthetic"}}]}'
```

The payload scores and timestamps above are illustrative inputs, not measured
detector results. To acknowledge an incident, use its returned ID:

```bash
curl -X POST http://127.0.0.1:15000/api/incidents/INC-ID/acknowledge \
  -H 'Content-Type: application/json' -d '{"acknowledged_by":"operator"}'
```

## Tests

```bash
.venv/bin/python -m pytest -q
```

Tests cover grouping, score calculation and validation, unscored events,
deduplication, escalation, additive SQLite storage, acknowledgements, and HMI
routes with a deliberately disconnected loopback PLC.

## Integration status and limitations

Completed: canonical risk engine; compatibility re-export; event
normalization and correlation; deduplication; additive SQLite incident/event
persistence; history/detail/acknowledgement API; HMI risk summary, evidence
register, severity filtering, acknowledgement, and high/critical notification
dialog.

Connected by explicit CLI invocation: P2's network replay and P5's physical
monitor use the publisher with `--publish`; they do not stream in the
background. There is no source heartbeat contract, source-specific score
calibration, authentication, manual resolution workflow, or production-device
integration. P5 uses P3's physical model; P2's network model remains a
separate fixture-trained detector.
