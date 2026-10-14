# Part 4: Event Correlation, Risk, and HMI Integration

Part 4 consumes already-normalized detections from the separate network and
physical-process detectors. It groups events and computes a transparent
experimental risk score. It does not operate a PLC, infer that an event is an
attack, or automatically remediate anything.

## Compatibility and architecture

The canonical risk implementation is
[`../risk_engine/`](../risk_engine/). The former
[`../risk engin/`](../risk%20engin/) modules and
[`risk_engine.py`](./risk_engine.py) are compatibility paths. Existing
correlation, physical telemetry, and Part 1 SQLite tables remain in place.

```text
Part 2 network detections and flow scores ─┐
                                           ├─ POST /api/risk/events -> normalize
Part 3 physical ML scores ─────────────────┤                         -> correlate
Part 1/5 OT detections ────────────────────┘                         -> risk engine
                                                                     -> SQLite + HMI
```

Part 2, Part 3, and Part 5 are not automatically connected as background
services. A configured producer or operator must submit records to the HMI API.

## Event input

Submit one event or `{"events": [...]}` to `POST /api/risk/events`:

```json
{
  "event_id": "demo-physical-01",
  "timestamp": "2026-10-14T09:30:04Z",
  "source": "ot_monitor",
  "asset_id": "PLC-01",
  "event_type": "temperature_high",
  "severity": "high",
  "evidence": "Synthetic demonstration only",
  "anomaly_score": 0.90,
  "measurements": {"temperature": 92.0, "unit": "degC"}
}
```

`asset_id` may be supplied as `machine_id`. ISO-8601 timestamps are normalized
to UTC. The event category may be set explicitly using
`event_category: "network"` or `"physical"`; otherwise it is inferred from
recognized source names (`zeek`, `suricata`, `modbus`, `os_security`,
`network_*`, `ot_*`, `physical_*`, or `plc_*`). The original `event_type`,
evidence, measurements, severity, and other JSON details are retained.

An optional detector score must be finite and in `[0, 1]`. It is a detector
score, **not an attack probability**. If a rule event has no score, it is still
correlated and persisted, but its incident is `UNASSESSED`; the pipeline does
not manufacture a zero score. Missing modalities in an otherwise scored
incident continue to contribute zero under the pre-existing Part 4 formula.
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

From the repository root, use the Part 1 virtual environment:

```bash
chem_shield_p1/.venv/bin/python -m chem_shield_p1.hmi.app \
  --host 127.0.0.1 --port 15000 --plc-port 5020 \
  --database chem_shield_p1/data/telemetry.db
```

The HMI can report an unavailable PLC independently of the Part 4 risk API. For
a local synthetic event test:

```bash
curl -X POST http://127.0.0.1:15000/api/risk/events \
  -H 'Content-Type: application/json' \
  -d '{"events":[{"event_id":"demo-net-01","timestamp":"2026-10-14T09:30:00Z","source":"network_model","asset_id":"PLC-01","event_type":"network_anomaly","anomaly_score":0.9,"evidence":"synthetic"},{"event_id":"demo-ot-01","timestamp":"2026-10-14T09:30:04Z","source":"ot_monitor","asset_id":"PLC-01","event_type":"temperature_high","anomaly_score":0.9,"evidence":"synthetic"}]}'
```

This illustrative pair produces `0.40*0.9 + 0.60*0.9 = 0.90` and
`CRITICAL` under the configured experimental defaults. It is not a measured
result. To acknowledge an incident, use its returned ID:

```bash
curl -X POST http://127.0.0.1:15000/api/incidents/INC-ID/acknowledge \
  -H 'Content-Type: application/json' -d '{"acknowledged_by":"operator"}'
```

## Tests

```bash
chem_shield_p1/.venv/bin/python -m unittest discover \
  -s chem_shield_p4/correlation/tests -v
chem_shield_p1/.venv/bin/python -m unittest discover \
  -s 'chem_shield_p4/risk engin/tests' -v
chem_shield_p1/.venv/bin/python -m unittest discover \
  -s chem_shield_p4/risk_engine/tests -v
chem_shield_p1/.venv/bin/python -m unittest discover \
  -s chem_shield_p1/hmi/tests -v
```

Tests cover grouping, score calculation and validation, unscored events,
deduplication, escalation, additive SQLite storage, acknowledgements, and HMI
routes with a deliberately disconnected loopback PLC.

## Integration status and limitations

Completed: canonical risk engine; compatibility wrappers; event normalization
and correlation; deduplication; additive SQLite incident/event persistence;
history/detail/acknowledgement API; HMI risk summary, evidence register,
severity filtering, acknowledgement, and high/critical notification dialog.

Not connected automatically: Part 2/3/5 producers do not stream in the
background; an event producer must POST normalized records. There is no source
heartbeat contract, source-specific score calibration, authentication, manual
resolution workflow, or production-device integration. Part 2 flow scores and Part 3/5 process alerts remain distinct from the
original Part 1 physical model and PLC simulator.
