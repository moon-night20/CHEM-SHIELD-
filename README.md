# CHEM-SHIELD

CHEM-SHIELD is an academic, simulation-first OT monitoring and defensive
cybersecurity project. Keep the virtual PLC bound to loopback for local demos.
The project does not authorize production OT connections or automated
mitigation.

## Project parts

- [Part 1: virtual OT lab and operator HMI](./chem_shield_p1/README.md)
- [Part 2: fixture-backed network adapters and scoring](./chem_shield_p2/README.md)
- [Part 3: physical-process ML detector](./chem_shield_p3/README.md)
- [Part 4: correlation and canonical risk engine](./chem_shield_p4/correlation/README.md)
- [Part 5: OT monitoring entry point](./chem_shield_p5/ot_monitor/README.md)

The Part 1 HMI hosts the Part 4 incident summary and its SQLite persistence.
P2 network replay and the P5 physical monitor can explicitly publish scored
events to its loopback `POST /api/risk/events` endpoint. No background capture
or automated response is enabled.

## Data flow

P1 simulation telemetry is stored locally and can be read by P5; P2 replays
sanitized network fixtures. P2 scores network records, while P5 keeps its
sensor validation/rules and scores telemetry with P3's saved physical model.
Both producers use the shared publisher to send scored events to the P1 HMI,
where P4 correlates by asset and time, calculates experimental risk, and feeds
the dashboard.

## Strict sequential P2-to-P5 chain

The offline chain enforces one JSON handoff per stage. No stage reads a later
stage's output, and P1 is only an optional final dashboard sink:

```text
network JSON/JSONL
      |
      v
P2 replay + network scoring --> out/p2_events.json
      |
      v
P3 saved physical model <--- telemetry CSV
      |                       (P2 anomaly window +/- 10 s)
      v
P4 correlation + canonical risk --> out/p4_incidents.json
      |                       out/p3_events.json
      v
P5 sensor validation + rules <--- same telemetry CSV
      |
      +--> out/p5_report.json
      |
      +--> optional P1 HMI sink (loopback only, with --publish)
```

The handoff contracts are:

- **P2** writes an object containing `events` (scored network events in the
  Part 4 event format) and `handoff` (`asset_ids`, `window`, `threshold`, and
  `anomalous_event_count`). The window spans events with a score at or above
  the configurable threshold.
- **P3** reads the P2 handoff and telemetry CSV, selects rows within the P2
  time window plus/minus the 10-second correlation window, and writes a list
  of Part 4 physical events to `p3_events.json`. The saved P3 model is used
  here; the P5 step does not score telemetry again. The configured PLC asset
  ID is the canonical ID for demo telemetry aliases such as `M-01`.
- **P4** reads the P2 and P3 files, correlates events by asset and the existing
  10-second rule, calculates risk using Part 4's unchanged risk engine, and
  writes incidents to `p4_incidents.json`.
- **P5** reads the P4 incidents and the same telemetry CSV. It runs only
  `SensorValidator` and `RuleEngine` (no P3 model, PLC writes, or database
  persistence) and writes per-incident results to `p5_report.json`.

Run the demo using aligned fixture timestamps:

```bash
python -m scripts.run_chain --step-by-step
```

The runner defaults to `chem_shield_p2/fixtures/demo_network_events.json`,
`chem_shield_p5/ot_monitor/samples/abnormal_telemetry.csv`, threshold `0.5`,
and `out/`. Override inputs and output location with `--network-input`,
`--telemetry`, and `--out-dir`. Use `--from-stage N --to-stage N` to rerun
one numbered chain stage (1=P2, 2=P3, 3=P4, 4=P5) from its saved predecessor
handoff. `--publish --hmi-url http://127.0.0.1:15000/api/risk/events` sends
the P2 and P3 event files to the loopback HMI only.

Troubleshooting:

- **No anomalies from P2:** check the P2 threshold and fixture contents. With
  no threshold-qualified P2 events, P3 writes an empty event list and the
  runner reports `no network trigger`.
- **Telemetry outside the P2 window:** P3 only scores rows within 10 seconds
  of the P2 anomaly window; align fixture timestamps or supply a matching CSV.
- **Asset ID mismatch:** P2's configured asset mapping and P5's
  `risk_asset_id` must agree. Telemetry source IDs are mapped to that canonical
  PLC ID only for this configured single-asset demo.
- **HMI not running:** the pipeline works without an HMI unless `--publish` is
  selected. Start the HMI on `127.0.0.1:15000` before publishing.

## HMI risk integration

Create the combined environment, install dependencies from the repository
root, and run the HMI bound to loopback:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m chem_shield_p1.hmi.app \
  --host 127.0.0.1 --port 15000 --plc-port 5020 \
  --database chem_shield_p1/data/telemetry.db
```

Risk input is independent of PLC control and can be tested with sanitized,
synthetic events:

```bash
curl -X POST http://127.0.0.1:15000/api/risk/events \
  -H 'Content-Type: application/json' \
  -d '{"events":[{"event_id":"demo-network-1","timestamp":"2026-10-14T09:30:00Z","source":"network_model","asset_id":"PLC-01","event_type":"network","anomaly_score":0.9,"evidence":{"fixture":"synthetic demonstration"}},{"event_id":"demo-physical-1","timestamp":"2026-10-14T09:30:04Z","source":"ot_monitor","asset_id":"PLC-01","event_type":"physical","anomaly_score":0.9,"evidence":{"fixture":"synthetic demonstration"}}]}'
```

The default Part 4 formula and thresholds are experimental project values, not
validated industrial safety settings. Scores are not probabilities. Read the
Part 4 documentation for lifecycle semantics, API routes, and tests.

## Run the connected fixture demo

The runner starts a temporary loopback HMI when needed, publishes P2 and P5
fixture events, then prints the correlated scored incidents:

```bash
.venv/bin/python -m scripts.run_pipeline_demo --start-hmi
```

Alternatively, omit `--start-hmi` when the HMI is already running on
`127.0.0.1:15000`.
