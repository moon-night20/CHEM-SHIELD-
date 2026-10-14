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
