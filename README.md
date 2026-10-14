# CHEM-SHIELD

CHEM-SHIELD is an academic, simulation-first OT monitoring and defensive
cybersecurity project. Keep the virtual PLC bound to loopback for local demos.
The project does not authorize production OT connections or automated
mitigation.

## Project parts

- [Part 1: virtual OT lab and operator HMI](./chem_shield_p1/README.md)
- [Part 2: offline network-event adapters](./chem_shield_p2/README.md)
- [Part 3: physical-process ML detector](./chem_shield_p3/README.md)
- [Part 4: correlation and canonical risk engine](./chem_shield_p4/correlation/README.md)
- [Part 5: OT monitoring entry point](./chem_shield_p5/ot_monitor/README.md)

The Part 1 HMI hosts the Part 4 incident summary and its SQLite persistence.
Part 2's network-flow model and Part 3/5 process monitors remain separate
producers; submit their normalized events to `POST /api/risk/events` when an
operator or integration service is configured to do so. No data source is silently treated as connected, and a
missing detector score produces an unassessed incident rather than a zero-risk
assessment.

## HMI risk integration

Use the Part 1 virtual environment and run the HMI from the repository root:

```bash
chem_shield_p1/.venv/bin/python -m pip install -r chem_shield_p1/requirements.txt
chem_shield_p1/.venv/bin/python -m chem_shield_p1.hmi.app \
  --host 127.0.0.1 --port 15000 --plc-port 5020 \
  --database chem_shield_p1/data/telemetry.db
```

Risk input is independent of PLC control and can be tested with sanitized,
synthetic events:

```bash
curl -X POST http://127.0.0.1:15000/api/risk/events \
  -H 'Content-Type: application/json' \
  -d '{"events":[{"event_id":"demo-network-1","timestamp":"2026-10-14T09:30:00Z","source":"network_model","asset_id":"PLC-01","event_type":"network_anomaly","anomaly_score":0.9,"evidence":"synthetic demonstration"},{"event_id":"demo-physical-1","timestamp":"2026-10-14T09:30:04Z","source":"ot_monitor","asset_id":"PLC-01","event_type":"temperature_high","anomaly_score":0.9,"evidence":"synthetic demonstration"}]}'
```

The default Part 4 formula and thresholds are experimental project values, not
validated industrial safety settings. Scores are not probabilities. Read the
Part 4 documentation for lifecycle semantics, API routes, and tests.
