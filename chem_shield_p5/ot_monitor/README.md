# CHEM-SHIELD Part 5 — OT physical-process monitoring

This package contains the read-only OT physical-process monitor implementation.
Part 1 retains the PLC, process simulator, communications, telemetry store, and
HMI; monitor logic and its tests live here.

## Existing project contracts

- Part 1 telemetry is stored by `chem_shield_p1/data/store.py`. Relevant
  columns are `timestamp`, `machine_id`, `motor_status`, `rpm`, `temperature`,
  `pressure`, and `power`.
- Part 1 test-event records use the fields in
  `chem_shield_p1/events/abnormal_events.py`: timestamp, source, machine_id,
  event_type, parameter, old_value, new_value, severity. Part 5
  `to_part1_event_record()` maps a normalized alert to this shape without
  calling `write_event()` or writing to the PLC.
- Part 4 correlation accepts timestamp, asset_id, event_type=`physical`, and
  anomaly_score. `to_part4_correlation_event()` maps normalized OT alerts to
  this interface.
- Part 5 uses Part 3's persisted `PhysicalAnomalyDetector` artifact as its only
  physical ML model. P5 retains its sensor validation and pressure/temperature/
  speed rule checks; the P3 model consumes RPM, temperature, pressure, and
  power, their per-reading rates, and physical-consistency residuals. Its score
  is an anomaly indicator, not a probability. If a reading lacks a required
  model channel or cannot be scored, P5 emits a medium-severity
  `model_scoring_unavailable` warning event.
- `config.example.json` maps the monitor's local machine IDs to the shared
  Part 4 correlation asset `PLC-01` through `risk_asset_id`.

The physical field mapping is `temperature` (degC), `pressure` (bar), `power`
(kW), `rpm` from Part 1's `rpm` (rpm), `operating_state` from `motor_status`,
and `asset_id` from `machine_id`. Part 1 simulator readings are fictional
simulated values.

## Data flow

P1 writes simulated telemetry locally; P5 reads it or a synthetic CSV, applies
sensor validation and rules, and uses P3's saved model for physical anomaly
scores. With `--publish`, scored events are adapted by
`to_part4_correlation_event()` and sent through the shared publisher to the P1
HMI. Readings that cannot be model-scored remain available to local rule checks
and produce a warning event in the monitor output.

## Setup and commands

Install the combined dependencies from the repository root:

```bash
.venv/bin/python -m pip install -r requirements.txt
```

Run the monitor on Part 5's synthetic CSV:

```bash
python3 -m chem_shield_p5.ot_monitor \
  --csv chem_shield_p5/ot_monitor/samples/abnormal_telemetry.csv \
  --config chem_shield_p5/ot_monitor/config.example.json
```

Publish the scored physical events to the loopback Part 1 HMI (start it first
on `127.0.0.1:15000`):

```bash
.venv/bin/python -m chem_shield_p5.ot_monitor \
  --csv chem_shield_p5/ot_monitor/samples/abnormal_telemetry.csv \
  --config chem_shield_p5/ot_monitor/config.example.json \
  --publish --hmi-url http://127.0.0.1:15000/api/risk/events
```

The publisher is opt-in, loopback-only, and reports accepted/rejected counts.
If the HMI is unavailable, it logs the failure and the monitor still completes.

Read the existing Part 1 SQLite telemetry in read-only mode:

```bash
python3 -m chem_shield_p5.ot_monitor \
  --database chem_shield_p1/data/telemetry.db \
  --config chem_shield_p5/ot_monitor/config.example.json
```

Continuously follow newly appended P1 telemetry and publish debounced scored
alerts to the loopback HMI. Start the HMI with the same ingest token first:

```bash
export CHEM_SHIELD_INGEST_TOKEN="local-demo-only-change-me"
python3 -m chem_shield_p5.ot_monitor --follow
```

Follow mode reads `chem_shield_p1/data/telemetry.db` by default. Use
`--database path/to/telemetry.db` to select another local simulator database,
`--poll-interval 2` to check every two seconds, and `--debounce-seconds 60` to
limit repeated publications for the same asset and alert type. It validates
each new reading, runs the configured rules and P3 model, and only publishes
events with a model score to the loopback `/api/risk/events` endpoint. The
SQLite source is opened read-only; no PLC writes or automated responses occur.

Persist alert summaries only with explicit opt-in:

```bash
python3 -m chem_shield_p5.ot_monitor \
  --database chem_shield_p1/data/telemetry.db \
  --config path/to/validated-site-config.json \
  --persist
```

By default, the monitor loads
`chem_shield_p3/models/isolation_forest.joblib`. An alternate compatible P3
artifact can be selected with `--model`:

```bash
python3 -m chem_shield_p5.ot_monitor \
  --csv chem_shield_p5/ot_monitor/samples/abnormal_telemetry.csv \
  --config chem_shield_p5/ot_monitor/config.example.json \
  --model chem_shield_p3/models/isolation_forest.joblib
```

The model reports anomaly rankings, not attack probabilities. The checked-in
CSV data is synthetic and does not establish real-world accuracy.

## Configuration and operational safety

`config.example.json` sets default sensor names, units, and the risk asset
mapping. For this fictional simulator only, it also sets upper alert limits of
70 °C temperature, 4 bar pressure, 12 kW power, and 1500 rpm speed. Values at
or below each limit do not trigger that upper-limit rule; values above it
create a critical severity OT event. These are demo thresholds, not validated
equipment safety limits. The lower limits and plausibility ranges remain
unset. Rule alerts are deterministic engineering/state checks and remain
independent of statistical model scores.

These events are alert-only: they do not stop the simulator. Part 6 can offer
its separate simulated stop only after an operator explicitly confirms an
eligible CRITICAL incident in the HMI.

Supported rule checks include configured upper/lower bounds, rate-of-change
limits, fluctuations, state-specific sensor ranges, and speed expectations
while running or stopped. Configurable physics-consistency rules also detect
RPM rising while power is flat, temperature falling under load, pressure failing
to track an RPM change, and configured sensors remaining frozen too long. Their
thresholds, sensor lists, and severities are set under
`rules.physics_consistency` in `config.example.json`; these rules are alert-only.
They are engineering/state checks, not statistical model scores; an alert does
not suppress or replace a model result.

The monitor validates missing, duplicate, stale, malformed, non-finite, and
configured-implausible measurements. It does not replace invalid measurements
with normal values. Measurement origin is retained in output. For database
input it is marked `simulated_part1`; sample CSV rows are explicitly synthetic.

No live equipment connector, PLC write, setpoint change, interlock override,
active scan, or automated remediation is present. The SQLite adapter only
reads existing telemetry and, when explicitly requested, persists alert
summaries through the existing event writer. The legacy events schema does not
store all rich evidence/measurement/model fields; the JSON event stream retains
those fields.

## Tests

```bash
.venv/bin/python -m pytest -q
```

Limits, units, state profiles, and severity policies require confirmation by
process/equipment owners before use outside this synthetic lab.
