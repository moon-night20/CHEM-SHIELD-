# CHEM-SHIELD Part 5 — OT physical-process monitoring

This package contains the read-only OT physical-process monitor implementation.
Part 1 retains the PLC, process simulator, communications, telemetry store, and
HMI; monitor logic and its tests live here.

## Existing project contracts

- Part 1 telemetry is stored by `chem_shield_p1/data/store.py`. Relevant
  columns are `timestamp`, `machine_id`, `motor_status`, `rpm`, `temperature`,
  and `pressure`.
- Part 1 test-event records use the fields in
  `chem_shield_p1/events/abnormal_events.py`: timestamp, source, machine_id,
  event_type, parameter, old_value, new_value, severity. Part 5
  `to_part1_event_record()` maps a normalized alert to this shape without
  calling `write_event()` or writing to the PLC.
- Part 4 correlation accepts timestamp, asset_id, event_type=`physical`, and
  anomaly_score. `to_part4_correlation_event()` maps normalized OT alerts to
  this interface.
- Part 3 already has `PhysicalAnomalyDetector`, which models motor speed,
  temperature, and vibration. It is unchanged. It does not model pressure, so
  the Part 1 OT implementation's separate `PhysicalProcessIsolationForest`
  models temperature, pressure, speed, changes, and operating state; it does
  not replace or modify the Part 3 detector.

The physical field mapping is `temperature` (degC), `pressure` (bar), `speed`
from Part 1's `rpm` (rpm), `operating_state` from `motor_status`, and `asset_id`
from `machine_id`. Part 1 simulator readings are fictional simulated values.

## Setup and commands

Install the Part 1 and Part 3 dependencies into the environment used to run the
repository:

```bash
python3 -m pip install -r chem_shield_p1/requirements.txt
python3 -m pip install -r chem_shield_p3/requirements.txt
```

Run the monitor on Part 5's synthetic CSV:

```bash
python3 -m chem_shield_p5.ot_monitor \
  --csv chem_shield_p5/ot_monitor/samples/abnormal_telemetry.csv \
  --config chem_shield_p5/ot_monitor/config.example.json
```

Read the existing Part 1 SQLite telemetry in read-only mode:

```bash
python3 -m chem_shield_p5.ot_monitor \
  --database chem_shield_p1/data/telemetry.db \
  --config chem_shield_p5/ot_monitor/config.example.json
```

Persist alert summaries only with explicit opt-in:

```bash
python3 -m chem_shield_p5.ot_monitor \
  --database chem_shield_p1/data/telemetry.db \
  --config path/to/validated-site-config.json \
  --persist
```

Train a model on the separate normal baseline and evaluate against the held-out
normal/abnormal sample:

```bash
python3 -m chem_shield_p5.ot_monitor.train_model \
  --baseline chem_shield_p5/ot_monitor/samples/normal_telemetry.csv \
  --evaluation chem_shield_p5/ot_monitor/samples/abnormal_telemetry.csv \
  --output /tmp/chem-shield-physical-iforest.joblib
```

Run inference with that artifact:

```bash
python3 -m chem_shield_p5.ot_monitor \
  --csv chem_shield_p5/ot_monitor/samples/abnormal_telemetry.csv \
  --config chem_shield_p5/ot_monitor/config.example.json \
  --model /tmp/chem-shield-physical-iforest.joblib
```

The model reports anomaly rankings, not attack probabilities. The checked-in
CSV data is synthetic and does not establish real-world accuracy.

## Configuration and operational safety

`config.example.json` sets default sensor names and units but deliberately
leaves engineering limits and plausibility ranges unset. Configure those from
validated equipment specifications and approved operating procedures. Rule
alerts are deterministic engineering/state checks and remain independent of
statistical model scores.

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
python3 -m unittest discover -s chem_shield_p5/ot_monitor/tests -v
python3 -m unittest discover -s chem_shield_p5/ot_monitor/tests -v
python3 -m unittest discover -s chem_shield_p1/tests -v
```

Limits, units, state profiles, and severity policies require confirmation by
process/equipment owners before use outside this synthetic lab.
