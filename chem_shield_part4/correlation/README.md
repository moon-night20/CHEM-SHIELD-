# CHEM-SHIELD Part 4 — Correlation Engine

This folder is **only** the correlation engine.

It does **not** rebuild:

- the network anomaly detector
- the physical / process anomaly detector

Those detectors are built by other teammates. This module **accepts their outputs** and groups related events into incidents.

Risk scoring is also **not** implemented here. See `risk_engine.py` for the later interface.

## What it does

Rule-based correlation (no AI / no machine learning):

1. Events must share the same `asset_id`.
2. After sorting by timestamp, an event joins the current incident for that asset if it is within the **correlation time window** of the previous event.
3. Default window = **10 seconds** (change it; do not hard-code it in call sites).

## Expected event format

```json
{
  "timestamp": "2026-09-18T09:31:01",
  "asset_id": "PLC_01",
  "event_type": "network",
  "anomaly_score": 0.70
}
```

`event_type` must be `"network"` or `"physical"`.  
`anomaly_score` must be a number from `0.0` to `1.0`.  
`timestamp` must be ISO-8601, for example `2026-09-18T09:31:01`.

## How another teammate sends detector output

```python
from correlation_engine import CorrelationEngine

network_and_physical_events = [
    {"timestamp": "2026-09-18T09:31:01", "asset_id": "PLC_01", "event_type": "network", "anomaly_score": 0.70},
    {"timestamp": "2026-09-18T09:31:04", "asset_id": "PLC_01", "event_type": "physical", "anomaly_score": 0.82},
]

engine = CorrelationEngine(time_window_seconds=10)
incidents, errors = engine.correlate(network_and_physical_events)

for incident in incidents:
    print(incident.to_dict())
```

Invalid events are skipped and returned in `errors`. Valid events are still correlated.

Later, pass incidents into the risk engine:

```python
from risk_engine import RiskEngine

# Not implemented in Version 1:
# RiskEngine().calculate_risk(incident)
```

## Run in VS Code

1. Open this folder: `chem_shield_part4`
2. Open a terminal in VS Code
3. Run:

```bash
python main.py
```

Optional:

```bash
python main.py --window 10 --input sample_data.json
```

The demo prints:

```
INPUT EVENTS
→ CORRELATED INCIDENTS
→ INCIDENT DETAILS
```

## Run tests

```bash
python -m unittest discover -s tests -v
```

## Sample story in `sample_data.json`

| Time | Asset | Type | Score | Result |
|------|-------|------|-------|--------|
| 09:31:01 | PLC_01 | network | 0.70 | Incident 1 |
| 09:31:04 | PLC_01 | physical | 0.82 | Incident 1 |
| 09:31:08 | PLC_01 | physical | 0.91 | Incident 1 |
| 09:32:30 | PLC_01 | network | 0.80 | New incident (outside 10s window) |
| 09:31:05 | PLC_02 | network | 0.65 | Separate incident (different asset) |
| 09:31:07 | PLC_02 | physical | 0.88 | Same PLC_02 incident |

PLC_01 incident 1:

- Events: 3
- Network present: true
- Physical present: true
- Start: 09:31:01
- End: 09:31:08
- Duration: 7 seconds
- Max network score: 0.70
- Max physical score: 0.91

## Files

| File | Role |
|------|------|
| `models.py` | `AnomalyEvent` and `Incident` |
| `validator.py` | Input checks |
| `correlation_engine.py` | Rule-based grouping |
| `risk_engine.py` | Empty interface for later |
| `main.py` | Command-line demo |
| `sample_data.json` | Example detector output |
| `tests/` | Unit tests |
