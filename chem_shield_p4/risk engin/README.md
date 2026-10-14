# CHEM-SHIELD Part 4 — Correlation Engine + Risk Engine

This folder is the **correlation and risk** slice of CHEM-SHIELD.

It does **not** rebuild:

- the network anomaly detector
- the physical / process anomaly detector

Those detectors are built by other teammates. This module **accepts their outputs**, groups related events into incidents, then scores each incident.

```
Network Detector
       ↓
Physical Detector
       ↓
Correlation Engine     (which events belong together)
       ↓
Correlated Incident
       ↓
Risk Engine            (how serious is that incident)
       ↓
Risk Score (0.0–1.0)
       ↓
LOW / MEDIUM / HIGH / CRITICAL
```

There is **no AI and no machine learning**. Both engines are rule-based, deterministic, and explainable.

Weights, thresholds, and criticality values in this project are **experimental CHEM-SHIELD parameters**. They are not presented as official cybersecurity standards.

## 1. Correlation Engine (`correlation_engine.py`)

Rule-based grouping:

1. Events must share the same `asset_id`.
2. After sorting by timestamp, an event joins the current incident for that asset if it is within the **correlation time window** of the previous event.
3. Default window = **10 seconds**.

The Risk Engine does **not** repeat these rules. It only consumes the incident that correlation already produced.

## 2. Risk Engine (`risk_engine.py`)

The Risk Engine combines:

- network anomaly evidence
- physical anomaly evidence
- asset criticality

Experimental formula:

```
base_risk  = (network_weight × network_score) + (physical_weight × physical_score)
final_risk = base_risk × asset_criticality
```

Defaults (all in `config.py`):

| Setting | Experimental value |
|---------|--------------------|
| `NETWORK_WEIGHT` | 0.40 |
| `PHYSICAL_WEIGHT` | 0.60 |
| `DEFAULT_CRITICALITY` | 1.0 |
| `LOW_THRESHOLD` | 0.30 |
| `MEDIUM_THRESHOLD` | 0.60 |
| `HIGH_THRESHOLD` | 0.80 |

Risk levels:

| Final risk | Level |
|------------|--------|
| 0.00 – 0.29 | LOW |
| 0.30 – 0.59 | MEDIUM |
| 0.60 – 0.79 | HIGH |
| 0.80 – 1.00 | CRITICAL |

If only one anomaly type is present, the missing score is treated as `0.0`. Example: network 0.70 and physical 0.0 → `(0.40 × 0.70) = 0.28` → **LOW**.

Criticality is a number from `0.0` to `1.0` (for example `0.2` low, `0.5` medium, `1.0` highly critical). It scales the final score: a base risk of `0.80` with criticality `0.5` becomes `0.40` (**MEDIUM**).

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

## How the two engines connect

The modules stay loosely coupled: correlation returns incidents; risk scores them.

```python
from correlation_engine import CorrelationEngine
from risk_engine import RiskEngine

events = [
    {"timestamp": "2026-09-18T09:31:01", "asset_id": "PLC_01", "event_type": "network", "anomaly_score": 0.70},
    {"timestamp": "2026-09-18T09:31:04", "asset_id": "PLC_01", "event_type": "physical", "anomaly_score": 0.82},
    {"timestamp": "2026-09-18T09:31:08", "asset_id": "PLC_01", "event_type": "physical", "anomaly_score": 0.91},
]

correlated_incidents, errors = CorrelationEngine().correlate(events)

risk_assessment = RiskEngine().calculate_risk(
    correlated_incidents[0],
    asset_criticality={"asset_id": "PLC_01", "criticality": 1.0},
)

print(risk_assessment.to_dict())
print(risk_assessment.explanation)
```

Worked example for that incident:

```
Network contribution  = 0.40 × 0.70 = 0.280
Physical contribution = 0.60 × 0.91 = 0.546
Base risk             = 0.280 + 0.546 = 0.826
Final risk            = 0.826 × 1.0 = 0.826
Risk level            = CRITICAL
```

Invalid scores, missing IDs, or weights that do not add to `1.0` raise a clear error. Nothing invalid is accepted silently.

## Run in VS Code

1. Open this folder: `chem_shield_part4`
2. Open a terminal in VS Code (**Terminal → New Terminal**)
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
→ RISK ENGINE
```

Example risk block for `INC-0001` / `PLC_01`:

```
Incident: INC-0001
Asset: PLC_01

Network score: 0.70
Physical score: 0.91
Asset criticality: 1.0

Base risk: 0.826
Final risk: 0.826

Risk level: CRITICAL
```

## Run tests

```bash
python -m unittest discover -s tests -v
```

Covered risk cases include:

1. Network 0.70 + physical 0.91 + criticality 1.0 → **0.826 CRITICAL**
2. Network only 0.70 → **0.28 LOW**
3. Physical only 0.80 → **0.48 MEDIUM**
4. Network 0.70 + physical 0.90 + criticality 0.5 → **0.41 MEDIUM**
5. Network score 1.5 → validation error
6. Physical score -0.2 → validation error
7. Weights that do not sum to 1.0 → configuration error

## Sample story in `sample_data.json`

| Time | Asset | Type | Score | Result |
|------|-------|------|-------|--------|
| 09:31:01 | PLC_01 | network | 0.70 | Incident 1 |
| 09:31:04 | PLC_01 | physical | 0.82 | Incident 1 |
| 09:31:08 | PLC_01 | physical | 0.91 | Incident 1 |
| 09:32:30 | PLC_01 | network | 0.80 | New incident (outside 10s window) |
| 09:31:05 | PLC_02 | network | 0.65 | Separate incident (different asset) |
| 09:31:07 | PLC_02 | physical | 0.88 | Same PLC_02 incident |

PLC_01 incident 1 (criticality `1.0`):

- Events: 3
- Max network score: 0.70
- Max physical score: 0.91
- Final risk: **0.826 CRITICAL**

## Files

| File | Role |
|------|------|
| `models.py` | `AnomalyEvent`, `Incident`, `RiskAssessment` |
| `validator.py` | Event checks and risk-input checks |
| `correlation_engine.py` | Groups related events |
| `risk_engine.py` | Scores a correlated incident |
| `config.py` | Experimental weights and thresholds |
| `main.py` | Command-line demo |
| `sample_data.json` | Example detector output + asset criticality |
| `tests/` | Unit tests |

## Later extensions

The Risk Engine only needs an incident-shaped object (or dictionary) plus criticality. You can later add more anomaly sources, different weights, different thresholds, extra asset fields, or another scoring function without changing how correlation groups events.
