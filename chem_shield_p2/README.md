# CHEM-SHIELD Part 2 / 3: passive network and OT security

This folder is intentionally separate from the physical OT process model in the main Part 1 project. It is a passive, simulation-first analysis layer for network telemetry and Modbus-style traffic using sanitized fixtures.

## Scope and constraints

- No live PLC writes or live OT connections.
- No active scanning or blocking.
- Localhost-only or fixture-based data only.
- The Part 1 HTTP/HMI, SQLite telemetry schema, PLC simulation, and physical-process semantics remain unchanged.

## Relevant repository contracts

The main project keeps its physical telemetry model in:

- `chem_shield/data/store.py` — SQLite schema for physical telemetry and common events.
- `chem_shield/README.md` — documented PLC/register contract and simulation-only scope.

This Part 2 / 3 code does not modify those contracts. It reads fixture data and emits normalized events for offline analysis.

## Completed adapters (fixture-backed and tested)

The following adapters are implemented and covered by unit tests against sanitized sample fixtures:

- Zeek connection logs (`zeek_conn.jsonl`)
- Suricata EVE JSONL (`suricata_eve.jsonl`)
- Controlled passive Modbus monitor output (`modbus_monitor.json`)
- Exported OS security logs (`os_security.json`)

These adapters normalize events to the common schema:

```json
{
  "event_id": "<stable-sha256-prefix>",
  "timestamp": "2026-10-10T12:00:00Z",
  "source": "zeek",
  "asset_id": "10.10.10.5",
  "event_type": "connection",
  "severity": "medium",
  "evidence": {
    "src_ip": "192.168.2.10",
    "dst_ip": "10.10.10.5",
    "dst_port": 502,
    "conn_state": "SF",
    "duration_seconds": 0.12,
    "orig_pkts": 40,
    "resp_pkts": 32,
    "modbus_function_code": 3
  }
}
```

## Planned / not implemented live integrations

These are explicitly not implemented in this patch and are not claimed as supported:

- Live Zeek capture on Linux hosts.
- Live Suricata daemon integration.
- Direct ingest from industrial PLC networks or production SIEM systems.
- Live Modbus monitoring over untrusted OT networks.
- SQLite writes into the physical telemetry tables in `chem_shield/data/store.py`.

## Offline replay and normalization

Run the offline replay from the repository root:

```bash
cd /Users/moonlit-night/Desktop/CHEM-SHIELD-
python3 -m chem_shield_p2.replay_events --input chem_shield_p2/fixtures/sample_network_events.json --pretty
```

## Tests

From the repository root:

```bash
cd /Users/moonlit-night/Desktop/CHEM-SHIELD-
python3 -m unittest discover -s chem_shield_p2/tests -v
```

## Part 3: separate network anomaly model

The model in `network_isolation_forest.py` is intentionally separate from the Part 1 physical ML or telemetry model. It trains only on normal baseline network traffic and evaluates on a held-out set containing both normal and abnormal scenarios.

Important: these anomaly scores are not probability-of-attack values. They are relative deviation scores that can help prioritise review.

To reproduce the network-model check:

```bash
cd /Users/moonlit-night/Desktop/CHEM-SHIELD-
python3 - <<'PY'
import json
from pathlib import Path
from chem_shield_p2.network_isolation_forest import NetworkIsolationForest

root = Path('chem_shield_p2/fixtures')
baseline = json.loads((root / 'network_baseline.json').read_text())
heldout = json.loads((root / 'network_holdout.json').read_text())

def vectorize(row):
    state_map = {'established': 1, 'new': 2, 'S0': 0, 'REJ': 3}
    op_map = {'read_holding_registers': 1, 'read_coils': 2, 'read_input_registers': 3, 'write_single_coil': 4, 'write_single_register': 5, 'write_multiple_registers': 6, 'read_write_multiple_registers': 7}
    return [
        float(row['duration']),
        float(row['packets']),
        float(row['bytes']),
        float(row['dst_port']),
        float(state_map.get(row.get('connection_state'), 0)),
        float(row['modbus_function_code']),
        float(op_map.get(row.get('modbus_operation'), 0)),
        float(row['approved_client']),
    ]

normal = [vectorize(item) for item in heldout if item['label'] == 'normal']
attack = [vectorize(item) for item in heldout if item['label'] == 'attack']
model = NetworkIsolationForest(n_estimators=32, max_depth=6, random_seed=7).fit([vectorize(item) for item in baseline])
print({'normal_mean': sum(model.score_samples(normal)) / len(normal), 'attack_mean': sum(model.score_samples(attack)) / len(attack)})
PY
```

## Linux-specific dependencies for live tooling

If this project is later extended to real Zeek or Suricata captures on Linux, the host will typically require packages such as:

```bash
sudo apt-get update
sudo apt-get install -y zeek suricata
```

Those dependencies are optional here because the code remains fixture-driven and passive. The current implementation does not require Zeek or Suricata binaries.

## Output and limitations

- Scripts read JSON/JSONL fixtures offline.
- No remote endpoints are contacted.
- No unauthorized scans or production OT traffic are generated.
- This implementation preserves the existing physical process telemetry and Modbus PLC contract by not touching the `chem_shield` Part 1 runtime.
