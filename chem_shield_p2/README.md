# CHEM-SHIELD Part 2 / 3: passive network and OT security

This folder is intentionally separate from the physical OT process model in
Part 1. It is a passive, simulation-first analysis layer for network telemetry
and Modbus-style traffic using sanitized fixtures. Publishing is an explicit
opt-in and is limited to the Part 1 loopback HMI.

## Scope and constraints

- No live PLC writes or live OT connections.
- No active scanning or blocking.
- Localhost-only or fixture-based data only.
- The Part 1 HTTP/HMI, SQLite telemetry schema, PLC simulation, and physical-process semantics remain unchanged.

## Relevant repository contracts

The main project keeps its physical telemetry model in:

- `chem_shield_p1/data/store.py` — SQLite schema for physical telemetry and common events.
- `chem_shield_p1/README.md` — documented PLC/register contract and simulation-only scope.

This Part 2 code does not modify those contracts. It reads fixture data and
emits normalized events for offline analysis or optional local publication.

## Data flow

P2 replays sanitized fixture records, normalizes them, scores them with
`NetworkIsolationForest`, maps the simulated target to `PLC-01`, and converts
them to Part 4 `event_type: "network"` events. With `--publish`, the shared
publisher posts these events to the P1 HMI; it does not open network captures
or connect to a PLC.

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
  "timestamp": "2026-10-14T10:00:00Z",
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
- SQLite writes into the physical telemetry tables in `chem_shield_p1/data/store.py`.

## Offline replay and normalization

Run the offline replay from the repository root:

```bash
python3 -m chem_shield_p2.replay_events \
  --input chem_shield_p2/fixtures/sample_network_events.json --pretty
```

## Tests

From the repository root:

```bash
.venv/bin/python -m pytest -q
```

## Part 4 handoff

Raw adapter output retains source-specific event types such as `connection`
and does not itself satisfy P4's scored-event contract. When `--publish` is
enabled, P2 scores each normalized record, converts its P4 `event_type` to
`network`, adds a bounded `anomaly_score`, and posts it through the shared
publisher. `config.example.json` maps fixture endpoint identities to the
simulated asset `PLC-01`; the existing adapter type and evidence remain
available to P4. See [Part 4's input contract](../chem_shield_p4/correlation/README.md).

## Fixture-trained network model

`NetworkIsolationForest` trains on the normal rows in
`fixtures/network_baseline.json`. On the first publishing run, P2 trains the
model, saves it under `chem_shield_p2/models/`, and reloads that artifact.
Subsequent runs reuse the saved model. The generated Joblib file is ignored by
Git; remove it to retrain from the checked-in baseline.

Run offline replay, or opt in to scoring and loopback publishing:

```bash
python3 -m chem_shield_p2.replay_events \
  --input chem_shield_p2/fixtures/sample_network_events.json --pretty

python3 -m chem_shield_p2.replay_events \
  --input chem_shield_p2/fixtures/sample_network_events.json \
  --publish --hmi-url http://127.0.0.1:15000/api/risk/events
```

Scores are relative anomaly indicators in `[0, 1]`, not attack probabilities.
The publisher reports HMI accepted/rejected counts and retries transient local
failures; detector execution continues if the HMI is unavailable.

## Linux-specific dependencies for live tooling

If this project is later extended to real Zeek or Suricata captures on Linux, the host will typically require packages such as:

```bash
sudo apt-get update
sudo apt-get install -y zeek suricata
```

Those dependencies are optional here because the code remains fixture-driven and passive. The current implementation does not require Zeek or Suricata binaries.

## Output and limitations

- Scripts read JSON/JSONL fixtures offline; publication is disabled unless
  `--publish` is passed.
- The publisher permits only `http://127.0.0.1` and sends no data to remote
  endpoints.
- No unauthorized scans or production OT traffic are generated.
- This implementation preserves the existing physical process telemetry and Modbus PLC contract by not touching the Part 1 runtime.
