# CHEM-SHIELD Part 7: Command Center

Part 7 adds an Admin-authenticated, loopback-only demo surface for the existing
simulation. It uses the Part 1 HMI risk feed, the Part 6 simulated response, and
the existing Attack Console API. It does not add a PLC, detector, or physical
control path.

## Architecture

```text
Admin browser (login + CSRF, 127.0.0.1:5000)
        |
        +--> /p7/command-center, /p7/timeline, /p7/integrity
        |           |
        |           +--> Part 7 blueprint, scenario runner, report generator
        |                         |                  |
        |                         |                  +--> local outbox
        |                         +--> p7 tables + existing hash-chained Admin audit
        |
        +--> Part 1 HMI read-only state/risk/event feeds (:15000)

Scenario runner --> existing OT Command Console API (:5001)
                            |
                            v
                 Part 1 virtual PLC (:15020) <--> process simulator
```

The runner is hosted in the Admin process; no additional service or dependency
is required. Scenario commands are sent to the OT Console, which applies only
simulated sensor overrides. Each run clears overrides when completed or
aborted. The UI refuses non-loopback requests and all mutation routes use the
Admin console's Flask-WTF CSRF protection.

## Pages and endpoints

- `http://127.0.0.1:5000/p7/command-center` — projected live status, gauges,
  scenario buttons, abort, countdown, mini-timeline, demo score, guided demo,
  and local mock-notifier outbox.
- `http://127.0.0.1:5000/p7/scenarios` — scenario details.
- `http://127.0.0.1:5000/p7/timeline` — live ordered run timeline and response
  timing.
- `http://127.0.0.1:5000/p7/integrity` — Admin audit-chain verification.
- `GET /p7/audit/verify` — authenticated integrity result.
- `POST /p7/scenarios/<id>/run` and `POST /p7/scenarios/abort` — CSRF-protected
  scenario controls.
- `POST /p7/reports` then `GET /p7/reports/<report-id>` — generate/open a
  self-contained printable HTML report. Use the browser Print command and
  choose Save as PDF.

Available scenarios are Overheat, Pressure spike, Overspeed, Stealthy in-range
drift, and Cascade. The drift stays under configured live limits; Part 3 model
detection depends on the model and telemetry, and is not guaranteed.

## Audit integrity

The existing `audit_log` is preserved. An additive `p7_audit_chain` table
stores a canonical JSON snapshot and SHA-256 hash for each row. Existing rows
are chained on the first migration; new Admin audit writes append to the chain.
Verification compares the current source records, ordering, links, and hashes.
The tamper helper creates and alters a separate copy only:

```text
Run from the repository root on macOS, Linux, or Windows:
python scripts/p7_tamper_demo.py --copy out/p7-audit-tamper-copy.db
```

The source Admin database is read-only to the helper. Its `--copy` destination
must differ from the live database and must not already exist. Verify the
original at `/p7/integrity` (INTACT); the copy is intended for an isolated
integrity-check demonstration.

## Security posture score

The 0–100 demo score has four equally weighted categories:

- Detection speed: 25 points multiplied by `max(0, 1 - detection_seconds/60)`.
- Operator response: 25 points multiplied by `max(0, 1 - response_seconds/60)`.
- Automatic stop: 25 points if Part 6 records an automatic simulated stop,
  otherwise 0.
- Audit integrity: 25 points if the current Admin hash chain verifies,
  otherwise 0.

This is a simple demo metric, not an industry standard, safety rating, or
probability.

## Mock notifier

Critical events are written in English to the on-screen outbox and ignored
Git-managed `out/outbox.log`. With no Telegram configuration, the default
notifier makes no network calls. Telegram delivery is optional and requires
both `CHEM_SHIELD_TELEGRAM_BOT_TOKEN` and `CHEM_SHIELD_TELEGRAM_CHAT_ID` to be
set by the user; never commit these values. E-mail delivery is not implemented.

## Demo run

From the repository root, the same commands work in macOS/Linux terminals and
Windows PowerShell after setup:

```text
python scripts/chemshield.py stop
python scripts/chemshield.py setup
python scripts/chemshield.py test
python scripts/chemshield.py run
```

Sign in to the Admin console and open `/p7/command-center`. Run Overheat to
observe the existing HMI warning and Part 6 countdown; leave it unacknowledged
to observe the configured auto-stop. Run Cascade and acknowledge the incident
in the HMI to observe recovery/override clearing. Use Abort to stop a scenario
early; the runner clears all overrides. Generate the report from the timeline
or incident detail page.

The scenario runner uses `CHEM_SHIELD_INGEST_TOKEN`, which `scripts/chemshield.py
run` shares with the HMI and local publishers. The default auto-stop remains
900 seconds. To demonstrate a shorter interval, set
`CHEM_SHIELD_AUTO_STOP_SECONDS` before starting the stack:

```text
macOS/Linux: export CHEM_SHIELD_AUTO_STOP_SECONDS=20
Windows PowerShell: $env:CHEM_SHIELD_AUTO_STOP_SECONDS = "20"
Windows cmd: set CHEM_SHIELD_AUTO_STOP_SECONDS=20
```

## MITRE ATT&CK for ICS mappings

The demo associates sensor setpoint changes with these official technique
pages, checked against the MITRE ATT&CK website:

- [T0831: Manipulation of Control](https://attack.mitre.org/techniques/T0831/)
- [T0836: Modify Parameter](https://attack.mitre.org/techniques/T0836/)
- [TA0106: Impair Process Control](https://attack.mitre.org/tactics/TA0106/)

The technique titles and tactic label were checked against the linked MITRE
pages. These are illustrative labels for simulated parameter changes, not an
attribution of real adversary activity.

## Cross-platform support

The project targets Python 3.9 through 3.13 on Windows 10/11, macOS, and Linux.
Use `python scripts/chemshield.py setup` to create the local environment,
install project requirements, and print the platform's activation command.
The command center remains bound to loopback and no part of this demo controls
physical equipment.
