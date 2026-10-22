# Three-minute Part 8 demo

## Before the demo

Install the dependencies once, then from the repository root run:

```sh
python -m chem_shield_p8.run
```

Open <http://127.0.0.1:15080>. The dashboard is simulation-only and stays on
loopback.

## Walkthrough

**0:00–0:30 — Reactor twin**

- Point out the live process values and animated reactor diagram.
- Explain that the vessel, actuators, register map, and all displayed data are
  software simulations.
- Show the Part 1 integration indicator. It is read-only; Part 8 can operate
  without Part 1.

**0:30–1:00 — Physics and zones**

- Compare the physics-rule score with the ML deviation score.
- Show the Purdue zone map and the illustrative compliance score.
- Note that the ML score is not a probability and the score is not a formal
  compliance certification.

**1:00–1:40 — Synthetic detection replay**

- Select **Rogue engineering workstation** and click **PLAY** (or use **STEP**
  to reveal each record).
- Review the unknown endpoint and unauthorized write alerts, asset discovery,
  and ATT&CK for ICS mapping.
- Drag the time slider to scrub the replay timeline.

**1:40–2:15 — Operator-approved response**

- In the response panel, propose **Request simulated reactor safe state**.
- Click **APPROVE** on the pending action and point out the audit record.
- Emphasize that approval changes only the Part 8 twin state; it sends no PLC,
  firewall, or external messaging command.

**2:15–2:45 — Incident report**

- Click **GENERATE INCIDENT REPORT**.
- Download the HTML and PDF. Show the process snapshot, event evidence, assets,
  ATT&CK mapping, response decisions, and recommendations.

**2:45–3:00 — Reproducibility and safety**

- Mention the other available scenarios: setpoint manipulation, sensor
  replay, loss of view, safety bypass, and IT-to-OT lateral movement.
- Stop the server with Ctrl+C. Tests can be run from the repository root:

  ```sh
  python -m pytest -q chem_shield_p8/tests
  ```
