# Admin console

From the repository root, create users with `chem_shield_p1/.venv/bin/python -m admin_part.manage_users create USER --role administrator`, then run `chem_shield_p1/.venv/bin/python -m admin_part.app`. The console reads the P4/P5 JSON files under `out/` and stores decisions in its local SQLite database.

Legacy note: `legacy/network_detector.py` is retained for reference only and is not wired into the project; P2 owns network detection.

All actions are human decisions recorded locally. No response is executed.
