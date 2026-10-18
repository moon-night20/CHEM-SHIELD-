from pathlib import Path
import csv
import sys

BASE_DIR = Path(__file__).resolve().parents[1]
CONFIG_FILE = BASE_DIR / "data" / "ot_config.env"
INPUT_FILE = BASE_DIR / "data" / "events" / "network_events.csv"
OUTPUT_FILE = BASE_DIR / "data" / "events" / "network_alerts.csv"

def read_config(path):
    config = {}

    for line in path.read_text().splitlines():
        line = line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        config[key.strip()] = value.strip()

    return config

config = read_config(CONFIG_FILE)

ot_ip = config.get("OT_IP", "")
plc_port = config.get("PLC_PORT", "")
authorized_source = config.get("AUTHORIZED_SOURCE", "")

if not ot_ip or not plc_port or not authorized_source:
    sys.exit(
        "OT configuration is incomplete.\n"
        "Fill OT_IP, PLC_PORT, and AUTHORIZED_SOURCE in data/ot_config.env "
        "only after the OT team confirms them."
    )

if not INPUT_FILE.exists():
    sys.exit(
        "No network event file found.\n"
        "Expected file: data/events/network_events.csv"
    )

with INPUT_FILE.open(newline="") as input_handle:
    events = list(csv.DictReader(input_handle))

fieldnames = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "destination_port",
    "operation",
    "value",
    "authorized",
    "request_count",
    "network_score",
    "status",
    "reason",
]

with OUTPUT_FILE.open("w", newline="") as output_handle:
    writer = csv.DictWriter(output_handle, fieldnames=fieldnames)
    writer.writeheader()

    for row in events:
        score = 0.0
        reasons = []

        if row.get("source_ip") != authorized_source:
            score += 0.4
            reasons.append("unauthorized source")

        if (
            row.get("destination_ip") == ot_ip
            and row.get("destination_port") == plc_port
        ):
            score += 0.2
            reasons.append("PLC service targeted")

        if row.get("operation", "").lower() == "write":
            score += 0.2
            reasons.append("control write")

        try:
            value = float(row.get("value", 0))
            request_count = int(row.get("request_count", 0))
        except ValueError:
            value = 0
            request_count = 0

        if value > 70:
            score += 0.2
            reasons.append("value above normal limit")

        if request_count > 10:
            score += 0.2
            reasons.append("abnormal request frequency")

        row["network_score"] = f"{min(score, 1.0):.2f}"
        row["status"] = "suspicious" if score >= 0.6 else "normal"
        row["reason"] = "; ".join(reasons)

        writer.writerow({name: row.get(name, "") for name in fieldnames})

print(f"Saved results to: {OUTPUT_FILE}")
