from collections import defaultdict
from datetime import datetime, timedelta


def failed_login_alerts(events, threshold=5, window_minutes=5):
    failures = defaultdict(list)

    for event in events:
        if event.get("event_type") != "login_failure":
            continue

        try:
            timestamp = datetime.fromisoformat(event["timestamp"])
        except (KeyError, TypeError, ValueError):
            continue

        key = (
            event.get("username", "unknown"),
            event.get("source_ip", "unknown"),
        )
        failures[key].append(timestamp)

    alerts = []

    for (username, source_ip), timestamps in failures.items():
        timestamps.sort()

        for timestamp in timestamps:
            start = timestamp - timedelta(minutes=window_minutes)
            count = sum(start <= item <= timestamp for item in timestamps)

            if count >= threshold:
                alerts.append({
                    "timestamp": timestamp.isoformat(timespec="seconds"),
                    "source_ip": source_ip,
                    "event_type": "Repeated failed login attempts",
                    "severity": "HIGH",
                    "score": 60,
                    "details": (
                        f"{username} had {count} failed login attempts "
                        f"within {window_minutes} minutes."
                    )
                })
                break

    return alerts
