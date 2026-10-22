"""Local-only mock notifier; no network transport is implemented."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from urllib.request import Request, urlopen


def queue_critical_message(
    outbox_path: str | Path,
    *,
    sensor: str,
    value: float,
    unit: str,
    machine_name: str = "PLC-01",
    countdown: str = "15:00",
) -> str:
    """Append an English notification to a local outbox file."""
    path = Path(outbox_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    message = (
        f"CRITICAL: {sensor} {value:g} {unit} on {machine_name}. "
        f"Auto-stop in {countdown}."
    )
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with path.open("a", encoding="utf-8", newline="") as stream:
        stream.write(f"{timestamp} {message}\n")
    bot_token = os.environ.get("CHEM_SHIELD_TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("CHEM_SHIELD_TELEGRAM_CHAT_ID")
    if bool(bot_token) != bool(chat_id):
        raise ValueError(
            "Set both CHEM_SHIELD_TELEGRAM_BOT_TOKEN and "
            "CHEM_SHIELD_TELEGRAM_CHAT_ID to enable Telegram notifications."
        )
    if bot_token and chat_id:
        endpoint = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = json.dumps(
            {"chat_id": chat_id, "text": message},
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        request = Request(
            endpoint,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=5) as response:
            if not 200 <= response.status < 300:
                raise RuntimeError(
                    f"Configured Telegram notifier returned HTTP {response.status}."
                )
    return message
