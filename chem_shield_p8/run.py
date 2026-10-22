"""Command-line launcher for the local Part 8 dashboard."""

from __future__ import annotations

import os

from chem_shield_p8.dashboard import create_app

DEFAULT_PORT = 15080


def dashboard_port(value: str | None = None) -> int:
    """Return a valid TCP port from the supplied value or environment."""
    raw_value = value if value is not None else os.environ.get("CHEM_SHIELD_P8_PORT")
    if raw_value is None:
        return DEFAULT_PORT
    try:
        port = int(raw_value)
    except ValueError as error:
        raise ValueError("CHEM_SHIELD_P8_PORT must be an integer between 1 and 65535.") from error
    if not 1 <= port <= 65535:
        raise ValueError("CHEM_SHIELD_P8_PORT must be an integer between 1 and 65535.")
    return port


def main() -> None:
    """Start the Flask dashboard on loopback only."""
    app = create_app()
    app.run(
        host="127.0.0.1",
        port=dashboard_port(),
        debug=False,
        use_reloader=False,
        threaded=True,
    )


if __name__ == "__main__":
    main()
