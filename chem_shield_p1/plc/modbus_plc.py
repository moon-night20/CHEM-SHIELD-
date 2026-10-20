"""Standalone virtual PLC register server.

The server is intentionally small and uses the same holding-register contract
that an OpenPLC Modbus TCP runtime can expose. It is the default laptop demo
because it has no native-runtime installation step.
"""

import argparse

from chem_shield_p1.process.modbus_server import (
    DEFAULT_PLC_HOST,
    DEFAULT_PLC_PORT,
    ProcessRegisterBank,
    serve,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="CHEM-SHIELD virtual PLC")
    parser.add_argument("--host", default=DEFAULT_PLC_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PLC_PORT)
    args = parser.parse_args()
    print(f"PLC-01 Modbus TCP listening on {args.host}:{args.port}")
    serve(ProcessRegisterBank(), args.host, args.port)


if __name__ == "__main__":
    main()