# PLC layer

`modbus_plc.py` runs PLC-01 as a local Modbus TCP server on `127.0.0.1:5020`.
It exposes the 13-register holding-register map in the Part 1 README, including
the simulation-only override mask and values at addresses 8–12. The process
simulator is a separate Modbus client, so it never calls PLC Python methods
directly.

The server is intentionally a small compatibility runtime. This register map
is for the local virtual lab only; do not connect it to physical equipment.