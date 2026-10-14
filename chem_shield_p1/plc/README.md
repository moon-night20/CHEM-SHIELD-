# PLC layer

`modbus_plc.py` runs PLC-01 as a local Modbus TCP server on `127.0.0.1:5020`.
It exposes the holding-register map in the Part 1 README. The process simulator
is a separate Modbus client, so it never calls PLC Python methods directly.

The server is intentionally a small compatibility runtime. For an OpenPLC
deployment, create a six-register holding-register program with the same
addresses and keep the HMI and process command lines pointed at the OpenPLC
host and port. No OpenPLC source is copied into this project.