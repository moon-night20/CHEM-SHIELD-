"""Modbus TCP endpoint representing the process-side I/O boundary."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
import ipaddress
import logging
from queue import Full, Queue
from threading import Lock, Thread

from pymodbus.datastore import ModbusSequentialDataBlock, ModbusServerContext, ModbusSlaveContext
from pymodbus.server.async_io import ModbusServerRequestHandler, ModbusTcpServer

from chem_shield_common.publisher import publish_events
from chem_shield_p1.plc.register_map import (
    ACTUAL_RPM,
    MOTOR_COMMAND,
    POWER,
    PRESSURE,
    REGISTER_COUNT,
    SLAVE_ID,
    TARGET_RPM,
    TEMPERATURE,
    decode_decimal,
    encode_power,
    encode_pressure,
    encode_temperature,
)
from chem_shield_p2.modbus_write_monitor import ModbusTcpWriteMonitor

DEFAULT_PLC_HOST = "127.0.0.1"
DEFAULT_PLC_PORT = 15020
LOGGER = logging.getLogger(__name__)


class ProcessRegisterBank:
    """Thread-safe register bank shared by the Modbus server and process loop."""

    def __init__(self) -> None:
        self._lock = Lock()
        self.values = [0] * REGISTER_COUNT
        self.values[TARGET_RPM] = 1400

    def read_commands(self) -> tuple[bool, float]:
        with self._lock:
            return bool(self.values[MOTOR_COMMAND]), float(self.values[TARGET_RPM])

    def write_telemetry(self, state: dict) -> None:
        with self._lock:
            self.values[ACTUAL_RPM] = round(state["rpm"])
            self.values[TEMPERATURE] = encode_temperature(state["temperature"])
            self.values[PRESSURE] = encode_pressure(state["pressure"])
            self.values[POWER] = encode_power(state["power"])

    def snapshot(self) -> dict[str, float | int]:
        with self._lock:
            return {
                "motor_command": self.values[MOTOR_COMMAND],
                "target_rpm": self.values[TARGET_RPM],
                "actual_rpm": self.values[ACTUAL_RPM],
                "temperature": decode_decimal(self.values[TEMPERATURE]),
                "pressure": decode_decimal(self.values[PRESSURE]),
                "power": decode_decimal(self.values[POWER]),
            }


def create_context(bank: ProcessRegisterBank) -> ModbusServerContext:
    # The callback block lets Modbus clients observe and change the shared bank.
    class BankBlock(ModbusSequentialDataBlock):
        def __init__(self):
            # PyModbus 3.8 uses one-based internal datastore addresses.
            super().__init__(1, [0] * (REGISTER_COUNT + 1))

        def getValues(self, address, count=1):
            with bank._lock:
                return bank.values[address - 1:address - 1 + count]

        def setValues(self, address, values):
            with bank._lock:
                bank.values[address - 1:address - 1 + len(values)] = values

    store = ModbusSlaveContext(hr=BankBlock())
    return ModbusServerContext(slaves=store, single=True)


class _LocalEventPublisher:
    """Publish monitor events off the Modbus request path."""

    def __init__(self) -> None:
        self._events: Queue[dict] = Queue(maxsize=1000)
        self._worker = Thread(
            target=self._publish_loop,
            name="modbus-event-publisher",
            daemon=True,
        )
        self._worker.start()

    def submit(self, event: dict) -> None:
        try:
            self._events.put_nowait(event)
        except Full:
            LOGGER.error(
                "Local Modbus event queue is full; event %s was not queued",
                event["event_id"],
            )

    def _publish_loop(self) -> None:
        while True:
            event = self._events.get()
            try:
                result = publish_events([event])
                if result["failed_batches"] or result["rejected"]:
                    LOGGER.warning("Modbus monitor HMI publish result: %s", result)
            except (TypeError, ValueError, OSError):
                LOGGER.exception("Could not publish Modbus monitor event %s", event["event_id"])
            finally:
                self._events.task_done()


class _MonitoredRequestHandler(ModbusServerRequestHandler):
    def execute(self, request, *addr):
        peer = self.transport.get_extra_info("peername") if self.transport else None
        source_address = peer[0] if peer else "unknown"
        self.server.write_monitor.inspect(request, source_address)
        super().execute(request, *addr)


class MonitoredModbusTcpServer(ModbusTcpServer):
    """Virtual PLC server with a passive decoded-request observation hook."""

    def __init__(
        self,
        context,
        address,
        write_monitor: ModbusTcpWriteMonitor,
        event_sink: Callable[[dict], None],
    ) -> None:
        self.write_monitor = write_monitor
        self.event_sink = event_sink
        self.write_monitor.event_sink = self.event_sink
        super().__init__(context, address=address)

    def callback_new_connection(self):
        return _MonitoredRequestHandler(self)


def serve(
    bank: ProcessRegisterBank,
    host: str = DEFAULT_PLC_HOST,
    port: int = DEFAULT_PLC_PORT,
) -> None:
    try:
        address = ipaddress.ip_address(host)
    except ValueError as error:
        raise ValueError("virtual PLC must bind to loopback address 127.0.0.1") from error
    if address != ipaddress.ip_address(DEFAULT_PLC_HOST):
        raise ValueError("virtual PLC must bind to loopback address 127.0.0.1")

    publisher = _LocalEventPublisher()
    monitor = ModbusTcpWriteMonitor()

    async def run_server() -> None:
        server = MonitoredModbusTcpServer(
            create_context(bank),
            address=(DEFAULT_PLC_HOST, port),
            write_monitor=monitor,
            event_sink=publisher.submit,
        )
        await server.serve_forever()

    asyncio.run(run_server())