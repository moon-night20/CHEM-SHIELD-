"""Validated device communication boundary for the operator HMI."""

from __future__ import annotations

import ipaddress
from threading import RLock
from typing import Any, Callable

from pymodbus.client import ModbusTcpClient


class DeviceConnection:
    def __init__(self, host: str, port: int, name: str = "PLC-01") -> None:
        self._lock = RLock()
        self.name = name
        self.host = host
        self.port = port
        self.status = "DISCONNECTED"
        self.error = ""
        self._client: ModbusTcpClient | None = None

    @staticmethod
    def validate(host: str, port: int) -> tuple[str, int]:
        host = str(host).strip()
        if not host:
            raise ValueError("IP address is required")
        try:
            ipaddress.ip_address(host)
        except ValueError as error:
            raise ValueError("IP address must be valid") from error
        try:
            port = int(port)
        except (TypeError, ValueError) as error:
            raise ValueError("Port must be between 1 and 65535") from error
        if not 1 <= port <= 65535:
            raise ValueError("Port must be between 1 and 65535")
        return host, port

    def configure(self, host: str, port: int, name: str | None = None) -> None:
        host, port = self.validate(host, port)
        self.disconnect()
        self.host, self.port = host, port
        if name and name.strip():
            self.name = name.strip()[:40]
        self.error = ""

    def connect(self) -> dict[str, Any]:
        self.status, self.error = "CONNECTING", ""
        client = ModbusTcpClient(self.host, port=self.port)
        if not client.connect():
            client.close()
            self.status = "CONNECTION ERROR"
            self.error = f"Unable to connect to {self.host}:{self.port}"
            raise ConnectionError(self.error)
        self._client = client
        self.status = "CONNECTED"
        return self.snapshot()

    def disconnect(self) -> dict[str, Any]:
        if self._client is not None:
            self._client.close()
        self._client = None
        self.status = "DISCONNECTED"
        return self.snapshot()

    def reconnect(self) -> dict[str, Any]:
        self.disconnect()
        return self.connect()

    def call(self, action: Callable[[ModbusTcpClient], Any]) -> Any:
        with self._lock:
            if self._client is None:
                raise ConnectionError("Device is disconnected")
            try:
                return action(self._client)
            except Exception as error:
                self.status, self.error = "CONNECTION ERROR", str(error)
                self._client.close()
                self._client = None
                raise

    def snapshot(self) -> dict[str, Any]:
        return {"name": self.name, "host": self.host, "port": self.port, "status": self.status, "error": self.error}
