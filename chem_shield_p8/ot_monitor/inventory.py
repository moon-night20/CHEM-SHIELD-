"""Auto-built inventory for endpoints seen in supplied OT event streams."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .events import OTEvent


@dataclass
class Asset:
    """One known or discovered endpoint in the synthetic plant network."""

    ip_address: str
    role: str
    device_id: str
    first_seen: datetime
    last_seen: datetime
    known: bool
    observations: int = 1

    def as_dict(self) -> dict[str, str | int | bool]:
        return {
            "ip_address": self.ip_address,
            "role": self.role,
            "device_id": self.device_id,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "known": self.known,
            "observations": self.observations,
        }


class AssetInventory:
    """Track first/last observation and classify endpoints from a local map."""

    def __init__(self, known_hosts: dict[str, str] | None = None) -> None:
        self.known_hosts = dict(known_hosts or {})
        self._assets: dict[str, Asset] = {}

    def observe(self, event: OTEvent) -> list[Asset]:
        """Record event endpoints, returning newly discovered assets."""
        discovered: list[Asset] = []
        endpoints = (
            (event.source_ip, "source", event.source_ip),
            (event.destination_ip, event.device_id, event.destination_ip),
        )
        for address, fallback_id, device_id in endpoints:
            known = address in self.known_hosts
            role = self.known_hosts.get(address, "unknown")
            asset = self._assets.get(address)
            if asset is None:
                asset = Asset(
                    ip_address=address,
                    role=role,
                    device_id=device_id or fallback_id,
                    first_seen=event.timestamp,
                    last_seen=event.timestamp,
                    known=known,
                )
                self._assets[address] = asset
                if not known:
                    discovered.append(asset)
            else:
                asset.last_seen = max(asset.last_seen, event.timestamp)
                asset.first_seen = min(asset.first_seen, event.timestamp)
                asset.observations += 1
            if address == event.destination_ip and asset.device_id == address:
                asset.device_id = event.device_id or address
        return discovered

    def get(self, ip_address: str) -> Asset | None:
        return self._assets.get(ip_address)

    def role_for(self, ip_address: str) -> str:
        asset = self._assets.get(ip_address)
        if asset is not None:
            return asset.role
        return self.known_hosts.get(ip_address, "unknown")

    def list_assets(self) -> list[Asset]:
        return sorted(self._assets.values(), key=lambda asset: (asset.role, asset.ip_address))
