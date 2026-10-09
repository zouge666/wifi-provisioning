"""A pretend Wi-Fi adapter for tests and demos: nothing real is touched."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass

from wifiprov.secret import Secret
from wifiprov.wifi import ConnectResult, Failure, Security, WifiCredentials, WifiNetwork


@dataclass(frozen=True)
class FakeNetwork:
    password: str | None = None  # None: an open network
    signal: int = 70
    ip: str | None = "192.168.1.50"  # None: the network hands out no address


class FakeBackend:
    """Behaves like a Wi-Fi adapter surrounded by the networks it is given.

    A failed attempt leaves ``connected_to`` as it was, like the real thing must.
    ``hold`` and ``connect_delay`` make a connection attempt slow, so tests can
    look at what the agent does in the middle of it.
    """

    def __init__(
        self,
        networks: Mapping[str, FakeNetwork] | None = None,
        *,
        connected_to: str | None = None,
        connect_delay: float = 0.0,
        hold: asyncio.Event | None = None,
    ) -> None:
        self.networks = dict(networks or {})
        self.connected_to = connected_to
        self.attempts: list[str] = []
        self._connect_delay = connect_delay
        self._hold = hold

    async def scan(self) -> list[WifiNetwork]:
        strongest_first = sorted(self.networks.items(), key=lambda item: -item[1].signal)
        return [
            WifiNetwork(
                ssid,
                network.signal,
                Security.OPEN if network.password is None else Security.WPA_PSK,
            )
            for ssid, network in strongest_first
        ]

    async def connect(self, credentials: WifiCredentials) -> ConnectResult:
        self.attempts.append(credentials.ssid)
        if self._hold is not None:
            await self._hold.wait()
        if self._connect_delay:
            await asyncio.sleep(self._connect_delay)

        network = self.networks.get(credentials.ssid)
        if network is None:
            return ConnectResult(False, Failure.NETWORK_NOT_FOUND)
        if network.password is not None and credentials.password != Secret(network.password):
            return ConnectResult(False, Failure.WRONG_PASSWORD)
        if network.ip is None:
            return ConnectResult(False, Failure.NO_ADDRESS)
        self.connected_to = credentials.ssid
        return ConnectResult(True, ip=network.ip)
