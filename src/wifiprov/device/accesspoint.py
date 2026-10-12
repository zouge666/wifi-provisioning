"""Provisioning through the device's own Wi-Fi network."""

from __future__ import annotations

import asyncio
import logging

from wifiprov.device.networkmanager import NetworkManagerBackend
from wifiprov.wifi import ConnectResult, WifiCredentials, WifiNetwork

logger = logging.getLogger(__name__)


class AccessPointBackend:
    """Lets a phone talk to the device over a Wi-Fi network that the device makes itself.

    The adapter has one radio. While it is an access point it cannot scan and it cannot
    join another network. So the scan is done before the access point starts, and joining
    a network starts by closing the access point. That cuts off the phone. When joining
    fails the access point comes back, and the phone can reconnect and ask what happened.
    """

    drops_link = True

    def __init__(self, wifi: NetworkManagerBackend, ssid: str) -> None:
        self._wifi = wifi
        self._ssid = ssid
        self._networks: list[WifiNetwork] = []

    async def start(self) -> str:
        """Scan, then open the access point. Returns the address of this machine on it."""
        self._networks = await self._wifi.scan()
        return await self._wifi.start_access_point(self._ssid)

    async def stop(self) -> None:
        await self._wifi.stop_access_point()

    async def scan(self) -> list[WifiNetwork]:
        return self._networks  # as it was before the access point opened

    async def connect(self, credentials: WifiCredentials) -> ConnectResult:
        await self._wifi.stop_access_point()  # the phone is cut off here
        try:
            result = await self._wifi.connect(credentials)
        except BaseException:
            await asyncio.shield(self._reopen())  # also when the attempt is cancelled
            raise
        if not result.connected:
            await self._reopen()
        return result

    async def _reopen(self) -> None:
        try:
            await self.start()
        except Exception as error:
            # Nothing more can be done here. The window will end and the next one starts again.
            logger.error("the access point could not be opened again: %s", error)
