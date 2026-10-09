"""What the device agent needs from whatever controls the Wi-Fi adapter."""

from __future__ import annotations

from typing import Protocol

from wifiprov.wifi import ConnectResult, WifiCredentials, WifiNetwork


class NetworkBackend(Protocol):
    """The agent only talks to this interface.

    A fake implementation lets everything be tested without a Wi-Fi adapter;
    the real one drives NetworkManager.
    """

    async def scan(self) -> list[WifiNetwork]:
        """The networks in range, strongest first. Hidden networks are left out."""

    async def connect(self, credentials: WifiCredentials) -> ConnectResult:
        """Try to join a network.

        If it does not work, the device must be left as it was before the call:
        still on the network it had, or still waiting for provisioning. A device
        that loses its connection because someone typed a wrong password is a
        device that someone has to drive to. If the call is cancelled, for
        example by a timeout, the same rule applies.
        """
