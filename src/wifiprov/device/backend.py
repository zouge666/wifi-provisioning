"""What the device agent needs from whatever controls the Wi-Fi adapter."""

from __future__ import annotations

from typing import Protocol

from wifiprov.wifi import ConnectResult, WifiCredentials, WifiNetwork


class NetworkBackend(Protocol):
    """The agent only talks to this interface.

    A fake implementation lets everything be tested without a Wi-Fi adapter;
    the real one drives NetworkManager.

    ``drops_link`` is True when joining a network cuts off the configurator, for example
    because the device talks to it over its own Wi-Fi network. The conversation is over
    after such an attempt, because the configurator has to come back and ask.
    """

    drops_link: bool

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
