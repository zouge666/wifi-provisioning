"""What the rest of the code expects from any way of carrying messages."""

from __future__ import annotations

from typing import Protocol


class TransportClosed(Exception):
    """The other side has gone away, or this side was already closed."""


class Transport(Protocol):
    """One connection that carries whole messages, in order, without loss.

    Bluetooth, a hotspot with a web server, a TCP socket and an in-memory pair
    can all provide this, and the protocol above does not care which one it is.
    A transport that has to cut messages into smaller pieces does that inside
    itself, so callers only ever see complete messages.
    """

    async def send(self, message: bytes) -> None:
        """Send one message. Raises TransportClosed if the connection is gone."""

    async def receive(self) -> bytes:
        """Wait for the next message. Raises TransportClosed when the other side closes."""

    async def close(self) -> None:
        """Close the connection. Closing twice is fine."""
