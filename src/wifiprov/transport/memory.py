"""Two connected ends inside one process: for tests and for simulating many devices."""

from __future__ import annotations

import asyncio

from wifiprov.transport.base import TransportClosed


class MemoryTransport:
    """One end of an in-memory connection. Create both ends with memory_transport_pair()."""

    def __init__(self) -> None:
        self._incoming: asyncio.Queue[bytes | None] = asyncio.Queue()
        self._peer: MemoryTransport | None = None
        self._closed = False
        self.sent: list[bytes] = []  # everything this end has sent, as it went "on the wire"

    async def send(self, message: bytes) -> None:
        peer = self._peer
        if self._closed or peer is None or peer._closed:
            raise TransportClosed("the connection is closed")
        self.sent.append(message)
        peer._incoming.put_nowait(message)

    async def receive(self) -> bytes:
        message = await self._incoming.get()
        if message is None:
            self._incoming.put_nowait(None)  # stay closed for any later call
            raise TransportClosed("the connection is closed")
        return message

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._incoming.put_nowait(None)  # wakes up a receive() waiting on this end
        if self._peer is not None:
            self._peer._incoming.put_nowait(None)


def memory_transport_pair() -> tuple[MemoryTransport, MemoryTransport]:
    first, second = MemoryTransport(), MemoryTransport()
    first._peer, second._peer = second, first
    return first, second
