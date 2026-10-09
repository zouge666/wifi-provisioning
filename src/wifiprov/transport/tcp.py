"""Messages over a TCP connection, for trying things out on one machine or one network.

TCP is a stream of bytes with no message boundaries, so every message is sent as
a 4-byte length followed by the message itself.

This transport needs the two sides to share a network, which the real flow must
not rely on. It exists so the device and the configurator can run as separate
programs before any radio is involved.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable

from wifiprov.transport.base import Transport, TransportClosed

MAX_FRAME_BYTES = 64 * 1024
_LENGTH_BYTES = 4


class TcpTransport:
    """One TCP connection that carries whole messages."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._reader = reader
        self._writer = writer

    async def send(self, message: bytes) -> None:
        if len(message) > MAX_FRAME_BYTES:
            raise ValueError(f"a message is at most {MAX_FRAME_BYTES} bytes")
        if self._writer.is_closing():
            raise TransportClosed("the connection is closed")
        try:
            self._writer.write(len(message).to_bytes(_LENGTH_BYTES, "big") + message)
            await self._writer.drain()
        except OSError:
            raise TransportClosed("the connection is closed") from None

    async def receive(self) -> bytes:
        try:
            header = await self._reader.readexactly(_LENGTH_BYTES)
            length = int.from_bytes(header, "big")
            if length > MAX_FRAME_BYTES:
                await self.close()
                raise TransportClosed("the other side announced an oversized message")
            return await self._reader.readexactly(length)
        except (asyncio.IncompleteReadError, OSError):
            raise TransportClosed("the connection is closed") from None

    async def close(self) -> None:
        if self._writer.is_closing():
            return
        self._writer.close()
        with contextlib.suppress(OSError):
            await self._writer.wait_closed()


async def connect_tcp(host: str, port: int) -> TcpTransport:
    """Open a connection. Raises OSError if nothing is listening."""
    reader, writer = await asyncio.open_connection(host, port)
    return TcpTransport(reader, writer)


async def serve_tcp(
    handler: Callable[[Transport], Awaitable[object]], host: str, port: int
) -> asyncio.AbstractServer:
    """Listen for connections and hand each one to the handler, as a transport."""

    async def on_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await handler(TcpTransport(reader, writer))

    return await asyncio.start_server(on_connection, host, port)
