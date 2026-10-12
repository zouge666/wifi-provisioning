"""The page and a WebSocket, served from the same port.

The device serves its own page, so a phone needs nothing installed. A plain request for
one of the known files gets that file. A request to /ws becomes a WebSocket, and each
WebSocket is one conversation, carried as whole binary messages.
"""

from __future__ import annotations

import contextlib
from collections.abc import Awaitable, Callable
from http import HTTPStatus
from importlib import resources
from pathlib import Path

from websockets.asyncio.server import Server, ServerConnection, serve
from websockets.datastructures import Headers
from websockets.exceptions import ConnectionClosed
from websockets.http11 import Request, Response

from wifiprov.transport.base import Transport, TransportClosed
from wifiprov.transport.tcp import MAX_FRAME_BYTES

WEBSOCKET_PATH = "/ws"

# The files of the page. Nothing else is ever read from disk.
FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}

# The page loads only its own script and style, and talks only to this device.
_SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self' ws:; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
}


class WebSocketTransport:
    """Messages over a WebSocket. It works for both ends of the connection."""

    def __init__(self, connection) -> None:
        self._connection = connection

    async def send(self, message: bytes) -> None:
        if len(message) > MAX_FRAME_BYTES:
            raise ValueError(f"a message is at most {MAX_FRAME_BYTES} bytes")
        try:
            await self._connection.send(message)
        except ConnectionClosed:
            raise TransportClosed("the connection is closed") from None

    async def receive(self) -> bytes:
        try:
            message = await self._connection.recv()
        except ConnectionClosed:
            raise TransportClosed("the connection is closed") from None
        if isinstance(message, str):
            await self.close()  # the protocol is binary: text means something else is talking
            raise TransportClosed("the other side sent text, not bytes")
        return message

    async def close(self) -> None:
        with contextlib.suppress(ConnectionClosed, OSError):
            await self._connection.close()


class WebServer:
    """The running server. Closing it stops new visitors but lets a conversation finish."""

    def __init__(self, server: Server) -> None:
        self._server = server

    @property
    def port(self) -> int:
        return self._server.sockets[0].getsockname()[1]

    def close(self) -> None:
        self._server.close(close_connections=False)

    async def wait_closed(self) -> None:
        await self._server.wait_closed()


async def serve_web(
    handler: Callable[[Transport], Awaitable[None]],
    host: str,
    port: int,
    *,
    files: Path | None = None,
) -> WebServer:
    """Serve the page and accept conversations. ``files`` is where the page files are."""
    folder = files if files is not None else Path(str(resources.files("wifiprov") / "web"))

    async def conversation(connection: ServerConnection) -> None:
        await handler(WebSocketTransport(connection))

    def answer(connection: ServerConnection, request: Request) -> Response | None:
        path = request.path.split("?", 1)[0]
        if path == WEBSOCKET_PATH:
            return None  # the WebSocket handshake goes on
        if path not in FILES:
            return _reply(HTTPStatus.NOT_FOUND, "text/plain; charset=utf-8", b"Not found\n")
        name, content_type = FILES[path]
        try:
            body = (folder / name).read_bytes()
        except OSError:
            return _reply(HTTPStatus.NOT_FOUND, "text/plain; charset=utf-8", b"Not found\n")
        return _reply(HTTPStatus.OK, content_type, body)

    server = await serve(
        conversation,
        host,
        port,
        process_request=answer,
        max_size=MAX_FRAME_BYTES,
        compression=None,
        server_header=None,
    )
    return WebServer(server)


def _reply(status: HTTPStatus, content_type: str, body: bytes) -> Response:
    headers = Headers({**_SECURITY_HEADERS, "Content-Type": content_type})
    headers["Content-Length"] = str(len(body))
    return Response(status.value, status.phrase, headers, body)
