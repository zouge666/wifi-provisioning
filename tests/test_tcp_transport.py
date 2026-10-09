import asyncio

import pytest

from wifiprov.transport.base import TransportClosed
from wifiprov.transport.tcp import MAX_FRAME_BYTES, connect_tcp, serve_tcp


class EchoServer:
    """Sends back every message it receives, and notes how each connection ended."""

    def __init__(self):
        self.server = None
        self.port = 0
        self.endings = []

    async def start(self):
        self.server = await serve_tcp(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def _handle(self, transport):
        try:
            while True:
                await transport.send(await transport.receive())
        except TransportClosed as error:
            self.endings.append(str(error))
        finally:
            await transport.close()

    async def stop(self):
        self.server.close()
        await self.server.wait_closed()


@pytest.fixture
async def echo():
    server = EchoServer()
    await server.start()
    yield server
    await server.stop()


async def test_messages_of_any_size_arrive_whole(echo):
    client = await connect_tcp("127.0.0.1", echo.port)
    for size in (0, 1, 5, 1000, MAX_FRAME_BYTES):
        message = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
        await client.send(message)
        assert await client.receive() == message
    await client.close()


async def test_message_boundaries_survive_when_many_are_sent_back_to_back(echo):
    client = await connect_tcp("127.0.0.1", echo.port)
    messages = [f"message {n}".encode() * (n % 7 + 1) for n in range(200)]
    for message in messages:
        await client.send(message)
    assert [await client.receive() for _ in messages] == messages
    await client.close()


async def test_a_message_delivered_in_pieces_is_put_back_together(echo):
    reader, writer = await asyncio.open_connection("127.0.0.1", echo.port)
    payload = b"hello in pieces"
    frame = len(payload).to_bytes(4, "big") + payload
    for piece in (frame[:2], frame[2:6], frame[6:]):
        writer.write(piece)
        await writer.drain()
        await asyncio.sleep(0.02)
    assert await reader.readexactly(len(frame)) == frame
    writer.close()


async def test_a_message_that_is_too_large_is_refused_before_it_is_sent(echo):
    client = await connect_tcp("127.0.0.1", echo.port)
    with pytest.raises(ValueError):
        await client.send(bytes(MAX_FRAME_BYTES + 1))
    await client.close()


async def test_an_announced_oversized_message_closes_the_connection(echo):
    reader, writer = await asyncio.open_connection("127.0.0.1", echo.port)
    writer.write((MAX_FRAME_BYTES + 1).to_bytes(4, "big"))
    await writer.drain()
    assert await reader.read() == b""  # the server hung up
    assert any("oversized" in ending for ending in echo.endings)
    writer.close()


async def test_closing_one_side_is_noticed_by_the_other(echo):
    client = await connect_tcp("127.0.0.1", echo.port)
    await client.close()
    await asyncio.sleep(0.05)
    assert echo.endings == ["the connection is closed"]


async def test_when_the_server_hangs_up_receive_says_so():
    async def hang_up(transport):
        await transport.close()

    server = await serve_tcp(hang_up, "127.0.0.1", 0)
    client = await connect_tcp("127.0.0.1", server.sockets[0].getsockname()[1])
    with pytest.raises(TransportClosed):
        await client.receive()
    await client.close()
    server.close()
    await server.wait_closed()


async def test_sending_on_a_connection_that_was_closed_fails_the_same_way_every_time(echo):
    client = await connect_tcp("127.0.0.1", echo.port)
    await client.close()
    with pytest.raises(TransportClosed):
        await client.send(b"too late")
    await client.close()  # closing again is fine


async def test_connecting_to_nothing_raises_an_os_error():
    server = await serve_tcp(lambda transport: asyncio.sleep(0), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()
    with pytest.raises(OSError):
        await connect_tcp("127.0.0.1", port)
