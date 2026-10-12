import asyncio
import re
from importlib import resources
from pathlib import Path

import pytest
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed

from wifiprov.configurator.client import Configurator
from wifiprov.device.agent import DeviceAgent, Outcome
from wifiprov.device.fake import FakeBackend, FakeNetwork
from wifiprov.identity import DeviceIdentity
from wifiprov.secret import Secret
from wifiprov.ticket import Ticket
from wifiprov.transport.base import TransportClosed
from wifiprov.transport.web import FILES, WebSocketTransport, serve_web
from wifiprov.wifi import WifiCredentials


@pytest.fixture
def page(tmp_path):
    (tmp_path / "index.html").write_text("<h1>the page</h1>")
    (tmp_path / "app.js").write_text("console.log(1)")
    (tmp_path / "style.css").write_text("body {}")
    return tmp_path


async def echo(transport):
    try:
        while True:
            await transport.send(await transport.receive())
    except TransportClosed:
        pass


@pytest.fixture
async def web(page):
    server = await serve_web(echo, "127.0.0.1", 0, files=page)
    yield server
    server.close()
    await server.wait_closed()


async def get(port, path):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(f"GET {path} HTTP/1.1\r\nHost: device\r\nConnection: close\r\n\r\n".encode())
    await writer.drain()
    data = await reader.read()
    writer.close()
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode().split("\r\n")
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers[name.lower()] = value.strip()
    return lines[0], headers, body


# ------------------------------------------------------------------------- the page


@pytest.mark.parametrize(
    ("path", "content_type", "body"),
    [
        ("/", "text/html; charset=utf-8", b"<h1>the page</h1>"),
        ("/app.js", "text/javascript; charset=utf-8", b"console.log(1)"),
        ("/style.css", "text/css; charset=utf-8", b"body {}"),
        ("/?x=1", "text/html; charset=utf-8", b"<h1>the page</h1>"),
    ],
)
async def test_the_files_of_the_page_are_served_with_the_right_type(web, path, content_type, body):
    status, headers, got = await get(web.port, path)
    assert status == "HTTP/1.1 200 OK"
    assert headers["content-type"] == content_type
    assert got == body


async def test_the_page_may_load_only_its_own_files_and_is_never_cached(web):
    _, headers, _ = await get(web.port, "/")
    policy = headers["content-security-policy"]
    assert "default-src 'none'" in policy
    assert "script-src 'self'" in policy
    assert "frame-ancestors 'none'" in policy
    assert headers["cache-control"] == "no-store"
    assert headers["x-content-type-options"] == "nosniff"
    assert "server" not in headers  # it does not say which software it is


@pytest.mark.parametrize(
    "path", ["/index.html", "/etc/passwd", "/../app.js", "/app.js.map", "/%2e%2e/app.js", "/ws/x"]
)
async def test_nothing_but_the_known_files_is_served(web, path):
    status, _, _ = await get(web.port, path)
    assert status.startswith("HTTP/1.1 404")


async def test_a_file_that_is_missing_is_not_found(web, page):
    (page / "app.js").unlink()
    status, _, _ = await get(web.port, "/app.js")
    assert status.startswith("HTTP/1.1 404")


# ------------------------------------------------------------------------- the page that ships

SHIPPED = Path(str(resources.files("wifiprov") / "web"))


async def test_the_device_serves_the_page_that_ships_with_it():
    server = await serve_web(echo, "127.0.0.1", 0)
    try:
        for path in FILES:
            status, _, body = await get(server.port, path)
            assert status == "HTTP/1.1 200 OK"
            assert body
    finally:
        server.close()
        await server.wait_closed()


def test_the_shipped_page_has_no_inline_code_and_loads_only_its_own_files():
    html = (SHIPPED / "index.html").read_text(encoding="utf-8")
    assert re.findall(r"<script[^>]*>", html) == ['<script src="/app.js">']
    assert re.findall(r"<link[^>]*>", html) == ['<link rel="stylesheet" href="/style.css">']
    assert "<style" not in html
    assert "style=" not in html
    assert not re.search(r"\son[a-z]+=", html)  # onclick and the like
    assert "http://" not in html
    assert "https://" not in html


def test_the_shipped_script_and_style_do_not_reach_for_other_hosts():
    script = (SHIPPED / "app.js").read_text(encoding="utf-8")
    style = (SHIPPED / "style.css").read_text(encoding="utf-8")
    for text in (script, style):
        assert "http://" not in text
        assert "https://" not in text
    assert "url(" not in style
    assert "@import" not in style


# ------------------------------------------------------------------------- the WebSocket


async def test_messages_go_both_ways_as_whole_binary_messages(web):
    async with connect(f"ws://127.0.0.1:{web.port}/ws") as client:
        await client.send(b"\x01\x02\x03")
        assert await client.recv() == b"\x01\x02\x03"
        await client.send(b"")
        assert await client.recv() == b""


async def test_text_is_not_part_of_the_protocol(web):
    async with connect(f"ws://127.0.0.1:{web.port}/ws") as client:
        await client.send("hello")
        with pytest.raises(ConnectionClosed):
            await client.recv()


async def test_a_message_that_is_too_large_closes_the_connection(web):
    async with connect(f"ws://127.0.0.1:{web.port}/ws", max_size=None) as client:
        await client.send(bytes(70_000))
        with pytest.raises(ConnectionClosed):
            await client.recv()


async def test_closing_the_server_keeps_a_conversation_going_but_takes_no_new_ones(web):
    port = web.port
    client = await connect(f"ws://127.0.0.1:{port}/ws")
    web.close()
    await client.send(b"still here")
    assert await client.recv() == b"still here"
    await client.close()
    with pytest.raises(OSError):
        await connect(f"ws://127.0.0.1:{port}/ws")


async def test_the_transport_reports_a_closed_connection(web):
    client = await connect(f"ws://127.0.0.1:{web.port}/ws")
    transport = WebSocketTransport(client)
    await transport.close()
    with pytest.raises(TransportClosed):
        await transport.receive()
    with pytest.raises(TransportClosed):
        await transport.send(b"x")


async def test_a_provisioning_conversation_works_over_a_websocket(page):
    identity = DeviceIdentity.generate()
    backend = FakeBackend({"Hospital": FakeNetwork("correct horse", signal=80, ip="10.20.0.7")})
    agent = DeviceAgent(identity, backend, receive_timeout=2.0, connect_timeout=2.0)
    outcomes = []

    async def handle(transport):
        outcomes.append(await agent.serve(transport))

    server = await serve_web(handle, "127.0.0.1", 0, files=page)
    try:
        async with connect(f"ws://127.0.0.1:{server.port}/ws") as client:
            ticket = Ticket.from_identity(identity)
            async with Configurator(ticket, WebSocketTransport(client), timeout=2.0) as phone:
                assert [n.ssid for n in await phone.scan()] == ["Hospital"]
                result = await phone.join(WifiCredentials("Hospital", Secret("correct horse")))
        assert result.connected
        assert result.ip == "10.20.0.7"
    finally:
        server.close()
        await server.wait_closed()
    assert outcomes == [Outcome.CONNECTED]
