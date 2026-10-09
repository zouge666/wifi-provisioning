import asyncio

import pytest

from wifiprov.transport.base import TransportClosed
from wifiprov.transport.memory import memory_transport_pair


async def test_messages_arrive_whole_and_in_order():
    a, b = memory_transport_pair()
    for message in (b"one", b"two", b"three"):
        await a.send(message)
    assert [await b.receive() for _ in range(3)] == [b"one", b"two", b"three"]


async def test_each_direction_is_independent():
    a, b = memory_transport_pair()
    await a.send(b"to b")
    await b.send(b"to a")
    assert await b.receive() == b"to b"
    assert await a.receive() == b"to a"


async def test_everything_sent_is_recorded_per_end():
    a, b = memory_transport_pair()
    await a.send(b"one")
    await b.send(b"two")
    assert a.sent == [b"one"]
    assert b.sent == [b"two"]


async def test_receive_waits_for_a_message():
    a, b = memory_transport_pair()
    waiting = asyncio.create_task(b.receive())
    await asyncio.sleep(0.02)
    assert not waiting.done()
    await a.send(b"now")
    assert await waiting == b"now"


async def test_closing_wakes_up_a_waiting_peer():
    a, b = memory_transport_pair()
    waiting = asyncio.create_task(b.receive())
    await asyncio.sleep(0.02)
    await a.close()
    with pytest.raises(TransportClosed):
        await waiting


async def test_closing_wakes_up_a_waiting_receiver_on_the_same_end():
    a, _ = memory_transport_pair()
    waiting = asyncio.create_task(a.receive())
    await asyncio.sleep(0.02)
    await a.close()
    with pytest.raises(TransportClosed):
        await waiting


async def test_messages_sent_before_the_close_are_still_delivered():
    a, b = memory_transport_pair()
    await a.send(b"last words")
    await a.close()
    assert await b.receive() == b"last words"
    with pytest.raises(TransportClosed):
        await b.receive()
    with pytest.raises(TransportClosed):
        await b.receive()  # and it stays closed


async def test_sending_on_a_closed_connection_fails_from_either_side():
    a, b = memory_transport_pair()
    await a.close()
    with pytest.raises(TransportClosed):
        await a.send(b"x")
    with pytest.raises(TransportClosed):
        await b.send(b"x")


async def test_closing_twice_is_fine():
    a, _ = memory_transport_pair()
    await a.close()
    await a.close()
