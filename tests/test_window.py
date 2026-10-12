import asyncio
import contextlib

from wifiprov.device.window import Window

SECONDS = 600


class FakeChannel:
    def __init__(self):
        self.closed = False

    async def close(self):
        self.closed = True


class Setup:
    """A window with a pretend network and a pretend way in, and a clock that does not wait."""

    def __init__(self, *, online=lambda: False):
        self.channels = []
        self.slept = []
        self.stop_time = asyncio.Event()  # the window timer waits for this
        self.online = online
        self.window = Window(
            self.open_channel, self.has_network, seconds=SECONDS, grace=30, poll=2, sleep=self.sleep
        )

    async def open_channel(self):
        channel = FakeChannel()
        self.channels.append(channel)
        return channel

    async def has_network(self):
        return self.online()

    async def sleep(self, seconds):
        self.slept.append(seconds)
        if seconds == SECONDS:  # the window timer
            await self.stop_time.wait()


async def let_the_window_open(setup):
    while not setup.channels:
        await asyncio.sleep(0)


async def test_the_window_stays_closed_when_the_device_has_a_network():
    setup = Setup(online=lambda: True)
    assert await setup.window.run() == "has_network"
    assert setup.channels == []


async def test_the_window_opens_when_there_is_no_network_and_closes_when_the_time_is_up():
    setup = Setup()
    round_ = asyncio.create_task(setup.window.run())
    await let_the_window_open(setup)
    assert not setup.channels[0].closed  # it stays open for as long as the time lasts
    setup.stop_time.set()
    assert await round_ == "timeout"
    assert setup.channels[0].closed


async def test_the_window_closes_as_soon_as_a_configurator_has_given_the_device_a_network():
    setup = Setup()
    round_ = asyncio.create_task(setup.window.run())
    await let_the_window_open(setup)
    setup.window.provisioned()
    assert await round_ == "connected"
    assert setup.channels[0].closed


async def test_the_device_waits_a_while_for_the_network_to_come_up_after_a_boot():
    answers = iter([False, False, False, True])
    setup = Setup(online=lambda: next(answers))
    assert await setup.window.run() == "has_network"
    assert setup.slept == [2, 2, 2]  # it asked again after each short wait
    assert setup.channels == []


async def test_the_device_gives_up_waiting_for_the_network_after_the_grace_time():
    setup = Setup()
    round_ = asyncio.create_task(setup.window.run())
    await let_the_window_open(setup)
    assert sum(s for s in setup.slept if s != SECONDS) == 30  # fifteen waits of two seconds
    setup.stop_time.set()
    await round_


async def test_a_window_that_is_asked_for_opens_even_when_the_device_has_a_network():
    setup = Setup(online=lambda: True)
    round_ = asyncio.create_task(setup.window.run(force=True))
    await let_the_window_open(setup)
    setup.stop_time.set()
    assert await round_ == "timeout"


async def test_the_window_is_closed_when_the_service_is_stopped():
    setup = Setup()
    round_ = asyncio.create_task(setup.window.run())
    await let_the_window_open(setup)
    round_.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await round_
    assert setup.channels[0].closed


async def test_the_window_can_open_again_after_it_has_closed():
    setup = Setup()
    for index in range(2):
        setup.stop_time.clear()
        round_ = asyncio.create_task(setup.window.run(force=True))
        while len(setup.channels) < index + 1:
            await asyncio.sleep(0)
        setup.window.provisioned()
        assert await round_ == "connected"
    assert [channel.closed for channel in setup.channels] == [True, True]
