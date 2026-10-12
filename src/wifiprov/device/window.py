"""When the device listens for a configurator, and for how long."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable
from typing import Protocol

logger = logging.getLogger(__name__)


class Channel(Protocol):
    """A way in for configurators that can be shut. An asyncio server is one."""

    def close(self) -> None: ...


class Window:
    """Lets configurators in for a limited time.

    The device only listens while the window is open. It opens when the device has no
    network, or when someone asks for it, and it closes when a configurator has given
    the device a network or when the time is up. A device that has a network is not
    listening, so nobody can try its setup code.
    """

    def __init__(
        self,
        open_channel: Callable[[], Awaitable[Channel]],
        has_network: Callable[[], Awaitable[bool]],
        *,
        seconds: float,
        grace: float = 30.0,
        poll: float = 2.0,
        sleep: Callable[[float], Awaitable[object]] = asyncio.sleep,
    ) -> None:
        self._open_channel = open_channel
        self._has_network = has_network
        self._seconds = seconds
        self._grace = grace  # after a boot, how long to wait for the network to come up
        self._poll = poll
        self._sleep = sleep
        self._provisioned = asyncio.Event()

    def provisioned(self) -> None:
        """Tell the window that a configurator has given the device a network."""
        self._provisioned.set()

    async def run(self, *, force: bool = False) -> str:
        """Run one round. It returns how the round ended.

        "has_network": the device had a network, so the window never opened.
        "connected": the window closed because a configurator gave the device a network.
        "timeout": the window closed because the time was up.
        """
        if not force and await self._wait_for_network():
            logger.info("the device has a network, so the provisioning window stays closed")
            return "has_network"

        self._provisioned.clear()
        channel = await self._open_channel()
        logger.info("the provisioning window is open for %s seconds", self._seconds)
        timer = asyncio.create_task(self._sleep(self._seconds))
        connected = asyncio.create_task(self._provisioned.wait())
        try:
            await asyncio.wait({timer, connected}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            channel.close()
            for task in (timer, connected):
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
        result = "connected" if self._provisioned.is_set() else "timeout"
        logger.info("the provisioning window is closed: %s", result)
        return result

    async def _wait_for_network(self) -> bool:
        waited = 0.0
        while not await self._has_network():
            if waited >= self._grace:
                return False
            await self._sleep(self._poll)
            waited += self._poll
        return True
