"""The configurator's side of provisioning, written as a library.

A phone app, a web page and the command line all do the same things in the same
order: open a session with the device on the sticker, look at the networks it can
see, and send the password of the one the technician picks.
"""

from __future__ import annotations

import asyncio
import contextlib
from types import TracebackType

from wifiprov import messages
from wifiprov.handshake import ConfiguratorHandshake, HandshakeError, WrongDevice
from wifiprov.messages import MessageError, NetworkList, ProvisionRequest, ScanRequest
from wifiprov.session import Session, SessionError
from wifiprov.ticket import Ticket
from wifiprov.transport.base import Transport, TransportClosed
from wifiprov.wifi import ConnectResult, WifiCredentials, WifiNetwork
from wifiprov.wire import MessageType, RejectReason, WireError, decode_reject

_REJECT = bytes([MessageType.REJECT])


class ProvisioningError(Exception):
    """Something went wrong that the person holding the phone should hear about."""


class DeviceRefused(ProvisioningError):
    """The device would not continue: it is locked, busy or did not accept the setup code."""

    def __init__(self, reason: RejectReason, retry_after: int = 0) -> None:
        super().__init__(reason.name.lower())
        self.reason = reason
        self.retry_after = retry_after


class NotTheExpectedDevice(ProvisioningError):
    """Whatever answered is not the device on the sticker."""


class DeviceUnreachable(ProvisioningError):
    """The device did not answer in time, or the connection broke."""


class ProtocolProblem(ProvisioningError):
    """The device sent something that does not make sense."""


class Configurator:
    """One conversation with one device, over a transport that is already connected.

    Use it as ``async with Configurator(ticket, transport) as phone``. The device
    speaks first (its hello), the phone speaks first inside the encrypted session.
    The password is never the first thing sent: ``join`` makes sure the device has
    answered something before it sends the password, because an answer proves the
    device has the same keys.
    """

    def __init__(
        self,
        ticket: Ticket,
        transport: Transport,
        *,
        timeout: float = 30.0,
        join_timeout: float = 90.0,
    ) -> None:
        self._ticket = ticket
        self._transport = transport
        self._timeout = timeout
        self._join_timeout = join_timeout  # joining a network can take a while
        self._session: Session | None = None
        self._confirmed = False  # has the device answered at least once?

    async def __aenter__(self) -> Configurator:
        await self.open()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.close()

    async def open(self) -> None:
        """Run the handshake. Raises if the device refuses or is not the one on the sticker."""
        first = await self._receive(self._timeout)
        if first[:1] == _REJECT:
            raise _refusal(first)
        try:
            keyshare, self._session = ConfiguratorHandshake(self._ticket).accept(first)
        except WrongDevice as error:
            raise NotTheExpectedDevice(str(error)) from None
        except HandshakeError as error:
            raise ProtocolProblem(str(error)) from None
        await self._send(keyshare)

    async def scan(self) -> list[WifiNetwork]:
        """The networks the device can see, strongest first."""
        reply = await self._ask(ScanRequest(), self._timeout)
        if not isinstance(reply, NetworkList):
            raise ProtocolProblem("the device answered a scan with something else")
        return list(reply.networks)

    async def join(self, credentials: WifiCredentials) -> ConnectResult:
        """Ask the device to join a network. A failed attempt can simply be tried again."""
        if not self._confirmed:
            await self.scan()
        reply = await self._ask(ProvisionRequest(credentials), self._join_timeout)
        if not isinstance(reply, ConnectResult):
            raise ProtocolProblem("the device answered a join request with something else")
        return reply

    async def close(self) -> None:
        with contextlib.suppress(TransportClosed):
            await self._transport.close()

    async def _ask(self, request: ScanRequest | ProvisionRequest, timeout: float):
        if self._session is None:
            raise RuntimeError("call open() before sending requests")
        await self._send(self._session.encrypt(messages.encode(request)))
        data = await self._receive(timeout)
        if data[:1] == _REJECT:
            raise _refusal(data)
        try:
            reply = messages.decode_response(self._session.decrypt(data))
        except (SessionError, MessageError):
            raise ProtocolProblem("the device sent a message that could not be read") from None
        self._confirmed = True
        return reply

    async def _send(self, message: bytes) -> None:
        try:
            await self._transport.send(message)
        except TransportClosed:
            raise DeviceUnreachable("the connection to the device was closed") from None

    async def _receive(self, timeout: float) -> bytes:
        try:
            return await asyncio.wait_for(self._transport.receive(), timeout)
        except asyncio.TimeoutError:
            raise DeviceUnreachable("the device did not answer in time") from None
        except TransportClosed:
            raise DeviceUnreachable("the connection to the device was closed") from None


def _refusal(data: bytes) -> ProvisioningError:
    try:
        reason, retry_after = decode_reject(data)
    except WireError:
        return ProtocolProblem("the device sent a refusal that could not be read")
    return DeviceRefused(reason, retry_after)
