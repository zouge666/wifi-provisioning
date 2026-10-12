"""The device's side of provisioning: one conversation at a time, one step after another.

    IDLE -> HANDSHAKE -> AUTHENTICATING -> READY <-> APPLYING -> IDLE

Inside the encrypted session the configurator always speaks first. The device sends
nothing encrypted until that first message has authenticated, because only someone
who knows the setup code can produce one. A reply made earlier, with keys that
depend on the code, would let an attacker who merely connects test guesses offline.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from enum import Enum

from wifiprov import messages
from wifiprov.device.backend import NetworkBackend
from wifiprov.device.lockout import Lockout
from wifiprov.handshake import DeviceHandshake, HandshakeError
from wifiprov.identity import DeviceIdentity
from wifiprov.messages import (
    MessageError,
    NetworkList,
    ProvisionAccepted,
    Response,
    ScanRequest,
    Status,
    StatusRequest,
)
from wifiprov.session import Session, SessionError
from wifiprov.transport.base import Transport, TransportClosed
from wifiprov.wifi import ConnectResult, Failure, WifiCredentials
from wifiprov.wire import RejectReason, encode_reject

logger = logging.getLogger(__name__)


class State(Enum):
    IDLE = "idle"  # waiting for a configurator
    HANDSHAKE = "handshake"  # agreeing on keys
    AUTHENTICATING = "authenticating"  # waiting for the first message, which proves the code
    READY = "ready"  # the configurator is authenticated and may ask for things
    APPLYING = "applying"  # trying to join a Wi-Fi network


class Outcome(Enum):
    """How one conversation ended."""

    CONNECTED = "connected"  # the device joined the network
    FAILED = "failed"  # authenticated, but no network was joined
    AUTH_FAILED = "auth_failed"  # the first message did not authenticate
    LOCKED = "locked"  # refused: too many wrong attempts
    BUSY = "busy"  # refused: already talking to someone
    ABANDONED = "abandoned"  # the other side left, went quiet or broke the protocol


class DeviceAgent:
    """Runs the provisioning conversation for one device.

    ``serve`` handles one connection from its first byte to its last and closes it.
    The caller decides when to listen for connections, for example only while a
    provisioning window is open.
    """

    def __init__(
        self,
        identity: DeviceIdentity,
        backend: NetworkBackend,
        *,
        lockout: Lockout | None = None,
        receive_timeout: float = 30.0,
        connect_timeout: float = 60.0,
    ) -> None:
        self._identity = identity
        self._backend = backend
        self.lockout = lockout if lockout is not None else Lockout()
        self._receive_timeout = receive_timeout
        self._connect_timeout = connect_timeout
        self.state = State.IDLE
        self.last_attempt: tuple[str, ConnectResult] | None = None  # the network and how it went
        self._busy = False

    async def serve(self, transport: Transport) -> Outcome:
        if self._busy:
            await _refuse(transport, RejectReason.BUSY)
            return Outcome.BUSY
        if self.lockout.is_locked():
            await _refuse(transport, RejectReason.LOCKED, self.lockout.retry_after())
            return Outcome.LOCKED
        self._busy = True
        try:
            outcome = await self._converse(transport)
            logger.info("provisioning conversation ended: %s", outcome.value)
            return outcome
        finally:
            self._busy = False
            self.state = State.IDLE
            await _close(transport)

    async def _converse(self, transport: Transport) -> Outcome:
        self.state = State.HANDSHAKE
        handshake = DeviceHandshake(self._identity)
        try:
            await transport.send(handshake.hello())
            session = handshake.finish(await self._receive(transport))
        except (TransportClosed, asyncio.TimeoutError, HandshakeError):
            return Outcome.ABANDONED

        self.state = State.AUTHENTICATING
        try:
            first = await self._receive(transport)
        except (TransportClosed, asyncio.TimeoutError):
            return Outcome.ABANDONED
        try:
            plaintext = session.decrypt(first)
        except SessionError:
            # Only a wrong setup code, or damage in transit, ends up here. Count it
            # and answer with nothing that depends on the code.
            self.lockout.record_failure()
            await _send_reject(transport, RejectReason.AUTH_FAILED)
            return Outcome.AUTH_FAILED

        self.lockout.record_success()
        return await self._serve_requests(transport, session, plaintext)

    async def _serve_requests(
        self, transport: Transport, session: Session, plaintext: bytes
    ) -> Outcome:
        attempted = False  # has the configurator asked to join a network yet?
        while True:
            self.state = State.READY
            try:
                request = messages.decode_request(plaintext)
            except MessageError:
                return Outcome.FAILED if attempted else Outcome.ABANDONED

            reply: Response
            joined = False  # did this request ask to join a network?
            if isinstance(request, ScanRequest):
                reply = NetworkList(tuple(await self._scan()))
            elif isinstance(request, StatusRequest):
                reply = Status(*self.last_attempt) if self.last_attempt else Status()
            else:
                attempted = joined = True
                # Joining may cut the link, so the configurator hears this first.
                await self._send(transport, session, ProvisionAccepted())
                self.state = State.APPLYING
                reply = await self._connect(request.credentials)
                self.last_attempt = (request.credentials.ssid, reply)
                self.state = State.READY

            await self._send(transport, session, reply)
            if isinstance(reply, ConnectResult) and reply.connected:
                return Outcome.CONNECTED
            if joined and self._backend.drops_link:
                return Outcome.FAILED  # the configurator is gone, and has to come back to ask

            try:
                plaintext = session.decrypt(await self._receive(transport))
            except (TransportClosed, asyncio.TimeoutError, SessionError):
                return Outcome.FAILED if attempted else Outcome.ABANDONED

    async def _scan(self) -> list:
        try:
            return list(await self._backend.scan())[: messages.MAX_NETWORKS]
        except Exception as error:
            logger.error("scanning failed unexpectedly: %s", type(error).__name__)
            return []

    async def _connect(self, credentials: WifiCredentials) -> ConnectResult:
        try:
            return await asyncio.wait_for(self._backend.connect(credentials), self._connect_timeout)
        except asyncio.TimeoutError:
            return ConnectResult(False, Failure.TIMEOUT)
        except Exception as error:
            # A bug in the backend must not take the agent down. Only the type of the
            # error is logged: its message might contain the password.
            logger.error("connecting failed unexpectedly: %s", type(error).__name__)
            return ConnectResult(False, Failure.OTHER)

    async def _send(self, transport: Transport, session: Session, message: Response) -> None:
        # If the phone has left, whether the device joined the network still counts.
        with contextlib.suppress(TransportClosed):
            await transport.send(session.encrypt(messages.encode(message)))

    async def _receive(self, transport: Transport) -> bytes:
        return await asyncio.wait_for(transport.receive(), self._receive_timeout)


async def _send_reject(transport: Transport, reason: RejectReason, retry_after: int = 0) -> None:
    with contextlib.suppress(TransportClosed):
        await transport.send(encode_reject(reason, retry_after))


async def _refuse(transport: Transport, reason: RejectReason, retry_after: int = 0) -> None:
    await _send_reject(transport, reason, retry_after)
    await _close(transport)


async def _close(transport: Transport) -> None:
    with contextlib.suppress(TransportClosed):
        await transport.close()
