import asyncio
import logging

import pytest

from wifiprov import messages
from wifiprov.device.agent import DeviceAgent, Outcome, State
from wifiprov.device.fake import FakeBackend, FakeNetwork
from wifiprov.device.lockout import Lockout
from wifiprov.handshake import ConfiguratorHandshake
from wifiprov.identity import DeviceIdentity
from wifiprov.messages import (
    NetworkList,
    ProvisionAccepted,
    ProvisionRequest,
    ScanRequest,
    Status,
    StatusRequest,
)
from wifiprov.secret import Secret
from wifiprov.setup_code import SetupCode
from wifiprov.ticket import Ticket
from wifiprov.transport.base import TransportClosed
from wifiprov.transport.memory import memory_transport_pair
from wifiprov.wifi import ConnectResult, Failure, WifiCredentials
from wifiprov.wire import RejectReason, decode_reject

SSID = "Hospital WiFi"
PASSWORD = "correct horse battery"
NETWORKS = {
    SSID: FakeNetwork(PASSWORD, signal=80, ip="10.20.0.7"),
    "Ward 3": FakeNetwork("another password", signal=60),
    "No DHCP": FakeNetwork("dhcp is broken", signal=50, ip=None),
    "Guest": FakeNetwork(None, signal=40),
}


class Phone:
    """Just enough of a configurator to drive the device in tests."""

    def __init__(self, ticket, transport):
        self.ticket = ticket
        self.transport = transport
        self.session = None

    async def handshake(self):
        hello = await asyncio.wait_for(self.transport.receive(), 2)
        keyshare, self.session = ConfiguratorHandshake(self.ticket).accept(hello)
        await self.transport.send(keyshare)

    async def say(self, message):
        await self.transport.send(self.session.encrypt(messages.encode(message)))

    async def hear(self):
        data = await asyncio.wait_for(self.transport.receive(), 2)
        return messages.decode_response(self.session.decrypt(data))

    async def ask(self, message):
        await self.say(message)
        return await self.hear()

    async def join(self, request):
        """Join a network: the device first says it has the details, then how it went."""
        await self.say(request)
        assert await self.hear() == ProvisionAccepted()
        return await self.hear()


def join(ssid=SSID, password=PASSWORD):
    return ProvisionRequest(WifiCredentials(ssid, Secret(password) if password else None))


@pytest.fixture
def identity():
    return DeviceIdentity.generate()


@pytest.fixture
def ticket(identity):
    return Ticket.from_identity(identity)


@pytest.fixture
def backend():
    return FakeBackend(NETWORKS, connected_to="Old network")


def make_agent(identity, backend, clock, **options):
    options.setdefault("receive_timeout", 1.0)
    options.setdefault("connect_timeout", 1.0)
    return DeviceAgent(identity, backend, lockout=Lockout(clock=clock), **options)


@pytest.fixture
def agent(identity, backend, clock):
    return make_agent(identity, backend, clock)


def connect(agent):
    """Open a connection to the agent. Returns the phone's end, the device's end, and the task."""
    device_end, phone_end = memory_transport_pair()
    return phone_end, device_end, asyncio.create_task(agent.serve(device_end))


async def attempt_with_wrong_code(agent, identity):
    wrong_ticket = Ticket(identity.public_key, SetupCode.generate())
    phone_end, device_end, task = connect(agent)
    phone = Phone(wrong_ticket, phone_end)
    await phone.handshake()
    await phone.say(ScanRequest())
    return await task, phone_end, device_end


async def test_a_configurator_can_scan_and_then_join_a_network(agent, backend, ticket):
    phone_end, _, task = connect(agent)
    phone = Phone(ticket, phone_end)
    await phone.handshake()

    listing = await phone.ask(ScanRequest())
    assert isinstance(listing, NetworkList)
    assert [network.ssid for network in listing.networks] == [SSID, "Ward 3", "No DHCP", "Guest"]

    result = await phone.join(join())
    assert result == ConnectResult(True, ip="10.20.0.7")

    assert await task is Outcome.CONNECTED
    assert backend.connected_to == SSID
    assert agent.state is State.IDLE
    with pytest.raises(TransportClosed):
        await phone_end.receive()


async def test_an_open_network_can_be_joined_without_a_password(agent, backend, ticket):
    phone_end, _, task = connect(agent)
    phone = Phone(ticket, phone_end)
    await phone.handshake()
    assert (await phone.join(join("Guest", None))).connected
    assert await task is Outcome.CONNECTED
    assert backend.connected_to == "Guest"


async def test_joining_can_be_the_very_first_request(agent, backend, ticket):
    phone_end, _, task = connect(agent)
    phone = Phone(ticket, phone_end)
    await phone.handshake()
    assert (await phone.join(join())).connected
    assert await task is Outcome.CONNECTED


async def test_the_device_sends_nothing_encrypted_before_the_configurator_speaks(agent, ticket):
    phone_end, device_end, task = connect(agent)
    phone = Phone(ticket, phone_end)
    await phone.handshake()
    await asyncio.sleep(0.05)
    assert len(device_end.sent) == 1  # only the hello

    await phone.ask(ScanRequest())
    assert len(device_end.sent) == 2

    await phone_end.close()
    assert await task is Outcome.ABANDONED


async def test_a_wrong_password_is_reported_and_the_device_keeps_its_old_network(
    agent, backend, ticket
):
    phone_end, _, task = connect(agent)
    phone = Phone(ticket, phone_end)
    await phone.handshake()

    result = await phone.join(join(password="not the right one"))
    assert result == ConnectResult(False, Failure.WRONG_PASSWORD)
    assert backend.connected_to == "Old network"
    assert agent.state is State.READY

    # The technician types it again, in the same conversation.
    assert (await phone.join(join())).connected
    assert await task is Outcome.CONNECTED
    assert backend.connected_to == SSID


@pytest.mark.parametrize(
    ("request_", "failure"),
    [
        (join("Out of range", "whatever123"), Failure.NETWORK_NOT_FOUND),
        (join("No DHCP", "dhcp is broken"), Failure.NO_ADDRESS),
    ],
    ids=["not found", "no address"],
)
async def test_each_failure_reason_reaches_the_configurator(
    agent, backend, ticket, request_, failure
):
    phone_end, _, task = connect(agent)
    phone = Phone(ticket, phone_end)
    await phone.handshake()
    assert await phone.join(request_) == ConnectResult(False, failure)
    assert backend.connected_to == "Old network"
    await phone_end.close()
    assert await task is Outcome.FAILED


async def test_a_connection_that_takes_too_long_is_reported_as_a_timeout(identity, ticket, clock):
    backend = FakeBackend(NETWORKS, connected_to="Old network", connect_delay=5)
    agent = make_agent(identity, backend, clock, connect_timeout=0.05)
    phone_end, _, task = connect(agent)
    phone = Phone(ticket, phone_end)
    await phone.handshake()

    assert await phone.join(join()) == ConnectResult(False, Failure.TIMEOUT)
    assert backend.connected_to == "Old network"
    await phone_end.close()
    assert await task is Outcome.FAILED


async def test_the_state_shows_when_the_device_is_joining_a_network(identity, ticket, clock):
    hold = asyncio.Event()
    agent = make_agent(identity, FakeBackend(NETWORKS, hold=hold), clock)
    phone_end, _, task = connect(agent)
    phone = Phone(ticket, phone_end)

    assert agent.state is State.IDLE
    await phone.handshake()
    await phone.say(ScanRequest())
    await phone.hear()
    assert agent.state is State.READY

    await phone.say(join())
    assert await phone.hear() == ProvisionAccepted()
    assert agent.state is State.APPLYING  # the join is still going on

    hold.set()
    assert (await phone.hear()).connected
    assert await task is Outcome.CONNECTED
    assert agent.state is State.IDLE


async def test_a_wrong_setup_code_is_refused_and_nothing_encrypted_is_sent(agent, identity):
    outcome, phone_end, device_end = await attempt_with_wrong_code(agent, identity)

    assert outcome is Outcome.AUTH_FAILED
    assert len(device_end.sent) == 2  # the hello and the refusal: no reply made with the keys
    reason, _ = decode_reject(device_end.sent[1])
    assert reason is RejectReason.AUTH_FAILED
    assert agent.state is State.IDLE


async def test_garbage_in_place_of_the_first_message_counts_as_a_failed_attempt(agent, ticket):
    phone_end, device_end, task = connect(agent)
    phone = Phone(ticket, phone_end)
    await phone.handshake()
    await phone_end.send(b"\x00this is not a data message")
    assert await task is Outcome.AUTH_FAILED
    assert decode_reject(device_end.sent[1])[0] is RejectReason.AUTH_FAILED


async def test_five_wrong_codes_in_a_row_lock_the_device(agent, identity, ticket, clock):
    for _ in range(5):
        outcome, _, _ = await attempt_with_wrong_code(agent, identity)
        assert outcome is Outcome.AUTH_FAILED

    phone_end, device_end, task = connect(agent)
    reason, retry_after = decode_reject(await asyncio.wait_for(phone_end.receive(), 2))
    assert reason is RejectReason.LOCKED
    assert retry_after == 300
    assert await task is Outcome.LOCKED
    assert len(device_end.sent) == 1  # not even a hello

    # Even the right code has to wait.
    clock.advance(100)
    phone_end, _, task = connect(agent)
    assert decode_reject(await asyncio.wait_for(phone_end.receive(), 2)) == (
        RejectReason.LOCKED,
        200,
    )
    await task


async def test_the_lock_ends_after_its_time_and_the_right_code_gets_in(
    agent, identity, ticket, clock
):
    for _ in range(5):
        await attempt_with_wrong_code(agent, identity)
    clock.advance(301)

    phone_end, _, task = connect(agent)
    phone = Phone(ticket, phone_end)
    await phone.handshake()
    assert (await phone.join(join())).connected
    assert await task is Outcome.CONNECTED


async def test_a_correct_code_resets_the_count_of_wrong_ones(agent, identity, ticket):
    for _ in range(4):
        await attempt_with_wrong_code(agent, identity)

    phone_end, _, task = connect(agent)
    phone = Phone(ticket, phone_end)
    await phone.handshake()
    await phone.ask(ScanRequest())
    await phone_end.close()
    await task

    for _ in range(4):
        await attempt_with_wrong_code(agent, identity)
    assert not agent.lockout.is_locked()


async def test_a_configurator_that_goes_quiet_is_dropped_without_a_strike(
    identity, backend, clock, ticket
):
    agent = make_agent(identity, backend, clock, receive_timeout=0.05)

    # Silent before the key share.
    phone_end, device_end, task = connect(agent)
    await asyncio.wait_for(phone_end.receive(), 2)
    assert await task is Outcome.ABANDONED
    assert agent.state is State.IDLE

    # Silent after the handshake.
    phone_end, _, task = connect(agent)
    await Phone(ticket, phone_end).handshake()
    assert await task is Outcome.ABANDONED

    # Silence is not a guess: ten of them do not lock the device.
    for _ in range(10):
        phone_end, _, task = connect(agent)
        await asyncio.wait_for(phone_end.receive(), 2)
        assert await task is Outcome.ABANDONED
    assert not agent.lockout.is_locked()


async def test_a_bad_key_share_ends_the_conversation_without_a_strike(agent, identity):
    for _ in range(8):
        phone_end, _, task = connect(agent)
        await asyncio.wait_for(phone_end.receive(), 2)
        await phone_end.send(b"\x02" + bytes(32))  # a key share that forces the secret
        assert await task is Outcome.ABANDONED
    assert not agent.lockout.is_locked()


async def test_a_configurator_that_leaves_mid_conversation_frees_the_device(agent, ticket):
    phone_end, _, task = connect(agent)
    await phone_end.close()
    assert await task is Outcome.ABANDONED
    assert agent.state is State.IDLE

    phone_end, _, task = connect(agent)
    phone = Phone(ticket, phone_end)
    await phone.handshake()
    assert isinstance(await phone.ask(ScanRequest()), NetworkList)


async def test_a_second_configurator_is_told_the_device_is_busy(agent, ticket):
    first_end, _, first_task = connect(agent)
    first = Phone(ticket, first_end)
    await first.handshake()

    second_end, second_device_end, second_task = connect(agent)
    assert decode_reject(await asyncio.wait_for(second_end.receive(), 2))[0] is RejectReason.BUSY
    assert await second_task is Outcome.BUSY
    assert len(second_device_end.sent) == 1

    assert isinstance(await first.ask(ScanRequest()), NetworkList)  # unaffected
    await first_end.close()
    await first_task


async def test_a_properly_encrypted_but_meaningless_message_ends_the_conversation_quietly(
    agent, identity, ticket
):
    phone_end, _, task = connect(agent)
    phone = Phone(ticket, phone_end)
    await phone.handshake()
    await phone_end.send(phone.session.encrypt(b"this is not json"))
    assert await task is Outcome.ABANDONED
    assert not agent.lockout.is_locked()  # the sender knew the code, so it is not a guess


async def test_a_crashing_backend_does_not_take_the_agent_down_or_leak_the_password(
    identity, ticket, clock, caplog
):
    class Crashing(FakeBackend):
        async def connect(self, credentials):
            raise RuntimeError(f"cannot join with {credentials.password.reveal()}")

    agent = make_agent(identity, Crashing(NETWORKS), clock)
    phone_end, _, task = connect(agent)
    phone = Phone(ticket, phone_end)
    await phone.handshake()

    with caplog.at_level(logging.DEBUG):
        assert await phone.join(join()) == ConnectResult(False, Failure.OTHER)
        await phone_end.close()
        await task

    assert "RuntimeError" in caplog.text
    assert PASSWORD not in caplog.text


async def test_the_network_name_and_password_never_appear_on_the_wire(agent, ticket):
    phone_end, device_end, task = connect(agent)
    phone = Phone(ticket, phone_end)
    await phone.handshake()
    await phone.ask(ScanRequest())
    assert (await phone.join(join())).connected
    await task

    everything = b"".join(phone_end.sent + device_end.sent)
    assert PASSWORD.encode() not in everything
    assert SSID.encode() not in everything


async def test_the_device_remembers_the_last_attempt_and_can_be_asked(agent, ticket):
    phone_end, _, task = connect(agent)
    phone = Phone(ticket, phone_end)
    await phone.handshake()
    assert await phone.ask(StatusRequest()) == Status()  # nothing was tried yet

    await phone.join(join(password="not the right one"))
    failed = Status(SSID, ConnectResult(False, Failure.WRONG_PASSWORD))
    assert await phone.ask(StatusRequest()) == failed

    await phone.join(join())
    assert await task is Outcome.CONNECTED

    # A later conversation, for example after the phone has come back.
    phone_end, _, task = connect(agent)
    phone = Phone(ticket, phone_end)
    await phone.handshake()
    assert await phone.ask(StatusRequest()) == Status(SSID, ConnectResult(True, ip="10.20.0.7"))
    await phone_end.close()
    await task


async def test_when_joining_cuts_the_link_the_conversation_ends_after_a_failed_attempt(
    identity, ticket, clock
):
    backend = FakeBackend(NETWORKS, connected_to="Old network", drops_link=True)
    agent = make_agent(identity, backend, clock)
    phone_end, _, task = connect(agent)
    phone = Phone(ticket, phone_end)
    await phone.handshake()

    result = await phone.join(join(password="not the right one"))
    assert result == ConnectResult(False, Failure.WRONG_PASSWORD)
    assert await task is Outcome.FAILED  # nobody had to hang up first
    assert agent.state is State.IDLE

    # The phone comes back and finds the device free, with the result kept.
    phone_end, _, task = connect(agent)
    phone = Phone(ticket, phone_end)
    await phone.handshake()
    status = await phone.ask(StatusRequest())
    assert status == Status(SSID, ConnectResult(False, Failure.WRONG_PASSWORD))
    await phone_end.close()
    await task


async def test_a_join_that_works_is_still_a_success_when_it_cuts_the_link(identity, ticket, clock):
    backend = FakeBackend(NETWORKS, connected_to="Old network", drops_link=True)
    phone_end, _, task = connect(make_agent(identity, backend, clock))
    phone = Phone(ticket, phone_end)
    await phone.handshake()
    assert (await phone.join(join())).connected
    assert await task is Outcome.CONNECTED
