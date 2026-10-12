import asyncio

import pytest

from wifiprov import messages
from wifiprov.configurator.client import (
    Configurator,
    DeviceRefused,
    DeviceUnreachable,
    NotTheExpectedDevice,
    ProtocolProblem,
)
from wifiprov.device.agent import DeviceAgent, Outcome
from wifiprov.device.fake import FakeBackend, FakeNetwork
from wifiprov.device.lockout import Lockout
from wifiprov.handshake import DeviceHandshake
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
from wifiprov.wifi import ConnectResult, Failure, Security, WifiCredentials, WifiNetwork
from wifiprov.wire import RejectReason

SSID = "Hospital WiFi"
PASSWORD = "correct horse battery"
NETWORKS = {
    SSID: FakeNetwork(PASSWORD, signal=80, ip="10.20.0.7"),
    "Guest": FakeNetwork(None, signal=40),
}


def join_request(password=PASSWORD):
    return WifiCredentials(SSID, Secret(password))


@pytest.fixture
def identity():
    return DeviceIdentity.generate()


@pytest.fixture
def ticket(identity):
    return Ticket.from_identity(identity)


@pytest.fixture
def backend():
    return FakeBackend(NETWORKS, connected_to="Old network")


@pytest.fixture
def agent(identity, backend, clock):
    return DeviceAgent(
        identity,
        backend,
        lockout=Lockout(max_failures=2, clock=clock),
        receive_timeout=1.0,
        connect_timeout=1.0,
    )


def start(agent):
    device_end, phone_end = memory_transport_pair()
    return phone_end, device_end, asyncio.create_task(agent.serve(device_end))


CLOSE = object()  # in a script: the link goes away here


class StubDevice:
    """A device that records what it is asked and answers from a script.

    An answer can be one message, raw bytes, or a list of those, which are sent one after
    the other. CLOSE in a list ends the conversation, like a device that left its network.
    """

    def __init__(self, identity, transport, answer):
        self.identity = identity
        self.transport = transport
        self.answer = answer
        self.requests = []

    async def run(self):
        handshake = DeviceHandshake(self.identity)
        await self.transport.send(handshake.hello())
        session = handshake.finish(await self.transport.receive())
        while True:
            try:
                data = await self.transport.receive()
            except TransportClosed:
                return
            request = messages.decode_request(session.decrypt(data))
            self.requests.append(request)
            reply = self.answer(request)
            for item in reply if isinstance(reply, list) else [reply]:
                if item is CLOSE:
                    await self.transport.close()
                    return
                if isinstance(item, bytes):  # raw bytes: a way to send something broken
                    await self.transport.send(item)
                else:
                    await self.transport.send(session.encrypt(messages.encode(item)))


def stub_answers(request):
    if isinstance(request, ScanRequest):
        return NetworkList((WifiNetwork(SSID, 80, Security.WPA_PSK),))
    if isinstance(request, StatusRequest):
        return Status(SSID, ConnectResult(True, ip="10.20.0.7"))
    return [ProvisionAccepted(), ConnectResult(True, ip="10.20.0.7")]


def start_stub(identity, answer=stub_answers):
    device_end, phone_end = memory_transport_pair()
    stub = StubDevice(identity, device_end, answer)
    return phone_end, stub, asyncio.create_task(stub.run())


async def test_scan_and_join_against_the_real_device(agent, backend, ticket):
    phone_end, _, task = start(agent)
    async with Configurator(ticket, phone_end, timeout=1.0) as phone:
        networks = await phone.scan()
        assert [network.ssid for network in networks] == [SSID, "Guest"]
        result = await phone.join(join_request())
    assert result == ConnectResult(True, ip="10.20.0.7")
    assert await task is Outcome.CONNECTED
    assert backend.connected_to == SSID


async def test_the_password_is_never_the_first_message(identity, ticket):
    phone_end, stub, task = start_stub(identity)
    async with Configurator(ticket, phone_end, timeout=1.0) as phone:
        await phone.join(join_request())
    await task
    assert [type(request) for request in stub.requests] == [ScanRequest, ProvisionRequest]


async def test_after_a_scan_joining_does_not_scan_again(identity, ticket):
    phone_end, stub, task = start_stub(identity)
    async with Configurator(ticket, phone_end, timeout=1.0) as phone:
        await phone.scan()
        await phone.join(join_request())
    await task
    assert [type(request) for request in stub.requests] == [ScanRequest, ProvisionRequest]


async def test_a_failed_join_can_be_tried_again(agent, backend, ticket):
    phone_end, _, task = start(agent)
    async with Configurator(ticket, phone_end, timeout=1.0) as phone:
        failed = await phone.join(join_request("not the right one"))
        assert failed == ConnectResult(False, Failure.WRONG_PASSWORD)
        assert backend.connected_to == "Old network"
        assert (await phone.join(join_request())).connected
    assert await task is Outcome.CONNECTED


async def test_a_wrong_setup_code_is_reported_as_a_refusal(agent, identity):
    wrong_ticket = Ticket(identity.public_key, SetupCode.generate())
    phone_end, _, task = start(agent)
    async with Configurator(wrong_ticket, phone_end, timeout=1.0) as phone:
        with pytest.raises(DeviceRefused) as refusal:
            await phone.scan()
    assert refusal.value.reason is RejectReason.AUTH_FAILED
    assert await task is Outcome.AUTH_FAILED


async def test_a_locked_device_says_how_long_to_wait(agent, identity, ticket):
    wrong_ticket = Ticket(identity.public_key, SetupCode.generate())
    for _ in range(2):  # the fixture locks after two wrong codes
        phone_end, _, task = start(agent)
        async with Configurator(wrong_ticket, phone_end, timeout=1.0) as phone:
            with pytest.raises(DeviceRefused):
                await phone.scan()
        await task

    phone_end, _, task = start(agent)
    with pytest.raises(DeviceRefused) as refusal:
        await Configurator(ticket, phone_end, timeout=1.0).open()
    assert refusal.value.reason is RejectReason.LOCKED
    assert refusal.value.retry_after == 300
    assert await task is Outcome.LOCKED


async def test_a_busy_device_is_reported_as_busy(agent, ticket):
    first_end, _, first_task = start(agent)
    async with Configurator(ticket, first_end, timeout=1.0):
        second_end, _, second_task = start(agent)
        with pytest.raises(DeviceRefused) as refusal:
            await Configurator(ticket, second_end, timeout=1.0).open()
        assert refusal.value.reason is RejectReason.BUSY
        assert await second_task is Outcome.BUSY
    await first_task


async def test_a_different_device_is_not_accepted(ticket):
    impostor = DeviceIdentity.generate()
    phone_end, _, task = start_stub(impostor)
    with pytest.raises(NotTheExpectedDevice, match="not the device on the sticker"):
        await Configurator(ticket, phone_end, timeout=1.0).open()
    task.cancel()


async def test_a_silent_device_is_reported_as_unreachable(ticket):
    phone_end, _ = memory_transport_pair()
    with pytest.raises(DeviceUnreachable, match="did not answer"):
        await Configurator(ticket, phone_end, timeout=0.05).open()


async def test_a_connection_that_breaks_is_reported_as_unreachable(ticket):
    phone_end, device_end = memory_transport_pair()
    await device_end.close()
    with pytest.raises(DeviceUnreachable, match="closed"):
        await Configurator(ticket, phone_end, timeout=1.0).open()


async def test_a_hello_that_makes_no_sense_is_a_protocol_problem(ticket):
    phone_end, device_end = memory_transport_pair()
    await device_end.send(b"\x01\x01 not a real hello")
    with pytest.raises(ProtocolProblem):
        await Configurator(ticket, phone_end, timeout=1.0).open()


async def test_a_refusal_that_cannot_be_read_is_a_protocol_problem(ticket):
    phone_end, device_end = memory_transport_pair()
    await device_end.send(b"\x04\x63\x00\x00")  # a refusal with an unknown reason
    with pytest.raises(ProtocolProblem):
        await Configurator(ticket, phone_end, timeout=1.0).open()


@pytest.mark.parametrize(
    "answer",
    [
        lambda request: b"\x03" + bytes(40),  # looks like data, does not authenticate
        lambda request: b"\x02" + bytes(32),  # not a message a device sends here
        lambda request: ConnectResult(True),  # a result where a network list belongs
    ],
    ids=["unauthenticated bytes", "wrong message type", "wrong kind of answer"],
)
async def test_an_answer_that_makes_no_sense_is_a_protocol_problem(identity, ticket, answer):
    phone_end, _, task = start_stub(identity, answer)
    async with Configurator(ticket, phone_end, timeout=1.0) as phone:
        with pytest.raises(ProtocolProblem):
            await phone.scan()
    await task


async def test_requests_need_an_open_session(ticket):
    phone_end, _ = memory_transport_pair()
    with pytest.raises(RuntimeError):
        await Configurator(ticket, phone_end).scan()


async def test_leaving_the_with_block_closes_the_connection(identity, ticket):
    phone_end, stub, task = start_stub(identity)
    async with Configurator(ticket, phone_end, timeout=1.0):
        pass
    await task
    with pytest.raises(TransportClosed):
        await phone_end.receive()


async def test_nothing_secret_goes_over_the_wire_in_the_clear(agent, ticket):
    phone_end, device_end, task = start(agent)
    async with Configurator(ticket, phone_end, timeout=1.0) as phone:
        await phone.scan()
        await phone.join(join_request())
    await task

    everything = b"".join(phone_end.sent + device_end.sent)
    for secret in (PASSWORD, SSID, ticket.setup_code.normalized, ticket.setup_code.display):
        assert secret.encode() not in everything


def accepted_then(*rest):
    def answer(request):
        if isinstance(request, ScanRequest):
            return NetworkList((WifiNetwork(SSID, 80, Security.WPA_PSK),))
        return [ProvisionAccepted(), *rest]

    return answer


async def test_a_device_that_leaves_before_it_can_say_how_it_went_gives_no_result(identity, ticket):
    phone_end, _, task = start_stub(identity, accepted_then(CLOSE))
    async with Configurator(ticket, phone_end, timeout=1.0) as phone:
        assert await phone.join(join_request()) is None
    await task


async def test_a_device_that_goes_quiet_after_accepting_gives_no_result(identity, ticket):
    phone_end, _, task = start_stub(identity, accepted_then())
    async with Configurator(ticket, phone_end, timeout=1.0, join_timeout=0.05) as phone:
        assert await phone.join(join_request()) is None
    task.cancel()


@pytest.mark.parametrize(
    "replies",
    [
        [ConnectResult(True, ip="10.20.0.7")],  # no "accepted" first
        [ProvisionAccepted(), NetworkList(())],  # something else instead of the result
    ],
    ids=["no accepted", "no result"],
)
async def test_a_join_answered_in_the_wrong_order_is_a_protocol_problem(identity, ticket, replies):
    def answer(request):
        if isinstance(request, ScanRequest):
            return NetworkList((WifiNetwork(SSID, 80, Security.WPA_PSK),))
        return replies

    phone_end, _, task = start_stub(identity, answer)
    async with Configurator(ticket, phone_end, timeout=1.0) as phone:
        with pytest.raises(ProtocolProblem):
            await phone.join(join_request())
    await task


async def test_status_reads_what_the_device_kept(identity, ticket):
    phone_end, stub, task = start_stub(identity)
    async with Configurator(ticket, phone_end, timeout=1.0) as phone:
        assert await phone.status() == Status(SSID, ConnectResult(True, ip="10.20.0.7"))
    await task
    assert stub.requests == [StatusRequest()]


async def test_status_answered_with_something_else_is_a_protocol_problem(identity, ticket):
    phone_end, _, task = start_stub(identity, lambda request: ConnectResult(True))
    async with Configurator(ticket, phone_end, timeout=1.0) as phone:
        with pytest.raises(ProtocolProblem):
            await phone.status()
    await task


async def test_a_new_session_reads_the_result_of_an_attempt_that_cut_the_link(
    identity, ticket, clock
):
    backend = FakeBackend(NETWORKS, connected_to="Old network", drops_link=True)
    agent = DeviceAgent(
        identity,
        backend,
        lockout=Lockout(clock=clock),
        receive_timeout=1.0,
        connect_timeout=1.0,
    )
    phone_end, _, task = start(agent)
    async with Configurator(ticket, phone_end, timeout=1.0) as phone:
        failed = await phone.join(join_request("not the right one"))
    assert failed == ConnectResult(False, Failure.WRONG_PASSWORD)
    assert await task is Outcome.FAILED

    phone_end, _, task = start(agent)
    async with Configurator(ticket, phone_end, timeout=1.0) as phone:
        assert await phone.status() == Status(SSID, ConnectResult(False, Failure.WRONG_PASSWORD))
    await task
