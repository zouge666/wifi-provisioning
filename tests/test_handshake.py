import hashlib
import hmac

import pytest

from wifiprov.handshake import (
    HELLO_LENGTH,
    KEYSHARE_LENGTH,
    ConfiguratorHandshake,
    DeviceHandshake,
    HandshakeError,
    derive_session_keys,
)
from wifiprov.identity import DeviceIdentity
from wifiprov.session import SessionError
from wifiprov.setup_code import SetupCode
from wifiprov.ticket import Ticket


@pytest.fixture
def identity():
    return DeviceIdentity.generate()


@pytest.fixture
def ticket(identity):
    return Ticket.from_identity(identity)


def run_handshake(identity, ticket):
    """Run a full handshake; return what was sent and the two sessions."""
    device = DeviceHandshake(identity)
    hello = device.hello()
    keyshare, configurator_session = ConfiguratorHandshake(ticket).accept(hello)
    return hello, keyshare, device.finish(keyshare), configurator_session


def test_both_sides_end_up_with_a_working_channel(identity, ticket):
    _, _, device_session, configurator_session = run_handshake(identity, ticket)
    assert (
        device_session.decrypt(configurator_session.encrypt(b"wifi password")) == b"wifi password"
    )
    assert configurator_session.decrypt(device_session.encrypt(b"connected")) == b"connected"


def test_message_sizes_and_types(identity, ticket):
    hello, keyshare, _, _ = run_handshake(identity, ticket)
    assert len(hello) == HELLO_LENGTH == 98
    assert hello[:2] == b"\x01\x01"  # type HELLO, protocol version 1
    assert len(keyshare) == KEYSHARE_LENGTH == 33
    assert keyshare[0] == 2  # type KEYSHARE


def test_every_handshake_uses_fresh_keys(identity, ticket):
    first_hello, _, first_device, first_configurator = run_handshake(identity, ticket)
    second_hello, _, second_device, _ = run_handshake(identity, ticket)
    assert first_hello != second_hello
    with pytest.raises(SessionError):
        second_device.decrypt(first_configurator.encrypt(b"from another conversation"))


def test_a_device_that_is_not_on_the_sticker_is_refused(ticket):
    impostor = DeviceIdentity.generate()
    hello = DeviceHandshake(impostor).hello()
    with pytest.raises(HandshakeError, match="not the device on the sticker"):
        ConfiguratorHandshake(ticket).accept(hello)


def test_a_device_with_the_right_key_but_a_different_code_is_still_the_same_device(identity):
    # Authenticity comes from the signature; the code only decides who may talk.
    ticket_with_wrong_code = Ticket(identity.public_key, SetupCode.generate())
    hello = DeviceHandshake(identity).hello()
    ConfiguratorHandshake(ticket_with_wrong_code).accept(hello)


def test_changing_any_byte_of_hello_is_detected(identity, ticket):
    hello = DeviceHandshake(identity).hello()
    for index in range(len(hello)):
        damaged = bytearray(hello)
        damaged[index] ^= 0x01
        with pytest.raises(HandshakeError):
            ConfiguratorHandshake(ticket).accept(bytes(damaged))


@pytest.mark.parametrize("length", [0, 1, 97, 99, 200])
def test_hello_of_the_wrong_length_is_rejected(identity, ticket, length):
    hello = DeviceHandshake(identity).hello()
    with pytest.raises(HandshakeError):
        ConfiguratorHandshake(ticket).accept((hello + bytes(200))[:length])


def test_an_unsupported_protocol_version_is_named_in_the_error(identity, ticket):
    hello = bytearray(DeviceHandshake(identity).hello())
    hello[1] = 2
    with pytest.raises(HandshakeError, match="unsupported protocol version 2"):
        ConfiguratorHandshake(ticket).accept(bytes(hello))


def test_a_wrong_setup_code_leaves_the_two_sides_unable_to_talk(identity):
    wrong_ticket = Ticket(identity.public_key, SetupCode.generate())
    _, _, device_session, configurator_session = run_handshake(identity, wrong_ticket)
    with pytest.raises(SessionError):
        device_session.decrypt(configurator_session.encrypt(b"wifi password"))
    with pytest.raises(SessionError):
        configurator_session.decrypt(device_session.encrypt(b"connected"))


def test_a_tampered_key_share_leaves_the_two_sides_unable_to_talk(identity, ticket):
    device = DeviceHandshake(identity)
    keyshare, configurator_session = ConfiguratorHandshake(ticket).accept(device.hello())
    damaged = bytearray(keyshare)
    damaged[5] ^= 0x01
    device_session = device.finish(bytes(damaged))
    with pytest.raises(SessionError):
        device_session.decrypt(configurator_session.encrypt(b"wifi password"))


def test_a_replayed_hello_gives_nobody_a_usable_session(identity, ticket):
    recorded_hello = DeviceHandshake(identity).hello()
    # A later attempt: the configurator is shown the recorded hello, but the real
    # device is a new handshake with a new key.
    keyshare, configurator_session = ConfiguratorHandshake(ticket).accept(recorded_hello)
    live_device = DeviceHandshake(identity)
    live_device.hello()
    live_session = live_device.finish(keyshare)
    with pytest.raises(SessionError):
        live_session.decrypt(configurator_session.encrypt(b"wifi password"))


@pytest.mark.parametrize(
    "keyshare",
    [bytes([2]) + bytes(32), bytes([2]) + b"\x01" + bytes(31)],
    ids=["all zeros", "the point with x = 1"],
)
def test_key_shares_that_force_the_secret_are_refused(identity, keyshare):
    device = DeviceHandshake(identity)
    device.hello()
    with pytest.raises(HandshakeError):
        device.finish(keyshare)


@pytest.mark.parametrize("length", [0, 1, 32, 34])
def test_key_share_of_the_wrong_length_is_rejected(identity, length):
    device = DeviceHandshake(identity)
    device.hello()
    with pytest.raises(HandshakeError):
        device.finish((bytes([2]) + bytes(40))[:length])


def test_key_share_of_the_wrong_type_is_rejected(identity):
    device = DeviceHandshake(identity)
    device.hello()
    with pytest.raises(HandshakeError):
        device.finish(bytes([1]) + bytes(32))


def test_each_handshake_object_can_be_used_only_once(identity, ticket):
    device = DeviceHandshake(identity)
    with pytest.raises(HandshakeError):
        device.finish(bytes(KEYSHARE_LENGTH))  # before hello
    hello = device.hello()
    with pytest.raises(HandshakeError):
        device.hello()  # hello twice

    configurator = ConfiguratorHandshake(ticket)
    keyshare, _ = configurator.accept(hello)
    with pytest.raises(HandshakeError):
        configurator.accept(hello)

    device.finish(keyshare)
    with pytest.raises(HandshakeError):
        device.finish(keyshare)


def test_a_failed_attempt_cannot_be_retried(identity, ticket):
    device = DeviceHandshake(identity)
    hello = device.hello()
    keyshare, _ = ConfiguratorHandshake(ticket).accept(hello)
    with pytest.raises(HandshakeError):
        device.finish(bytes([2]) + bytes(32))
    with pytest.raises(HandshakeError):
        device.finish(keyshare)


def test_the_fresh_private_key_does_not_outlive_the_handshake(identity, ticket):
    device = DeviceHandshake(identity)
    configurator = ConfiguratorHandshake(ticket)
    keyshare, _ = configurator.accept(device.hello())
    device.finish(keyshare)
    assert device._ephemeral is None
    assert configurator._ephemeral is None


def _hkdf_sha256(key_material, salt, info, length):
    """HKDF from RFC 5869, written out so the tests do not depend on the library under test."""
    pseudo_random_key = hmac.new(salt, key_material, hashlib.sha256).digest()
    output, block = b"", b""
    for counter in range(1, -(-length // 32) + 1):
        block = hmac.new(
            pseudo_random_key, block + info + bytes([counter]), hashlib.sha256
        ).digest()
        output += block
    return output[:length]


SHARED = bytes(range(32))
CODE = SetupCode("7K3Q-9ZXD")
DEVICE_KEY = bytes(range(32, 64))
HELLO = bytes(range(98))
KEYSHARE = bytes(range(33))


def test_key_schedule_matches_the_documented_construction():
    transcript = hashlib.sha256(DEVICE_KEY + HELLO + KEYSHARE).digest()
    expected = _hkdf_sha256(SHARED + b"7K3Q9ZXD", transcript, b"wifiprov/v1/session", 64)

    keys = derive_session_keys(SHARED, CODE, DEVICE_KEY, HELLO, KEYSHARE)

    assert keys.configurator_to_device == expected[:32]
    assert keys.device_to_configurator == expected[32:]
    assert keys.configurator_to_device != keys.device_to_configurator


@pytest.mark.parametrize(
    "changed",
    [
        {"shared_secret": bytes(32)},
        {"setup_code": SetupCode("7K3Q-9ZXE")},
        {"device_public_key": bytes(32)},
        {"hello": bytes(98)},
        {"keyshare": bytes(33)},
    ],
    ids=["shared secret", "setup code", "device key", "hello", "key share"],
)
def test_every_ingredient_changes_the_keys(changed):
    inputs = {
        "shared_secret": SHARED,
        "setup_code": CODE,
        "device_public_key": DEVICE_KEY,
        "hello": HELLO,
        "keyshare": KEYSHARE,
    }
    baseline = derive_session_keys(**inputs)
    different = derive_session_keys(**{**inputs, **changed})
    assert different.configurator_to_device != baseline.configurator_to_device
    assert different.device_to_configurator != baseline.device_to_configurator
