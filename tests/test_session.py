import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from wifiprov.session import KEY_LENGTH, Session, SessionError


def make_pair():
    """Two sessions that share keys the way a configurator and a device would."""
    key_a, key_b = os.urandom(KEY_LENGTH), os.urandom(KEY_LENGTH)
    return Session(send_key=key_a, receive_key=key_b), Session(send_key=key_b, receive_key=key_a)


def test_messages_flow_in_both_directions():
    configurator, device = make_pair()
    assert device.decrypt(configurator.encrypt(b"scan")) == b"scan"
    assert configurator.decrypt(device.encrypt(b"networks")) == b"networks"


def test_many_messages_in_a_row():
    configurator, device = make_pair()
    for number in range(100):
        message = f"message {number}".encode()
        assert device.decrypt(configurator.encrypt(message)) == message


def test_an_empty_message_is_allowed():
    configurator, device = make_pair()
    assert device.decrypt(configurator.encrypt(b"")) == b""


def test_the_same_plaintext_never_produces_the_same_bytes_twice():
    configurator, _ = make_pair()
    assert configurator.encrypt(b"hello") != configurator.encrypt(b"hello")


def test_the_wire_format_is_a_type_byte_then_ciphertext_and_tag():
    configurator, _ = make_pair()
    assert len(configurator.encrypt(b"hello")) == 1 + len(b"hello") + 16
    assert configurator.encrypt(b"hello")[0] == 3


def test_the_wire_format_matches_the_documented_construction():
    # Nonce: 4 zero bytes and the message counter. Associated data: the type byte.
    send_key, receive_key = os.urandom(KEY_LENGTH), os.urandom(KEY_LENGTH)
    session = Session(send_key, receive_key)
    first, second = session.encrypt(b"one"), session.encrypt(b"two")

    cipher = ChaCha20Poly1305(send_key)
    assert cipher.decrypt(bytes(12), first[1:], b"\x03") == b"one"
    assert cipher.decrypt(bytes(4) + (1).to_bytes(8, "big"), second[1:], b"\x03") == b"two"


def test_a_replayed_message_is_rejected():
    configurator, device = make_pair()
    message = configurator.encrypt(b"wifi password")
    assert device.decrypt(message) == b"wifi password"
    with pytest.raises(SessionError):
        device.decrypt(message)


def test_a_reordered_message_is_rejected_and_does_not_break_the_session():
    configurator, device = make_pair()
    first, second = configurator.encrypt(b"first"), configurator.encrypt(b"second")
    with pytest.raises(SessionError):
        device.decrypt(second)
    assert device.decrypt(first) == b"first"
    assert device.decrypt(second) == b"second"


def test_a_dropped_message_is_noticed():
    configurator, device = make_pair()
    configurator.encrypt(b"lost on the way")
    with pytest.raises(SessionError):
        device.decrypt(configurator.encrypt(b"arrives"))


def test_changing_any_single_bit_is_detected():
    configurator, device = make_pair()
    message = configurator.encrypt(b"wifi password")
    for index in range(len(message)):
        for bit in range(8):
            damaged = bytearray(message)
            damaged[index] ^= 1 << bit
            with pytest.raises(SessionError):
                device.decrypt(bytes(damaged))
    assert device.decrypt(message) == b"wifi password"


def test_a_session_cannot_read_its_own_messages():
    configurator, _ = make_pair()
    with pytest.raises(SessionError):
        configurator.decrypt(configurator.encrypt(b"reflected"))


def test_another_conversation_cannot_read_the_message():
    configurator, _ = make_pair()
    _, stranger = make_pair()
    with pytest.raises(SessionError):
        stranger.decrypt(configurator.encrypt(b"secret"))


@pytest.mark.parametrize(
    "message",
    [b"", b"\x03", b"\x03" + bytes(15), b"\x02" + bytes(40), b"\x01" + bytes(40)],
    ids=["empty", "type only", "shorter than a tag", "key share type", "hello type"],
)
def test_malformed_messages_raise_session_error(message):
    _, device = make_pair()
    with pytest.raises(SessionError):
        device.decrypt(message)


@pytest.mark.parametrize("length", [0, 16, 31, 33])
def test_keys_must_be_32_bytes(length):
    with pytest.raises(ValueError):
        Session(bytes(length), bytes(KEY_LENGTH))
    with pytest.raises(ValueError):
        Session(bytes(KEY_LENGTH), bytes(length))


def test_a_session_that_waits_for_the_other_side_cannot_send_first():
    key_a, key_b = os.urandom(KEY_LENGTH), os.urandom(KEY_LENGTH)
    device = Session(key_a, key_b, peer_speaks_first=True)
    with pytest.raises(SessionError, match="first message"):
        device.encrypt(b"too early")


def test_it_may_send_once_a_message_from_the_other_side_has_authenticated():
    key_a, key_b = os.urandom(KEY_LENGTH), os.urandom(KEY_LENGTH)
    device = Session(key_a, key_b, peer_speaks_first=True)
    configurator = Session(key_b, key_a)
    device.decrypt(configurator.encrypt(b"hello"))
    assert configurator.decrypt(device.encrypt(b"welcome")) == b"welcome"


def test_a_message_that_fails_authentication_does_not_unlock_sending():
    key_a, key_b = os.urandom(KEY_LENGTH), os.urandom(KEY_LENGTH)
    device = Session(key_a, key_b, peer_speaks_first=True)
    with pytest.raises(SessionError):
        device.decrypt(b"\x03" + bytes(40))
    with pytest.raises(SessionError, match="first message"):
        device.encrypt(b"still too early")
