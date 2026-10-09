import pytest

from wifiprov.wire import (
    REJECT_LENGTH,
    MessageType,
    RejectReason,
    WireError,
    decode_reject,
    encode_reject,
)


def test_message_types_are_one_byte_each():
    assert [int(t) for t in MessageType] == [1, 2, 3, 4]


def test_reject_format():
    # type, reason, then the seconds to wait as two bytes (300 = 0x012C)
    assert encode_reject(RejectReason.LOCKED, 300) == bytes([4, 2, 1, 44])
    assert len(encode_reject(RejectReason.BUSY)) == REJECT_LENGTH


@pytest.mark.parametrize("reason", list(RejectReason))
def test_reject_round_trips(reason):
    assert decode_reject(encode_reject(reason, 123)) == (reason, 123)


def test_the_wait_is_kept_inside_two_bytes():
    assert decode_reject(encode_reject(RejectReason.LOCKED, 70_000))[1] == 65_535
    assert decode_reject(encode_reject(RejectReason.LOCKED, -5))[1] == 0


@pytest.mark.parametrize(
    "message",
    [
        b"",
        b"\x04",
        b"\x04\x01\x00",
        b"\x04\x01\x00\x00\x00",
        b"\x03\x01\x00\x00",
        b"\x04\x09\x00\x00",
        b"\x04\x00\x00\x00",
    ],
)
def test_malformed_rejects_are_refused(message):
    with pytest.raises(WireError):
        decode_reject(message)
