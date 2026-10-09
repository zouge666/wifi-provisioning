"""Constants shared by the messages of the provisioning protocol."""

from __future__ import annotations

from enum import IntEnum

VERSION = 1


class MessageType(IntEnum):
    """The first byte of every message."""

    HELLO = 1  # device to configurator: a fresh public key, signed by the device
    KEYSHARE = 2  # configurator to device: the configurator's own fresh public key
    DATA = 3  # either direction: an encrypted message
    REJECT = 4  # device to configurator, not encrypted: the device will not go on


class RejectReason(IntEnum):
    AUTH_FAILED = 1  # the first message did not authenticate: wrong setup code, or damaged
    LOCKED = 2  # too many failed attempts, try again later
    BUSY = 3  # the device is already talking to another configurator


class WireError(ValueError):
    """A message on the wire is malformed."""


REJECT_LENGTH = 4
_MAX_RETRY_AFTER = 0xFFFF


def encode_reject(reason: RejectReason, retry_after: int = 0) -> bytes:
    """A refusal: type, reason, and how many seconds to wait before trying again.

    It cannot be encrypted, because it is sent when there is no session. It only
    helps the person holding the phone; nothing depends on trusting it.
    """
    seconds = min(max(retry_after, 0), _MAX_RETRY_AFTER)
    return bytes([MessageType.REJECT, reason]) + seconds.to_bytes(2, "big")


def decode_reject(message: bytes) -> tuple[RejectReason, int]:
    if len(message) != REJECT_LENGTH or message[0] != MessageType.REJECT:
        raise WireError("not a reject message")
    try:
        reason = RejectReason(message[1])
    except ValueError:
        raise WireError("unknown reject reason") from None
    return reason, int.from_bytes(message[2:], "big")
