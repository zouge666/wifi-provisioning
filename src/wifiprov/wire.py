"""Constants shared by the messages of the provisioning protocol."""

from __future__ import annotations

from enum import IntEnum

VERSION = 1


class MessageType(IntEnum):
    """The first byte of every message."""

    HELLO = 1  # device to configurator: a fresh public key, signed by the device
    KEYSHARE = 2  # configurator to device: the configurator's own fresh public key
    DATA = 3  # either direction: an encrypted message
