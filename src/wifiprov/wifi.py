"""What the device and the configurator say about Wi-Fi networks."""

from __future__ import annotations

import string
from dataclasses import dataclass
from enum import Enum

from wifiprov.secret import Secret

SSID_MAX_BYTES = 32
PASSPHRASE_MIN = 8
PASSPHRASE_MAX = 63
RAW_KEY_LENGTH = 64


class Security(str, Enum):
    OPEN = "open"
    WPA_PSK = "wpa-psk"  # WPA2 or WPA3 Personal: one shared passphrase
    ENTERPRISE = "enterprise"  # 802.1X: needs a user name and certificates
    OTHER = "other"


class Failure(str, Enum):
    """Why joining a network did not work, in terms a technician can act on."""

    NETWORK_NOT_FOUND = "network_not_found"  # not in range, or the name is wrong
    WRONG_PASSWORD = "wrong_password"
    NO_ADDRESS = "no_address"  # joined, but the network gave no IP address
    TIMEOUT = "timeout"
    UNSUPPORTED = "unsupported"  # for example an enterprise network
    OTHER = "other"


_FAILURE_TEXT = {
    Failure.NETWORK_NOT_FOUND: (
        "The device cannot see that network. Is it in range, and is the name right?"
    ),
    Failure.WRONG_PASSWORD: "The network did not accept the password.",
    Failure.NO_ADDRESS: "The device joined the network but did not get an IP address.",
    Failure.TIMEOUT: "The network did not answer in time.",
    Failure.UNSUPPORTED: "This kind of network is not supported.",
    Failure.OTHER: "Something went wrong on the device.",
}


def describe_failure(failure: Failure) -> str:
    """A sentence a technician can act on."""
    return _FAILURE_TEXT[failure]


def _check_ssid(ssid: str) -> None:
    try:
        size = len(ssid.encode("utf-8"))
    except (AttributeError, UnicodeEncodeError):
        raise ValueError("the network name is not valid text") from None
    if not 1 <= size <= SSID_MAX_BYTES:
        raise ValueError(f"a network name has 1 to {SSID_MAX_BYTES} bytes")


def _check_passphrase(password: str) -> None:
    # Errors never repeat the password.
    if len(password) == RAW_KEY_LENGTH and all(c in string.hexdigits for c in password):
        return  # a raw 256-bit key written in hex
    if not PASSPHRASE_MIN <= len(password) <= PASSPHRASE_MAX:
        raise ValueError(f"a Wi-Fi password has {PASSPHRASE_MIN} to {PASSPHRASE_MAX} characters")
    if not all(0x20 <= ord(character) <= 0x7E for character in password):
        raise ValueError("a Wi-Fi password uses printable ASCII characters only")
    if password != password.strip(" "):
        # NetworkManager's editor drops spaces at both ends, so the device would join with
        # a different password than the one that was typed.
        raise ValueError("a Wi-Fi password cannot start or end with a space")


@dataclass(frozen=True)
class WifiNetwork:
    """A network the device can see."""

    ssid: str
    signal: int  # 0 (barely there) to 100 (right next to it)
    security: Security

    def __post_init__(self) -> None:
        _check_ssid(self.ssid)
        if type(self.signal) is not int or not 0 <= self.signal <= 100:
            raise ValueError("signal strength is a whole number from 0 to 100")
        if not isinstance(self.security, Security):
            raise ValueError("unknown security type")


@dataclass(frozen=True)
class WifiCredentials:
    """What it takes to join a network. No password means an open network."""

    ssid: str
    password: Secret | None = None

    def __post_init__(self) -> None:
        _check_ssid(self.ssid)
        if self.password is not None:
            if not isinstance(self.password, Secret):
                raise ValueError("the password must be wrapped in a Secret")
            _check_passphrase(self.password.reveal())


@dataclass(frozen=True)
class ConnectResult:
    """The outcome of trying to join a network."""

    connected: bool
    failure: Failure | None = None
    ip: str | None = None

    def __post_init__(self) -> None:
        if self.connected and self.failure is not None:
            raise ValueError("a successful connection has no failure")
        if not self.connected and self.failure is None:
            raise ValueError("a failed connection needs a reason")
        if not self.connected and self.ip is not None:
            raise ValueError("a failed connection has no address")
