"""The conversation inside an encrypted session.

Every message is a small JSON object with a "type". The reader is strict, for the
same reason the sticker reader is: the bytes come from outside. Unknown or repeated
keys, wrong types, values out of range and oversized input are all refused with a
MessageError, and an error never repeats a password.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from typing import Any

from wifiprov.secret import Secret
from wifiprov.wifi import ConnectResult, Failure, Security, WifiCredentials, WifiNetwork

MAX_MESSAGE_BYTES = 4096
MAX_NETWORKS = 32


class MessageError(ValueError):
    """The bytes are not a valid message."""


@dataclass(frozen=True)
class ScanRequest:
    """Configurator to device: which Wi-Fi networks can you see?"""


@dataclass(frozen=True)
class ProvisionRequest:
    """Configurator to device: join this network."""

    credentials: WifiCredentials


@dataclass(frozen=True)
class NetworkList:
    """Device to configurator: the networks it can see, strongest first."""

    networks: tuple[WifiNetwork, ...]

    def __post_init__(self) -> None:
        if len(self.networks) > MAX_NETWORKS:
            raise ValueError(f"a network list has at most {MAX_NETWORKS} entries")


Request = ScanRequest | ProvisionRequest
Response = NetworkList | ConnectResult


def encode(message: Request | Response) -> bytes:
    """Turn a message into bytes. This is the only place a password is revealed."""
    document: dict[str, Any]
    if isinstance(message, ScanRequest):
        document = {"type": "scan"}
    elif isinstance(message, ProvisionRequest):
        document = {"type": "provision", "ssid": message.credentials.ssid}
        if message.credentials.password is not None:
            document["password"] = message.credentials.password.reveal()
    elif isinstance(message, NetworkList):
        document = {
            "type": "networks",
            "networks": [
                {"ssid": network.ssid, "signal": network.signal, "security": network.security.value}
                for network in message.networks
            ],
        }
    elif isinstance(message, ConnectResult):
        document = {"type": "result", "connected": message.connected}
        if message.failure is not None:
            document["failure"] = message.failure.value
        if message.ip is not None:
            document["ip"] = message.ip
    else:
        raise TypeError(f"cannot encode {type(message).__name__}")
    return json.dumps(document, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def decode_request(data: bytes) -> Request:
    """Read a message sent by a configurator. Used by the device."""
    document = _load(data)
    kind = document.get("type")
    if kind == "scan":
        _expect_keys(document, {"type"})
        return ScanRequest()
    if kind == "provision":
        _expect_keys(document, {"type", "ssid"}, optional={"password"})
        password = None
        if "password" in document:
            password = Secret(_text(document["password"]))
        try:
            return ProvisionRequest(WifiCredentials(_text(document["ssid"]), password))
        except ValueError:
            raise MessageError("the network name or password is not valid") from None
    raise MessageError("unknown request")


def decode_response(data: bytes) -> Response:
    """Read a message sent by a device. Used by the configurator."""
    document = _load(data)
    kind = document.get("type")
    if kind == "networks":
        _expect_keys(document, {"type", "networks"})
        entries = document["networks"]
        if not isinstance(entries, list):
            raise MessageError("networks must be a list")
        try:
            return NetworkList(tuple(_network(entry) for entry in entries))
        except ValueError:
            raise MessageError("the network list is not valid") from None
    if kind == "result":
        connected = document.get("connected")
        if type(connected) is not bool:
            raise MessageError("connected must be true or false")
        try:
            if connected:
                _expect_keys(document, {"type", "connected"}, optional={"ip"})
                return ConnectResult(True, ip=_ip(document.get("ip")))
            _expect_keys(document, {"type", "connected", "failure"})
            return ConnectResult(False, Failure(_text(document["failure"])))
        except ValueError:
            raise MessageError("the result is not valid") from None
    raise MessageError("unknown response")


def _load(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_MESSAGE_BYTES:
        raise MessageError("the message is too large")
    try:
        document = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_repeated_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise MessageError("not valid JSON") from None
    if not isinstance(document, dict):
        raise MessageError("a message is a JSON object")
    return document


def _reject_repeated_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # Python keeps the last of two equal keys, other readers keep the first. Refusing
    # both removes any chance of two programs reading the same bytes differently.
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("repeated key")
    return dict(pairs)


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not allowed")


def _expect_keys(
    document: dict[str, Any], required: set[str], optional: set[str] = frozenset()
) -> None:
    keys = set(document)
    if not required <= keys <= required | optional:
        raise MessageError("unexpected or missing fields")


def _text(value: Any) -> str:
    if not isinstance(value, str):
        raise MessageError("expected text")
    return value


def _network(entry: Any) -> WifiNetwork:
    if not isinstance(entry, dict):
        raise MessageError("a network is an object")
    _expect_keys(entry, {"ssid", "signal", "security"})
    return WifiNetwork(_text(entry["ssid"]), entry["signal"], Security(_text(entry["security"])))


def _ip(value: Any) -> str | None:
    if value is None:
        return None
    text = _text(value)
    if str(ipaddress.ip_address(text)) != text:  # also rejects other spellings of one address
        raise ValueError("not a canonical address")
    return text
