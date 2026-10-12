"""Writes protocol/vectors.json: inputs and the outputs that every implementation must give.

The Python code and the TypeScript code of the configurator are written separately. Both
are tested against this one file, so they cannot drift apart.

    uv run python protocol/generate_vectors.py           # write the file
    uv run python protocol/generate_vectors.py --check   # fail if the file is out of date

All keys here are made from a label with SHA-256, so anyone can recompute them. They are for
tests only and protect nothing.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from wifiprov import b64url, crockford, messages
from wifiprov.handshake import (
    ConfiguratorHandshake,
    DeviceHandshake,
    HandshakeError,
    WrongDevice,
    derive_session_keys,
)
from wifiprov.identity import DeviceIdentity, device_id_from_public_key
from wifiprov.messages import (
    NetworkList,
    ProvisionAccepted,
    ProvisionRequest,
    ScanRequest,
    Status,
    StatusRequest,
)
from wifiprov.secret import Secret
from wifiprov.session import Session, SessionError
from wifiprov.setup_code import SetupCode, SetupCodeError
from wifiprov.ticket import Ticket, TicketError
from wifiprov.wifi import ConnectResult, Failure, Security, WifiCredentials, WifiNetwork
from wifiprov.wire import MessageType, RejectReason, WireError, decode_reject, encode_reject

FILE = Path(__file__).with_name("vectors.json")
SETUP_CODE = "7K3Q-9ZXD"


def fixed(label: str) -> bytes:
    return hashlib.sha256(b"wifiprov test vector " + label.encode()).digest()


def _public(key: X25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def build() -> dict:
    """All the vectors. Every case is checked against the Python code while it is made."""
    identity = DeviceIdentity(
        Ed25519PrivateKey.from_private_bytes(fixed("device")), SetupCode(SETUP_CODE)
    )
    ticket = Ticket.from_identity(identity)
    return {
        "about": "Test vectors for the wifiprov protocol. Made by protocol/generate_vectors.py.",
        "b64url": _b64url(),
        "crockford": _crockford(),
        "setup_code": _setup_code(),
        "ticket": _ticket(ticket),
        "handshake": _handshake(identity, ticket),
        "messages": _messages(),
        "wire": _wire(),
    }


# ---------------------------------------------------------------- encodings


def _b64url() -> dict:
    samples = [b"", b"\x00", b"\xfb\xff", b"abc", bytes(range(32)), b"\xff" * 5]
    invalid = ["AA==", "A", "AB", "A B", "+/8", "é", "AAAA\n"]
    for text in invalid:
        try:
            b64url.decode(text)
        except ValueError:
            continue
        raise AssertionError(f"{text!r} should be rejected")
    return {
        "valid": [{"hex": data.hex(), "text": b64url.encode(data)} for data in samples],
        "invalid": invalid,
    }


def _crockford() -> dict:
    samples = [b"", b"\x00", b"\xff", bytes([1, 2, 3, 4, 5]), bytes(range(10))]
    normalize = ["7K3Q-9ZXD", "7k3q 9zxd", "O0Il1", "ABCDEFGHJKMNPQRSTVWXYZ", ""]
    invalid = ["U", "7K3Q9ZX!", "é", "7K3Q_9ZXD"]
    for text in invalid:
        try:
            crockford.normalize(text)
        except ValueError:
            continue
        raise AssertionError(f"{text!r} should be rejected")
    return {
        "encode": [{"hex": data.hex(), "text": crockford.encode(data)} for data in samples],
        "normalize": [{"input": text, "output": crockford.normalize(text)} for text in normalize],
        "invalid": invalid,
    }


def _setup_code() -> dict:
    valid = ["7K3Q-9ZXD", "7k3q9zxd", " 7K3Q 9ZXD ", "OOIL-1234"]
    invalid = ["7K3Q-9ZX", "7K3Q-9ZXDD", "7K3Q-9ZXU", "", "7K3Q-9ZX!"]
    for text in invalid:
        try:
            SetupCode(text)
        except SetupCodeError:
            continue
        raise AssertionError(f"{text!r} should be rejected")
    return {
        "valid": [
            {
                "input": text,
                "normalized": SetupCode(text).normalized,
                "display": SetupCode(text).display,
            }
            for text in valid
        ],
        "invalid": invalid,
    }


def _ticket(ticket: Ticket) -> dict:
    uri = ticket.to_uri()
    other = Ticket(
        DeviceIdentity(
            Ed25519PrivateKey.from_private_bytes(fixed("another")), SetupCode("0123-4567")
        ).public_key,
        SetupCode("0123-4567"),
    )
    pk = b64url.encode(ticket.public_key)
    device_id = ticket.device_id
    invalid = [
        uri.replace("wifiprov://", "http://"),
        uri.replace("/v1/", "/v2/").replace("://v1/", "://v2/"),
        f"wifiprov://v1/{device_id}?code={SETUP_CODE}",
        f"wifiprov://v1/{device_id}?pk={pk}",
        f"wifiprov://v1/{device_id}?pk={pk}&code={SETUP_CODE}&x=1",
        f"wifiprov://v1/{device_id}?pk={pk}&pk={pk}&code={SETUP_CODE}",
        f"wifiprov://v1/{other.device_id}?pk={pk}&code={SETUP_CODE}",
        uri + "#more",
        f"wifiprov://v1/{device_id}?pk={pk}A&code={SETUP_CODE}",
        f"wifiprov://v1/{device_id}?pk={pk[:-1]}&code={SETUP_CODE}",
        f"wifiprov://v1/{device_id}?pk={pk}&code=7K3Q-9ZX",
        "hello",
        "",
    ]
    for text in invalid:
        try:
            Ticket.from_uri(text)
        except TicketError:
            continue
        raise AssertionError(f"{text!r} should be rejected")
    valid = [uri, f"  {uri}\n", f"wifiprov://v1/{device_id}?pk={pk}&code=7k3q9zxd"]
    for text in valid:
        assert Ticket.from_uri(text) == ticket
    return {
        "device_id": device_id,
        "device_id_of_key": device_id_from_public_key(ticket.public_key),
        "public_key_hex": ticket.public_key.hex(),
        "setup_code": SETUP_CODE,
        "valid": valid,
        "invalid": invalid,
    }


# ---------------------------------------------------------------- handshake and session


def _handshake(identity: DeviceIdentity, ticket: Ticket) -> dict:
    device_eph = X25519PrivateKey.from_private_bytes(fixed("device ephemeral"))
    config_eph = X25519PrivateKey.from_private_bytes(fixed("configurator ephemeral"))
    device = DeviceHandshake(identity, ephemeral=device_eph)
    hello = device.hello()
    configurator = ConfiguratorHandshake(ticket, ephemeral=config_eph)
    keyshare, config_session = configurator.accept(hello)
    device.finish(keyshare)  # the device must be able to finish with the same bytes

    shared = config_eph.exchange(X25519PublicKey.from_public_bytes(_public(device_eph)))
    keys = derive_session_keys(shared, ticket.setup_code, ticket.public_key, hello, keyshare)

    return {
        "device_private_key_hex": fixed("device").hex(),
        "device_public_key_hex": identity.public_key.hex(),
        "setup_code": SETUP_CODE,
        "device_ephemeral_private_hex": fixed("device ephemeral").hex(),
        "configurator_ephemeral_private_hex": fixed("configurator ephemeral").hex(),
        "hello_hex": hello.hex(),
        "keyshare_hex": keyshare.hex(),
        "shared_secret_hex": shared.hex(),
        "configurator_to_device_key_hex": keys.configurator_to_device.hex(),
        "device_to_configurator_key_hex": keys.device_to_configurator.hex(),
        "wrong_code_keys": _wrong_code_keys(ticket, shared, hello, keyshare),
        "bad_hellos": _bad_hellos(identity, ticket, hello),
        "session": _session(keys),
    }


def _wrong_code_keys(ticket: Ticket, shared: bytes, hello: bytes, keyshare: bytes) -> dict:
    other = derive_session_keys(shared, SetupCode("0000-0000"), ticket.public_key, hello, keyshare)
    return {
        "setup_code": "0000-0000",
        "configurator_to_device_key_hex": other.configurator_to_device.hex(),
        "device_to_configurator_key_hex": other.device_to_configurator.hex(),
    }


def _bad_hellos(identity: DeviceIdentity, ticket: Ticket, hello: bytes) -> list[dict]:
    label = b"wifiprov/v1/hello"
    impostor = DeviceIdentity(
        Ed25519PrivateKey.from_private_bytes(fixed("another")), identity.setup_code
    )
    device_public = hello[2:34]
    zero_key = bytes(32)
    cases = [
        (
            "signed by another device",
            hello[:34] + impostor.sign(label + device_public),
            "wrong_device",
        ),
        ("one bit of the signature flipped", hello[:-1] + bytes([hello[-1] ^ 1]), "wrong_device"),
        (
            "the key is not the one that was signed",
            hello[:2] + bytes([hello[2] ^ 1]) + hello[3:],
            "wrong_device",
        ),
        ("unsupported version", hello[:1] + b"\x02" + hello[2:], "handshake_error"),
        ("not a hello", bytes([MessageType.KEYSHARE]) + hello[1:], "handshake_error"),
        ("too short", hello[:-1], "handshake_error"),
        ("too long", hello + b"\x00", "handshake_error"),
        ("empty", b"", "handshake_error"),
        (
            "signed key that forces a zero secret",
            hello[:2] + zero_key + identity.sign(label + zero_key),
            "handshake_error",
        ),
    ]
    result = []
    for name, data, expected in cases:
        try:
            ConfiguratorHandshake(
                ticket,
                ephemeral=X25519PrivateKey.from_private_bytes(fixed("configurator ephemeral")),
            ).accept(data)
        except WrongDevice:
            got = "wrong_device"
        except HandshakeError:
            got = "handshake_error"
        else:
            got = "accepted"
        assert got == expected, (name, got)
        result.append({"name": name, "hello_hex": data.hex(), "error": expected})
    return result


def _session(keys) -> dict:
    to_device = [
        messages.encode(ScanRequest()),
        messages.encode(ProvisionRequest(WifiCredentials("Hospital", Secret("correct horse")))),
        messages.encode(StatusRequest()),
    ]
    to_configurator = [
        messages.encode(NetworkList((WifiNetwork("Hospital", 80, Security.WPA_PSK),))),
        messages.encode(ProvisionAccepted(drops_link=True)),
        messages.encode(Status("Hospital", ConnectResult(False, Failure.WRONG_PASSWORD))),
    ]
    sender = Session(keys.configurator_to_device, keys.device_to_configurator)
    device = Session(keys.device_to_configurator, keys.configurator_to_device)
    from_configurator = [
        {"counter": n, "plaintext_hex": data.hex(), "wire_hex": sender.encrypt(data).hex()}
        for n, data in enumerate(to_device)
    ]
    from_device = [
        {"counter": n, "plaintext_hex": data.hex(), "wire_hex": device.encrypt(data).hex()}
        for n, data in enumerate(to_configurator)
    ]

    good = bytes.fromhex(from_device[0]["wire_hex"])
    second = bytes.fromhex(from_device[1]["wire_hex"])
    bad = {
        "a bit of the tag flipped": good[:-1] + bytes([good[-1] ^ 1]),
        "a bit of the text flipped": good[:2] + bytes([good[2] ^ 1]) + good[3:],
        "the header changed": bytes([MessageType.REJECT]) + good[1:],
        "cut short": good[:-1],
        "only the header": good[:1],
        "empty": b"",
        "the second message first": second,
    }
    for name, data in bad.items():
        receiver = Session(keys.configurator_to_device, keys.device_to_configurator)
        try:
            receiver.decrypt(data)
        except SessionError:
            continue
        raise AssertionError(f"{name} should be rejected")
    receiver = Session(keys.configurator_to_device, keys.device_to_configurator)
    with contextlib.suppress(SessionError):
        receiver.decrypt(bad["a bit of the tag flipped"])
    assert receiver.decrypt(good) == bytes.fromhex(from_device[0]["plaintext_hex"])
    return {
        "from_configurator": from_configurator,
        "from_device": from_device,
        "bad_messages": [{"name": name, "wire_hex": data.hex()} for name, data in bad.items()],
        "after_a_bad_message": {
            "bad_wire_hex": bad["a bit of the tag flipped"].hex(),
            "good_wire_hex": good.hex(),
            "plaintext_hex": from_device[0]["plaintext_hex"],
        },
    }


# ---------------------------------------------------------------- messages and wire


def _networks(entries) -> NetworkList:
    return NetworkList(tuple(WifiNetwork(*entry) for entry in entries))


def _messages() -> dict:
    requests = [
        ({"kind": "scan"}, ScanRequest()),
        ({"kind": "status"}, StatusRequest()),
        (
            {"kind": "provision", "ssid": "Hospital", "password": "correct horse"},
            ProvisionRequest(WifiCredentials("Hospital", Secret("correct horse"))),
        ),
        (
            {"kind": "provision", "ssid": "Open cafe"},
            ProvisionRequest(WifiCredentials("Open cafe")),
        ),
        (
            {"kind": "provision", "ssid": "Café ☕", "password": "pass word 123"},
            ProvisionRequest(WifiCredentials("Café ☕", Secret("pass word 123"))),
        ),
    ]
    networks = [("Hospital", 80, Security.WPA_PSK), ("Guest", 40, Security.OPEN)]
    network_entries = [
        {"ssid": ssid, "signal": signal, "security": security.value}
        for ssid, signal, security in networks
    ]
    responses = [
        ({"kind": "networks", "networks": network_entries}, _networks(networks)),
        ({"kind": "networks", "networks": []}, NetworkList(())),
        ({"kind": "accepted", "dropsLink": False}, ProvisionAccepted()),
        ({"kind": "accepted", "dropsLink": True}, ProvisionAccepted(drops_link=True)),
        (
            {"kind": "result", "connected": True, "ip": "192.168.1.50"},
            ConnectResult(True, ip="192.168.1.50"),
        ),
        ({"kind": "result", "connected": True}, ConnectResult(True)),
        *[
            ({"kind": "result", "connected": False, "failure": f.value}, ConnectResult(False, f))
            for f in Failure
        ],
        ({"kind": "last_attempt"}, Status()),
        (
            {
                "kind": "last_attempt",
                "ssid": "Hospital",
                "result": {"connected": True, "ip": "10.0.0.2"},
            },
            Status("Hospital", ConnectResult(True, ip="10.0.0.2")),
        ),
        (
            {
                "kind": "last_attempt",
                "ssid": "Café ☕",
                "result": {"connected": False, "failure": "wrong_password"},
            },
            Status("Café ☕", ConnectResult(False, Failure.WRONG_PASSWORD)),
        ),
    ]
    invalid = [
        "ok",
        "[]",
        '{"type":"scan"}',
        '{"type":"hello"}',
        '{"type":"networks","networks":{}}',
        '{"type":"networks","networks":["Hospital"]}',
        '{"type":"networks","networks":[{"ssid":"a","signal":1,"security":"open","x":1}]}',
        '{"type":"networks","networks":[{"ssid":"a","security":"open"}]}',
        '{"type":"networks","networks":[{"ssid":"a","signal":true,"security":"open"}]}',
        '{"type":"networks","networks":[{"ssid":"a","signal":101,"security":"open"}]}',
        '{"type":"networks","networks":[{"ssid":"a","signal":1,"security":"wep"}]}',
        '{"type":"accepted","ssid":"Hospital"}',
        '{"type":"accepted","drops_link":"yes"}',
        '{"type":"accepted","drops_link":1}',
        '{"type":"result","connected":"yes"}',
        '{"type":"result","connected":true,"failure":"timeout"}',
        '{"type":"result","connected":false}',
        '{"type":"result","connected":false,"failure":"meteor"}',
        '{"type":"result","connected":false,"failure":"timeout","ip":"10.0.0.2"}',
        '{"type":"result","connected":true,"ip":"not an address"}',
        '{"type":"result","connected":true,"ip":3232235777}',
        '{"type":"last_attempt","ssid":"Hospital"}',
        '{"type":"last_attempt","connected":true}',
        '{"type":"last_attempt","ssid":"","connected":true}',
        '{"type":"last_attempt","ssid":5,"connected":true}',
        '{"type":"last_attempt","ssid":"Hospital","connected":false}',
        '{"type":"last_attempt","ssid":"Hospital","connected":true,"x":1}',
    ]
    for text in invalid:
        try:
            messages.decode_response(text.encode())
        except messages.MessageError:
            continue
        raise AssertionError(f"{text!r} should be rejected")
    for description, message in responses:
        assert messages.decode_response(messages.encode(message)) == message, description
    return {
        "requests": [
            {"message": description, "json": messages.encode(message).decode()}
            for description, message in requests
        ],
        "responses": [
            {"message": description, "json": messages.encode(message).decode()}
            for description, message in responses
        ],
        "invalid_responses": invalid,
    }


def _wire() -> dict:
    cases = [
        (RejectReason.AUTH_FAILED, 0),
        (RejectReason.LOCKED, 300),
        (RejectReason.BUSY, 0),
        (RejectReason.LOCKED, 65535),
    ]
    invalid = ["", "04", "040100", "0301000000", "04630000", "0401000000"]
    for text in invalid:
        try:
            decode_reject(bytes.fromhex(text))
        except WireError:
            continue
        raise AssertionError(f"{text!r} should be rejected")
    return {
        "reject": [
            {
                "hex": encode_reject(reason, seconds).hex(),
                "reason": reason.name.lower(),
                "retry_after": seconds,
            }
            for reason, seconds in cases
        ],
        "invalid_reject": invalid,
    }


def render() -> str:
    return json.dumps(build(), indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str]) -> int:
    text = render()
    if argv == ["--check"]:
        if FILE.read_text(encoding="utf-8") != text:
            print(f"{FILE} is out of date. Run: uv run python protocol/generate_vectors.py")
            return 1
        return 0
    FILE.write_text(text, encoding="utf-8")
    print(f"wrote {FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
