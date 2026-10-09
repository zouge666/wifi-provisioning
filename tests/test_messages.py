import json

import pytest

from wifiprov import messages
from wifiprov.messages import (
    MAX_MESSAGE_BYTES,
    MAX_NETWORKS,
    MessageError,
    NetworkList,
    ProvisionRequest,
    ScanRequest,
    decode_request,
    decode_response,
    encode,
)
from wifiprov.secret import Secret
from wifiprov.wifi import ConnectResult, Failure, Security, WifiCredentials, WifiNetwork

PROVISION = ProvisionRequest(WifiCredentials("Hospital", Secret("correct horse")))
NETWORKS = NetworkList(
    (WifiNetwork("Hospital", 80, Security.WPA_PSK), WifiNetwork("Guest", 40, Security.OPEN))
)


@pytest.mark.parametrize(
    "message",
    [
        ScanRequest(),
        PROVISION,
        ProvisionRequest(WifiCredentials("Open cafe")),
        ProvisionRequest(WifiCredentials("Café ☕", Secret("pass word 123"))),
    ],
)
def test_requests_round_trip(message):
    assert decode_request(encode(message)) == message


@pytest.mark.parametrize(
    "message",
    [
        NETWORKS,
        NetworkList(()),
        ConnectResult(True, ip="192.168.1.50"),
        ConnectResult(True),
        ConnectResult(True, ip="2001:db8::1"),
        *[ConnectResult(False, failure) for failure in Failure],
    ],
)
def test_responses_round_trip(message):
    assert decode_response(encode(message)) == message


def test_the_wire_format_is_compact_json_with_a_type():
    # These exact bytes are what another implementation has to produce and accept.
    assert encode(ScanRequest()) == b'{"type":"scan"}'
    assert encode(PROVISION) == b'{"type":"provision","ssid":"Hospital","password":"correct horse"}'
    assert (
        encode(ProvisionRequest(WifiCredentials("Cafe"))) == b'{"type":"provision","ssid":"Cafe"}'
    )
    assert encode(NETWORKS) == (
        b'{"type":"networks","networks":['
        b'{"ssid":"Hospital","signal":80,"security":"wpa-psk"},'
        b'{"ssid":"Guest","signal":40,"security":"open"}]}'
    )
    assert (
        encode(ConnectResult(True, ip="10.0.0.2"))
        == b'{"type":"result","connected":true,"ip":"10.0.0.2"}'
    )
    assert encode(ConnectResult(False, Failure.WRONG_PASSWORD)) == (
        b'{"type":"result","connected":false,"failure":"wrong_password"}'
    )


def test_a_full_list_of_networks_fits_in_one_message():
    networks = tuple(
        WifiNetwork(f"Network number {n:02d} " + "x" * 10, 50, Security.WPA_PSK)
        for n in range(MAX_NETWORKS)
    )
    assert len(encode(NetworkList(networks))) < MAX_MESSAGE_BYTES


def test_the_password_does_not_show_in_the_repr_of_a_message():
    assert "correct horse" not in repr(PROVISION)


def test_unknown_objects_cannot_be_encoded():
    with pytest.raises(TypeError):
        encode("scan")  # type: ignore[arg-type]


BAD_REQUESTS = {
    "not json": b"scan",
    "not utf-8": b"\xff\xfe\xfd",
    "a list": b'["scan"]',
    "no type": b'{"ssid":"x"}',
    "unknown type": b'{"type":"reboot"}',
    "a response, not a request": encode(NETWORKS),
    "extra field on scan": b'{"type":"scan","extra":1}',
    "repeated key": b'{"type":"scan","type":"scan"}',
    "not a number": b'{"type":"provision","ssid":"Hospital","password":NaN}',
    "no ssid": b'{"type":"provision"}',
    "ssid is not text": b'{"type":"provision","ssid":5}',
    "empty ssid": b'{"type":"provision","ssid":""}',
    "ssid too long": b'{"type":"provision","ssid":"' + b"x" * 33 + b'"}',
    "password is null": b'{"type":"provision","ssid":"Hospital","password":null}',
    "password is a number": b'{"type":"provision","ssid":"Hospital","password":12345678}',
    "password too short": b'{"type":"provision","ssid":"Hospital","password":"short"}',
    "extra field on provision": b'{"type":"provision","ssid":"Hospital","hidden":true}',
    "too large": b'{"type":"scan"}' + b" " * MAX_MESSAGE_BYTES,
    "nested far too deep": b"[" * 3000,
    "empty": b"",
}


@pytest.mark.parametrize("data", BAD_REQUESTS.values(), ids=list(BAD_REQUESTS))
def test_decode_request_rejects_bad_input(data):
    with pytest.raises(MessageError):
        decode_request(data)


def test_errors_never_repeat_the_password():
    data = b'{"type":"provision","ssid":"Hospital","password":"sevenpw"}'
    with pytest.raises(MessageError) as error:
        decode_request(data)
    assert "sevenpw" not in str(error.value)
    assert error.value.__suppress_context__


BAD_RESPONSES = {
    "not json": b"ok",
    "a request, not a response": b'{"type":"scan"}',
    "unknown type": b'{"type":"hello"}',
    "networks is not a list": b'{"type":"networks","networks":{}}',
    "network is not an object": b'{"type":"networks","networks":["Hospital"]}',
    "network with an extra field": b'{"type":"networks","networks":[{"ssid":"a","signal":1,"security":"open","x":1}]}',
    "network without a signal": b'{"type":"networks","networks":[{"ssid":"a","security":"open"}]}',
    "signal is a float": b'{"type":"networks","networks":[{"ssid":"a","signal":5.0,"security":"open"}]}',
    "signal is a boolean": b'{"type":"networks","networks":[{"ssid":"a","signal":true,"security":"open"}]}',
    "signal out of range": b'{"type":"networks","networks":[{"ssid":"a","signal":101,"security":"open"}]}',
    "unknown security": b'{"type":"networks","networks":[{"ssid":"a","signal":1,"security":"wep"}]}',
    "too many networks": json.dumps(
        {
            "type": "networks",
            "networks": [
                {"ssid": f"n{n}", "signal": 1, "security": "open"} for n in range(MAX_NETWORKS + 1)
            ],
        }
    ).encode(),
    "connected is not a boolean": b'{"type":"result","connected":"yes"}',
    "success that also names a failure": b'{"type":"result","connected":true,"failure":"timeout"}',
    "failed without a reason": b'{"type":"result","connected":false}',
    "unknown failure": b'{"type":"result","connected":false,"failure":"meteor"}',
    "failure with an address": b'{"type":"result","connected":false,"failure":"timeout","ip":"10.0.0.2"}',
    "address is not an address": b'{"type":"result","connected":true,"ip":"not an address"}',
    "address in another spelling": b'{"type":"result","connected":true,"ip":"::FFFF:1.2.3.4"}',
    "address is a number": b'{"type":"result","connected":true,"ip":3232235777}',
}


@pytest.mark.parametrize("data", BAD_RESPONSES.values(), ids=list(BAD_RESPONSES))
def test_decode_response_rejects_bad_input(data):
    with pytest.raises(MessageError):
        decode_response(data)


def test_module_exposes_the_documented_limits():
    assert messages.MAX_MESSAGE_BYTES == 4096
    assert messages.MAX_NETWORKS == 32
