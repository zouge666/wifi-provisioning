import random

import pytest

from wifiprov import b64url


@pytest.mark.parametrize("length", range(41))
def test_round_trip(length):
    data = random.Random(length).randbytes(length)
    text = b64url.encode(data)
    assert "=" not in text
    assert b64url.decode(text) == data


def test_uses_the_url_safe_alphabet():
    # Standard base64 would write "+/8=".
    assert b64url.encode(b"\xfb\xff") == "-_8"


@pytest.mark.parametrize(
    "text",
    [
        "QQ==",  # padding is not part of the format
        "+/8",  # the standard alphabet, not the URL-safe one
        "Q Q",  # whitespace
        "Q",  # one character cannot encode a whole byte
        "QR",  # non-zero trailing bits: not the canonical spelling of b"A"
        "ü",  # not ASCII
    ],
)
def test_decode_rejects_anything_but_the_canonical_spelling(text):
    with pytest.raises(ValueError):
        b64url.decode(text)


def test_decode_rejects_bytes_input():
    with pytest.raises(ValueError):
        b64url.decode(b"QQ")
