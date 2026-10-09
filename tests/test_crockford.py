import base64
import random

import pytest

from wifiprov import crockford

_RFC4648_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_TO_CROCKFORD = str.maketrans(_RFC4648_ALPHABET, crockford.ALPHABET)


def test_alphabet_has_32_symbols_and_no_look_alikes():
    assert len(set(crockford.ALPHABET)) == 32
    assert not set("ILOU") & set(crockford.ALPHABET)


@pytest.mark.parametrize("length", range(21))
def test_encode_matches_standard_base32_with_the_crockford_alphabet(length):
    # The standard library is an independent reference for the bit packing.
    data = random.Random(length).randbytes(length)
    expected = base64.b32encode(data).decode("ascii").rstrip("=").translate(_TO_CROCKFORD)
    assert crockford.encode(data) == expected


def test_encode_extremes():
    assert crockford.encode(b"\x00" * 5) == "00000000"
    assert crockford.encode(b"\xff" * 5) == "ZZZZZZZZ"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("7K3Q-9ZXD", "7K3Q9ZXD"),
        ("7k3q-9zxd", "7K3Q9ZXD"),
        (" 7k3q 9zxd ", "7K3Q9ZXD"),
        ("o0il-1LOl", "00111101"),
    ],
)
def test_normalize_is_forgiving_about_case_separators_and_look_alikes(text, expected):
    assert crockford.normalize(text) == expected


@pytest.mark.parametrize("text", ["7K3U", "7K3!", "7K3Q\n", "7K3ß", "7K3١"])
def test_normalize_rejects_characters_outside_the_alphabet(text):
    with pytest.raises(ValueError):
        crockford.normalize(text)


def test_normalize_rejects_non_strings():
    with pytest.raises(ValueError):
        crockford.normalize(12345678)  # type: ignore[arg-type]
