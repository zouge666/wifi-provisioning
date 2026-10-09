"""Crockford base32: an alphabet without the characters people mix up (no I, L, O, U)."""

from __future__ import annotations

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

# O looks like 0, and I and L look like 1. Crockford maps them to the digit.
_LOOK_ALIKES = str.maketrans({"O": "0", "I": "1", "L": "1"})
_SEPARATORS = str.maketrans("", "", " -")


def encode(data: bytes) -> str:
    """Encode bytes as Crockford base32, without padding."""
    bit_count = len(data) * 8
    padding = -bit_count % 5
    value = int.from_bytes(data, "big") << padding
    bit_count += padding
    return "".join(ALPHABET[(value >> shift) & 0x1F] for shift in range(bit_count - 5, -1, -5))


def normalize(text: str) -> str:
    """Return the canonical form of a Crockford string.

    Case is ignored, spaces and hyphens are dropped and look-alike letters are
    mapped to the digit they resemble. Anything else outside the alphabet is an
    error, including non-ASCII text that would otherwise change when upper-cased.
    """
    if not isinstance(text, str):
        raise ValueError("expected a string")
    if not text.isascii():
        raise ValueError("contains non-ASCII characters")
    canonical = text.upper().translate(_SEPARATORS).translate(_LOOK_ALIKES)
    if not set(canonical) <= set(ALPHABET):
        raise ValueError("contains characters outside the alphabet")
    return canonical
