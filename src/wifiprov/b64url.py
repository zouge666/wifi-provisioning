"""Unpadded base64url: how binary data is written in text such as the sticker URI."""

from __future__ import annotations

import base64


def encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode(text: str) -> bytes:
    """Decode unpadded base64url, rejecting anything but the canonical spelling.

    The standard library silently skips stray characters and accepts several
    spellings of the same bytes. Text that comes from a camera or a keyboard
    deserves a stricter reader.
    """
    if not isinstance(text, str):
        raise ValueError("expected a string")
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError as exc:
        raise ValueError("not valid base64url") from exc
    if encode(data) != text:
        raise ValueError("not canonical unpadded base64url")
    return data
