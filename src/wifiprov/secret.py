"""A value that must never show up in logs, tracebacks or reprs."""

from __future__ import annotations

import hmac


class Secret:
    """Wraps a secret string, such as a Wi-Fi password.

    Printing, logging or formatting a Secret shows asterisks. The real value is
    only available through :meth:`reveal`, so every place that uses it is easy
    to find and review.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("a secret is a string")
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Secret):
            return NotImplemented
        return hmac.compare_digest(self._value.encode(), other._value.encode())

    def __hash__(self) -> int:
        return hash(self._value)

    def __repr__(self) -> str:
        return "Secret(********)"
