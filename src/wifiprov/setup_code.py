"""The short secret printed on a device's sticker next to its QR code."""

from __future__ import annotations

import hmac
import secrets

from wifiprov import crockford

LENGTH = 8  # 8 symbols of 5 bits each: 40 bits of entropy
_GROUP = 4


class SetupCodeError(ValueError):
    """The text is not a valid setup code."""


class SetupCode:
    """A setup code such as ``7K3Q-9ZXD``.

    Whoever can read the sticker may provision the device, so the code is a
    secret: it never appears in ``repr`` or ``str``. Use :attr:`display` when it
    has to be printed on purpose.

    Input is read forgivingly, because a technician may type it by hand: case,
    spaces, hyphens and look-alike letters (O for 0, I or L for 1) do not matter.
    """

    __slots__ = ("_symbols",)

    def __init__(self, text: str) -> None:
        try:
            symbols = crockford.normalize(text)
        except ValueError:
            raise SetupCodeError(
                "a setup code uses only the letters and digits on the sticker"
            ) from None
        if len(symbols) != LENGTH:
            raise SetupCodeError(f"a setup code has {LENGTH} characters, not {len(symbols)}")
        self._symbols = symbols

    @classmethod
    def generate(cls) -> SetupCode:
        return cls("".join(secrets.choice(crockford.ALPHABET) for _ in range(LENGTH)))

    @property
    def normalized(self) -> str:
        """The symbols without separators, e.g. ``7K3Q9ZXD``."""
        return self._symbols

    @property
    def display(self) -> str:
        """The form printed on the sticker, e.g. ``7K3Q-9ZXD``."""
        return f"{self._symbols[:_GROUP]}-{self._symbols[_GROUP:]}"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SetupCode):
            return NotImplemented
        return hmac.compare_digest(self._symbols, other._symbols)

    def __hash__(self) -> int:
        return hash(self._symbols)

    def __repr__(self) -> str:
        return "SetupCode(****-****)"
