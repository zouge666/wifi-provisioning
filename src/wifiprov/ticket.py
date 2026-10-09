"""The sticker payload: what a configurator needs to recognise and authorise a device.

A ticket is written as a URI, so it fits in a QR code and can also be read out
or typed by hand::

    wifiprov://v1/K7Q3ZXD2?pk=<public key, base64url>&code=7K3Q-9ZXD
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit

from wifiprov import b64url
from wifiprov.identity import PUBLIC_KEY_LENGTH, DeviceIdentity, device_id_from_public_key
from wifiprov.setup_code import SetupCode

SCHEME = "wifiprov"
VERSION = "v1"


class TicketError(ValueError):
    """The text is not a valid ticket."""


@dataclass(frozen=True, repr=False)
class Ticket:
    """The public key that identifies a device and the setup code that authorises a user."""

    public_key: bytes
    setup_code: SetupCode

    def __post_init__(self) -> None:
        if len(self.public_key) != PUBLIC_KEY_LENGTH:
            raise TicketError(f"a public key has {PUBLIC_KEY_LENGTH} bytes")

    @property
    def device_id(self) -> str:
        return device_id_from_public_key(self.public_key)

    @classmethod
    def from_identity(cls, identity: DeviceIdentity) -> Ticket:
        return cls(identity.public_key, identity.setup_code)

    def to_uri(self) -> str:
        return (
            f"{SCHEME}://{VERSION}/{self.device_id}"
            f"?pk={b64url.encode(self.public_key)}&code={self.setup_code.display}"
        )

    @classmethod
    def from_uri(cls, uri: str) -> Ticket:
        """Parse text scanned from a QR code or typed in.

        The reader is strict, because the text comes from outside: exactly the
        expected parts, canonical encodings, and a device ID that matches the key.
        Error messages never repeat the setup code.
        """
        try:
            parts = urlsplit(uri.strip())
        except ValueError:
            raise TicketError("not a valid ticket") from None
        if parts.scheme != SCHEME:
            raise TicketError(f"a ticket starts with {SCHEME}://")
        if parts.netloc != VERSION:
            raise TicketError("unsupported ticket version")
        if parts.fragment:
            raise TicketError("unexpected data in ticket")
        fields = _parse_query(parts.query)
        try:
            public_key = b64url.decode(fields["pk"])
            setup_code = SetupCode(fields["code"])
        except ValueError:
            raise TicketError("the public key or the setup code is malformed") from None
        ticket = cls(public_key, setup_code)
        if parts.path != f"/{ticket.device_id}":
            raise TicketError("the device ID does not match the public key")
        return ticket

    def __repr__(self) -> str:
        return f"Ticket(device_id={self.device_id!r})"


def _parse_query(query: str) -> dict[str, str]:
    try:
        pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        # Not chained on purpose: the library's message quotes the offending
        # field, and that field may be the setup code.
        raise TicketError("the ticket query is malformed") from None
    fields = dict(pairs)
    if len(fields) != len(pairs) or set(fields) != {"pk", "code"}:
        raise TicketError("a ticket has exactly one pk and one code")
    return fields
