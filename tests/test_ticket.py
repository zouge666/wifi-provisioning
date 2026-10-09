import traceback

import pytest

from wifiprov import b64url
from wifiprov.identity import DeviceIdentity, verify
from wifiprov.setup_code import SetupCode
from wifiprov.ticket import Ticket, TicketError


@pytest.fixture
def identity():
    return DeviceIdentity.generate()


@pytest.fixture
def ticket(identity):
    return Ticket.from_identity(identity)


def _pk(ticket):
    return b64url.encode(ticket.public_key)


def _code(ticket):
    return ticket.setup_code.display


def test_the_uri_has_the_documented_shape(identity, ticket):
    uri = ticket.to_uri()
    assert uri.startswith(f"wifiprov://v1/{identity.device_id}?pk=")
    assert uri.endswith(f"&code={identity.setup_code.display}")


def test_a_ticket_round_trips_through_its_uri(ticket):
    assert Ticket.from_uri(ticket.to_uri()) == ticket


def test_whitespace_around_scanned_text_is_ignored(ticket):
    assert Ticket.from_uri(f"  {ticket.to_uri()}\n") == ticket


def test_the_ticket_key_verifies_the_devices_signatures(identity, ticket):
    assert verify(ticket.public_key, b"hello", identity.sign(b"hello"))


def test_a_ticket_needs_a_32_byte_public_key():
    with pytest.raises(TicketError):
        Ticket(b"too short", SetupCode("7K3Q-9ZXD"))


BROKEN_URIS = {
    "wrong scheme": lambda t: t.to_uri().replace("wifiprov://", "https://", 1),
    "unsupported version": lambda t: t.to_uri().replace("wifiprov://v1/", "wifiprov://v2/"),
    "no query": lambda t: f"wifiprov://v1/{t.device_id}",
    "missing code": lambda t: f"wifiprov://v1/{t.device_id}?pk={_pk(t)}",
    "missing key": lambda t: f"wifiprov://v1/{t.device_id}?code={_code(t)}",
    "unknown parameter": lambda t: t.to_uri() + "&x=1",
    "repeated parameter": lambda t: t.to_uri() + f"&code={_code(t)}",
    "extra path segment": lambda t: t.to_uri().replace(f"/{t.device_id}?", f"/{t.device_id}/x?"),
    "fragment": lambda t: t.to_uri() + "#fragment",
    "key is not base64url": lambda t: f"wifiprov://v1/{t.device_id}?pk={'!' * 43}&code={_code(t)}",
    "key is too short": lambda t: (
        f"wifiprov://v1/{t.device_id}?pk={b64url.encode(t.public_key[:31])}&code={_code(t)}"
    ),
    "id does not match the key": lambda t: f"wifiprov://v1/ZZZZZZZZ?pk={_pk(t)}&code={_code(t)}",
    "malformed code": lambda t: f"wifiprov://v1/{t.device_id}?pk={_pk(t)}&code=7K3Q-9ZXU",
    "empty": lambda t: "",
    "not a ticket": lambda t: "hello",
}


@pytest.mark.parametrize("make", BROKEN_URIS.values(), ids=list(BROKEN_URIS))
def test_from_uri_rejects_malformed_tickets(ticket, make):
    with pytest.raises(TicketError):
        Ticket.from_uri(make(ticket))


def test_errors_never_repeat_the_setup_code(ticket):
    # A field without "=" makes the query parser quote it in its own message.
    uri = f"wifiprov://v1/{ticket.device_id}?pk={_pk(ticket)}&{ticket.setup_code.display}"
    with pytest.raises(TicketError) as error:
        Ticket.from_uri(uri)
    rendered = "".join(traceback.format_exception(error.value))
    assert ticket.setup_code.normalized not in rendered


def test_repr_shows_the_id_but_not_the_setup_code(ticket):
    assert ticket.device_id in repr(ticket)
    assert ticket.setup_code.normalized not in repr(ticket)
