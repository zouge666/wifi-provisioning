"""The key agreement that turns a sticker into a private channel.

The device signs a fresh public key with its identity, so the configurator knows
it is talking to the device on the sticker. Both sides then agree on a shared
secret from two fresh keys and stir the setup code into it, so only someone who
has read the sticker can follow the conversation. No secret is ever sent.

    device                                   configurator
      |  HELLO: fresh public key, signed        |
      |---------------------------------------->|  checks the signature against the sticker
      |  KEYSHARE: its own fresh public key     |
      |<----------------------------------------|
      |  both derive the same session keys      |
"""

from __future__ import annotations

import hashlib
from typing import NamedTuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from wifiprov.identity import SIGNATURE_LENGTH, DeviceIdentity, verify
from wifiprov.session import KEY_LENGTH, Session
from wifiprov.setup_code import SetupCode
from wifiprov.ticket import Ticket
from wifiprov.wire import VERSION, MessageType

EPHEMERAL_KEY_LENGTH = 32
HELLO_LENGTH = 2 + EPHEMERAL_KEY_LENGTH + SIGNATURE_LENGTH
KEYSHARE_LENGTH = 1 + EPHEMERAL_KEY_LENGTH

# A label ties a signature or a set of keys to one purpose, so that neither can be
# lifted out of this protocol and reused somewhere else.
_HELLO_LABEL = b"wifiprov/v1/hello"
_SESSION_LABEL = b"wifiprov/v1/session"


class HandshakeError(ValueError):
    """A message is malformed, or the device is not the one on the sticker."""


class SessionKeys(NamedTuple):
    configurator_to_device: bytes
    device_to_configurator: bytes


def derive_session_keys(
    shared_secret: bytes,
    setup_code: SetupCode,
    device_public_key: bytes,
    hello: bytes,
    keyshare: bytes,
) -> SessionKeys:
    """Stir everything both sides know into two independent keys.

    The setup code goes in with the shared secret, so a configurator with the
    wrong code ends up with different keys. The hash of the whole conversation
    is the salt, so a change to any handshake message changes the keys too.
    """
    transcript = hashlib.sha256(device_public_key + hello + keyshare).digest()
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=2 * KEY_LENGTH,
        salt=transcript,
        info=_SESSION_LABEL,
    ).derive(shared_secret + setup_code.normalized.encode("ascii"))
    return SessionKeys(material[:KEY_LENGTH], material[KEY_LENGTH:])


class DeviceHandshake:
    """The device's half of the handshake. One instance serves one attempt."""

    def __init__(self, identity: DeviceIdentity) -> None:
        self._identity = identity
        self._ephemeral: X25519PrivateKey | None = X25519PrivateKey.generate()
        self._hello: bytes | None = None

    def hello(self) -> bytes:
        """The first message: a fresh public key, signed with the device identity."""
        if self._hello is not None:
            raise HandshakeError("hello has already been created")
        ephemeral_public = _public_bytes(self._ephemeral)
        signature = self._identity.sign(_HELLO_LABEL + ephemeral_public)
        self._hello = bytes([MessageType.HELLO, VERSION]) + ephemeral_public + signature
        return self._hello

    def finish(self, keyshare: bytes) -> Session:
        """Complete the handshake with the configurator's reply."""
        if self._hello is None:
            raise HandshakeError("hello must be sent before the handshake can finish")
        if self._ephemeral is None:
            raise HandshakeError("the handshake has already been used")
        # The fresh private key is dropped here, whatever happens next. It must not
        # outlive the handshake, and a failed attempt cannot be retried.
        ephemeral, self._ephemeral = self._ephemeral, None
        configurator_public = _parse_keyshare(keyshare)
        shared = _agree(ephemeral, configurator_public)
        keys = derive_session_keys(
            shared, self._identity.setup_code, self._identity.public_key, self._hello, keyshare
        )
        # The configurator must speak first: see Session for why.
        return Session(
            send_key=keys.device_to_configurator,
            receive_key=keys.configurator_to_device,
            peer_speaks_first=True,
        )


class ConfiguratorHandshake:
    """The configurator's half of the handshake. One instance serves one attempt."""

    def __init__(self, ticket: Ticket) -> None:
        self._ticket = ticket
        self._ephemeral: X25519PrivateKey | None = X25519PrivateKey.generate()

    def accept(self, hello: bytes) -> tuple[bytes, Session]:
        """Check the device's hello. Returns the reply to send and the session."""
        if self._ephemeral is None:
            raise HandshakeError("the handshake has already been used")
        ephemeral, self._ephemeral = self._ephemeral, None
        device_public, signature = _parse_hello(hello)
        if not verify(self._ticket.public_key, _HELLO_LABEL + device_public, signature):
            raise HandshakeError("this is not the device on the sticker")
        keyshare = bytes([MessageType.KEYSHARE]) + _public_bytes(ephemeral)
        shared = _agree(ephemeral, device_public)
        keys = derive_session_keys(
            shared, self._ticket.setup_code, self._ticket.public_key, hello, keyshare
        )
        return keyshare, Session(
            send_key=keys.configurator_to_device, receive_key=keys.device_to_configurator
        )


def _public_bytes(key: X25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _agree(private_key: X25519PrivateKey, peer_public: bytes) -> bytes:
    try:
        shared = private_key.exchange(X25519PublicKey.from_public_bytes(peer_public))
    except ValueError:
        raise HandshakeError("the key share is not usable") from None
    if not any(shared):
        # A handful of special public keys force the shared secret to zero, so an
        # attacker could pick it without knowing any private key.
        raise HandshakeError("the key share is not usable")
    return shared


def _parse_hello(message: bytes) -> tuple[bytes, bytes]:
    if len(message) != HELLO_LENGTH or message[0] != MessageType.HELLO:
        raise HandshakeError("not a hello message")
    if message[1] != VERSION:
        raise HandshakeError(f"unsupported protocol version {message[1]}")
    return message[2 : 2 + EPHEMERAL_KEY_LENGTH], message[2 + EPHEMERAL_KEY_LENGTH :]


def _parse_keyshare(message: bytes) -> bytes:
    if len(message) != KEYSHARE_LENGTH or message[0] != MessageType.KEYSHARE:
        raise HandshakeError("not a key share message")
    return message[1:]
