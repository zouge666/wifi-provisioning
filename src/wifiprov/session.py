"""An encrypted conversation between a configurator and a device."""

from __future__ import annotations

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from wifiprov.wire import MessageType

KEY_LENGTH = 32
_HEADER = bytes([MessageType.DATA])
_MAX_MESSAGES = 2**64


class SessionError(ValueError):
    """A message could not be sent, or did not pass authentication."""


def _nonce(counter: int) -> bytes:
    # ChaCha20-Poly1305 takes a 12-byte nonce: four zero bytes and the 8-byte counter.
    return bytes(4) + counter.to_bytes(8, "big")


class Session:
    """Encrypts and decrypts the messages of one conversation.

    Each direction has its own key and its own message counter. The counter is
    the nonce, so it is never sent: both sides count the messages they have
    handled. A message that is altered, replayed, reordered or sent by the wrong
    party no longer decrypts. The transport must deliver messages in order and
    without loss, which is what the layers below this one are for.
    """

    __slots__ = ("_receive", "_received", "_send", "_sent")

    def __init__(self, send_key: bytes, receive_key: bytes) -> None:
        if len(send_key) != KEY_LENGTH or len(receive_key) != KEY_LENGTH:
            raise ValueError(f"session keys are {KEY_LENGTH} bytes long")
        self._send = ChaCha20Poly1305(send_key)
        self._receive = ChaCha20Poly1305(receive_key)
        self._sent = 0
        self._received = 0

    def encrypt(self, plaintext: bytes) -> bytes:
        """Seal one message and return the bytes to put on the wire."""
        if self._sent >= _MAX_MESSAGES:
            raise SessionError("too many messages for one session")
        sealed = self._send.encrypt(_nonce(self._sent), plaintext, _HEADER)
        self._sent += 1
        return _HEADER + sealed

    def decrypt(self, message: bytes) -> bytes:
        """Open the next message the other side sent.

        Anything that does not authenticate raises SessionError and leaves the
        session as it was, so a bad message cannot throw the counters off.
        """
        if message[:1] != _HEADER:
            raise SessionError("not a data message")
        try:
            plaintext = self._receive.decrypt(_nonce(self._received), message[1:], _HEADER)
        except InvalidTag:
            raise SessionError("the message failed authentication") from None
        self._received += 1
        return plaintext
