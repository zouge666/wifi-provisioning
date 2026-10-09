"""A device's long-term identity: the key that proves which device is talking."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from wifiprov import b64url, crockford
from wifiprov.setup_code import SetupCode

PUBLIC_KEY_LENGTH = 32
FILE_VERSION = 1


class IdentityError(ValueError):
    """An identity file is malformed or has an unsupported version."""


def device_id_from_public_key(public_key: bytes) -> str:
    """A short, readable fingerprint of a public key, such as ``K7Q3ZXD2``.

    The ID is derived from the key instead of being chosen separately, so a
    sticker cannot carry an ID that belongs to a different key. It is only a
    label for people: authentication always uses the full key.
    """
    return crockford.encode(hashlib.sha256(public_key).digest()[:5])


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Check an Ed25519 signature; any failure returns False.

    A public key that is not 32 bytes long raises ValueError: that is a bug in
    the caller, not an attack.
    """
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except InvalidSignature:
        return False
    return True


class DeviceIdentity:
    """The secrets that belong to one device: a signing key and a setup code."""

    __slots__ = ("_private_key", "setup_code")

    def __init__(self, private_key: Ed25519PrivateKey, setup_code: SetupCode) -> None:
        self._private_key = private_key
        self.setup_code = setup_code

    @classmethod
    def generate(cls) -> DeviceIdentity:
        return cls(Ed25519PrivateKey.generate(), SetupCode.generate())

    @property
    def public_key(self) -> bytes:
        return self._private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    @property
    def device_id(self) -> str:
        return device_id_from_public_key(self.public_key)

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(message)

    def save(self, path: str | os.PathLike[str]) -> None:
        """Write the identity to a new file that only its owner can read.

        Refuses to overwrite an existing file: replacing an identity would
        orphan the sticker that was printed for it.
        """
        path = Path(path)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        seed = self._private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        document = {
            "version": FILE_VERSION,
            "private_key": b64url.encode(seed),
            "setup_code": self.setup_code.display,
        }
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(document, file, indent=2)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> DeviceIdentity:
        """Read an identity written by :meth:`save`.

        Like ssh does for private keys, it refuses a file that other users of
        the machine can read.
        """
        path = Path(path)
        _require_owner_only(path)
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            version = document["version"]
        except (KeyError, TypeError, ValueError) as exc:
            raise IdentityError(f"{path} is not a valid identity file") from exc
        if version != FILE_VERSION:
            raise IdentityError(f"{path} has unsupported version {version!r}")
        try:
            seed = b64url.decode(document["private_key"])
            private_key = Ed25519PrivateKey.from_private_bytes(seed)
            setup_code = SetupCode(document["setup_code"])
        except (KeyError, TypeError, ValueError) as exc:
            raise IdentityError(f"{path} is not a valid identity file") from exc
        return cls(private_key, setup_code)

    def __repr__(self) -> str:
        return f"DeviceIdentity(device_id={self.device_id!r})"


def _require_owner_only(path: Path) -> None:
    if os.name != "posix":
        return
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        raise PermissionError(
            f"{path} can be read by other users (mode {mode:04o}); "
            f"fix it with: chmod 600 {shlex.quote(str(path))}"
        )
