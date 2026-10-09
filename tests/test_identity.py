import json
import os
import stat

import pytest

from wifiprov.identity import (
    PUBLIC_KEY_LENGTH,
    DeviceIdentity,
    IdentityError,
    device_id_from_public_key,
    verify,
)

posix_only = pytest.mark.skipif(os.name != "posix", reason="relies on POSIX file modes")


def test_a_new_identity_has_a_32_byte_key_and_an_8_character_id():
    identity = DeviceIdentity.generate()
    assert len(identity.public_key) == PUBLIC_KEY_LENGTH
    assert len(identity.device_id) == 8


def test_the_device_id_is_derived_from_the_public_key():
    identity = DeviceIdentity.generate()
    assert identity.device_id == device_id_from_public_key(identity.public_key)


def test_identities_are_independent():
    first, second = DeviceIdentity.generate(), DeviceIdentity.generate()
    assert first.public_key != second.public_key
    assert first.device_id != second.device_id
    assert first.setup_code != second.setup_code


def test_a_signature_verifies_with_the_public_key():
    identity = DeviceIdentity.generate()
    signature = identity.sign(b"hello")
    assert verify(identity.public_key, b"hello", signature)


def test_a_changed_message_does_not_verify():
    identity = DeviceIdentity.generate()
    signature = identity.sign(b"hello")
    assert not verify(identity.public_key, b"hellO", signature)


def test_a_changed_signature_does_not_verify():
    identity = DeviceIdentity.generate()
    signature = bytearray(identity.sign(b"hello"))
    signature[0] ^= 0x01
    assert not verify(identity.public_key, b"hello", bytes(signature))


def test_a_truncated_signature_does_not_verify():
    identity = DeviceIdentity.generate()
    assert not verify(identity.public_key, b"hello", identity.sign(b"hello")[:-1])


def test_another_devices_key_does_not_verify():
    identity, impostor = DeviceIdentity.generate(), DeviceIdentity.generate()
    signature = impostor.sign(b"hello")
    assert not verify(identity.public_key, b"hello", signature)


def test_a_public_key_of_the_wrong_length_is_a_caller_error():
    with pytest.raises(ValueError):
        verify(b"too short", b"hello", b"x" * 64)


def test_save_and_load_round_trip(tmp_path):
    original = DeviceIdentity.generate()
    path = tmp_path / "state" / "identity.json"
    original.save(path)

    loaded = DeviceIdentity.load(path)

    assert loaded.public_key == original.public_key
    assert loaded.setup_code == original.setup_code
    assert verify(original.public_key, b"hello", loaded.sign(b"hello"))


@posix_only
def test_saved_files_are_private_to_the_owner(tmp_path):
    path = tmp_path / "state" / "identity.json"
    DeviceIdentity.generate().save(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_save_never_overwrites_an_existing_identity(tmp_path):
    path = tmp_path / "identity.json"
    first = DeviceIdentity.generate()
    first.save(path)

    with pytest.raises(FileExistsError):
        DeviceIdentity.generate().save(path)

    assert DeviceIdentity.load(path).public_key == first.public_key


@posix_only
def test_load_refuses_a_file_other_users_can_read(tmp_path):
    path = tmp_path / "identity.json"
    DeviceIdentity.generate().save(path)
    path.chmod(0o644)
    with pytest.raises(PermissionError, match="chmod 600"):
        DeviceIdentity.load(path)


def test_load_reports_a_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        DeviceIdentity.load(tmp_path / "missing.json")


@pytest.mark.parametrize("content", ["", "not json", "[]", "null", '"text"'])
def test_load_rejects_files_that_are_not_identity_documents(tmp_path, content):
    path = tmp_path / "identity.json"
    path.write_text(content)
    path.chmod(0o600)
    with pytest.raises(IdentityError):
        DeviceIdentity.load(path)


@pytest.mark.parametrize(
    "edit",
    [
        lambda document: document.pop("version"),
        lambda document: document.update(version=2),
        lambda document: document.pop("private_key"),
        lambda document: document.update(private_key="AAAA"),
        lambda document: document.update(private_key=12345),
        lambda document: document.pop("setup_code"),
        lambda document: document.update(setup_code="7K3Q-9ZXU"),
        lambda document: document.update(setup_code=None),
    ],
    ids=[
        "missing version",
        "unsupported version",
        "missing key",
        "key of the wrong length",
        "key of the wrong type",
        "missing code",
        "malformed code",
        "code of the wrong type",
    ],
)
def test_load_rejects_malformed_documents(tmp_path, edit):
    path = tmp_path / "identity.json"
    DeviceIdentity.generate().save(path)
    document = json.loads(path.read_text())
    edit(document)
    path.write_text(json.dumps(document))

    with pytest.raises(IdentityError):
        DeviceIdentity.load(path)


def test_repr_shows_the_id_but_no_secrets():
    identity = DeviceIdentity.generate()
    text = repr(identity)
    assert identity.device_id in text
    assert identity.setup_code.normalized not in text
