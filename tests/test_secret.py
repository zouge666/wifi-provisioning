import pytest

from wifiprov.secret import Secret


def test_the_value_is_available_only_through_reveal():
    assert Secret("hunter22").reveal() == "hunter22"


def test_repr_str_and_format_hide_the_value():
    secret = Secret("hunter22")
    for text in (repr(secret), str(secret), f"{secret}", f"{secret!r}", format(secret)):
        assert "hunter22" not in text
        assert "***" in text


def test_a_secret_inside_another_object_stays_hidden():
    assert "hunter22" not in repr({"password": Secret("hunter22")})
    assert "hunter22" not in repr([Secret("hunter22")])


def test_equality_compares_the_values():
    assert Secret("hunter22") == Secret("hunter22")
    assert Secret("hunter22") != Secret("hunter23")
    assert Secret("hunter22") != "hunter22"


def test_equal_secrets_hash_the_same():
    assert hash(Secret("hunter22")) == hash(Secret("hunter22"))


def test_only_strings_can_be_wrapped():
    with pytest.raises(TypeError):
        Secret(12345678)  # type: ignore[arg-type]
