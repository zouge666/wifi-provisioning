import re

import pytest

from wifiprov.setup_code import SetupCode, SetupCodeError

STICKER_FORMAT = re.compile(r"[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}")


def test_generated_codes_use_the_sticker_format():
    for _ in range(200):
        assert STICKER_FORMAT.fullmatch(SetupCode.generate().display)


def test_generated_codes_do_not_repeat():
    codes = {SetupCode.generate().normalized for _ in range(1000)}
    assert len(codes) == 1000


def test_display_and_normalized_forms():
    code = SetupCode("7k3q9zxd")
    assert code.display == "7K3Q-9ZXD"
    assert code.normalized == "7K3Q9ZXD"


@pytest.mark.parametrize("text", ["7K3Q-9ZXD", "7k3q-9zxd", "7K3Q9ZXD", " 7k3q 9zxd "])
def test_equivalent_spellings_are_equal(text):
    assert SetupCode(text) == SetupCode("7K3Q-9ZXD")


def test_look_alike_letters_are_read_as_the_digits_they_resemble():
    assert SetupCode("OOOO-IIII") == SetupCode("0000-1111")
    assert SetupCode("0000-LLLL") == SetupCode("0000-1111")


def test_different_codes_are_not_equal():
    assert SetupCode("7K3Q-9ZXD") != SetupCode("7K3Q-9ZXE")
    assert SetupCode("7K3Q-9ZXD") != "7K3Q-9ZXD"


@pytest.mark.parametrize(
    "text",
    ["", "7K3Q-9ZX", "7K3Q-9ZXDA", "7K3Q-9ZXU", "7K3Q-9ZX!", "7K3Q-9ZXß", "7K3Q-9ZXD\n"],
)
def test_invalid_codes_are_rejected(text):
    with pytest.raises(SetupCodeError):
        SetupCode(text)


def test_the_code_never_appears_in_repr_str_or_error_messages():
    code = SetupCode("7K3Q-9ZXD")
    assert "7K3Q" not in repr(code)
    assert "7K3Q" not in str(code)
    with pytest.raises(SetupCodeError) as error:
        SetupCode("7K3Q-9ZXU")
    assert "7K3Q" not in str(error.value)
