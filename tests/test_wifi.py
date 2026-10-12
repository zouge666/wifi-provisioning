import pytest

from wifiprov.secret import Secret
from wifiprov.wifi import ConnectResult, Failure, Security, WifiCredentials, WifiNetwork


def test_a_normal_network_is_accepted():
    network = WifiNetwork("Hospital WiFi", 80, Security.WPA_PSK)
    assert network.ssid == "Hospital WiFi"


@pytest.mark.parametrize("ssid", ["", "x" * 33, "é" * 17, "\ud800"])
def test_network_names_must_be_1_to_32_bytes_of_valid_text(ssid):
    with pytest.raises(ValueError):
        WifiNetwork(ssid, 50, Security.OPEN)
    with pytest.raises(ValueError):
        WifiCredentials(ssid)


def test_a_32_byte_name_is_the_longest_allowed():
    assert WifiCredentials("x" * 32).ssid == "x" * 32
    assert WifiCredentials("é" * 16).ssid == "é" * 16  # 16 characters, 32 bytes


@pytest.mark.parametrize("signal", [-1, 101, 50.5, True, "50"])
def test_signal_strength_is_a_whole_number_from_0_to_100(signal):
    with pytest.raises(ValueError):
        WifiNetwork("net", signal, Security.OPEN)


@pytest.mark.parametrize(
    "password", ["12345678", "a" * 63, "pass word with spaces", "a" * 64, "0123456789abcdef" * 4]
)
def test_valid_passwords_are_accepted(password):
    assert WifiCredentials("net", Secret(password)).password == Secret(password)


@pytest.mark.parametrize(
    "password",
    [
        "short",
        "a" * 7,
        "a" * 65,
        "pässword1234",
        "tab\tinside1",
        "a" * 63 + "\n",
        "z" * 64 + "!",
        " starts with a space",
        "ends with a space ",
    ],
)
def test_invalid_passwords_are_rejected_without_repeating_them(password):
    with pytest.raises(ValueError) as error:
        WifiCredentials("net", Secret(password))
    assert password not in str(error.value)


def test_the_password_must_be_a_secret():
    with pytest.raises(ValueError):
        WifiCredentials("net", "plain-text-password")  # type: ignore[arg-type]


def test_an_open_network_has_no_password():
    assert WifiCredentials("cafe").password is None


def test_credentials_hide_the_password_in_repr():
    assert "hunter2222" not in repr(WifiCredentials("net", Secret("hunter2222")))


def test_a_connect_result_is_either_a_success_or_a_failure_with_a_reason():
    assert ConnectResult(True, ip="10.0.0.2").connected
    assert ConnectResult(False, Failure.WRONG_PASSWORD).failure is Failure.WRONG_PASSWORD
    with pytest.raises(ValueError):
        ConnectResult(False)
    with pytest.raises(ValueError):
        ConnectResult(True, Failure.TIMEOUT)
    with pytest.raises(ValueError):
        ConnectResult(False, Failure.TIMEOUT, ip="10.0.0.2")
