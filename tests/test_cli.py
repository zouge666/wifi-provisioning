import asyncio
import getpass
import io
import os
import signal
import socket
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

from wifiprov.cli import DEMO_NETWORKS, _has_network, _serve_in_windows, main
from wifiprov.device.agent import DeviceAgent
from wifiprov.device.fake import FakeBackend
from wifiprov.device.lockout import Lockout
from wifiprov.device.networkmanager import NetworkManagerError, WifiStatus
from wifiprov.identity import DeviceIdentity
from wifiprov.secret import Secret
from wifiprov.setup_code import SetupCode
from wifiprov.ticket import Ticket
from wifiprov.transport.tcp import serve_tcp
from wifiprov.wifi import ConnectResult, Failure, Security, WifiNetwork

posix_only = pytest.mark.skipif(os.name != "posix", reason="relies on POSIX file modes")
PASSWORD = "correct horse battery"


class Terminal(io.StringIO):
    """Standard input that looks like a person at a keyboard."""

    def isatty(self):
        return True


async def run(*argv):
    # The program starts its own event loop, so it runs in a thread next to the test's device.
    return await asyncio.to_thread(main, list(argv))


@pytest.fixture
def identity():
    return DeviceIdentity.generate()


@pytest.fixture
def ticket_file(tmp_path, identity):
    path = tmp_path / "ticket.txt"
    path.write_text(Ticket.from_identity(identity).to_uri() + "\n")
    return path


@pytest.fixture
async def device(identity):
    backend = FakeBackend(DEMO_NETWORKS, connected_to="Old network")
    agent = DeviceAgent(identity, backend, receive_timeout=2.0, connect_timeout=2.0)
    server = await serve_tcp(agent.serve, "127.0.0.1", 0)
    yield SimpleNamespace(port=server.sockets[0].getsockname()[1], backend=backend)
    server.close()
    await server.wait_closed()


def configure_args(ticket_file, device, *extra):
    return [
        "configure",
        "--ticket-file",
        str(ticket_file),
        "--connect",
        f"127.0.0.1:{device.port}",
        *extra,
    ]


def assert_no_secrets(identity, *texts):
    for text in texts:
        assert PASSWORD not in text
        assert identity.setup_code.normalized not in text
        assert identity.setup_code.display not in text


# ------------------------------------------------------------------------------- init


@posix_only
def test_init_writes_a_private_identity_and_ticket(tmp_path, capsys):
    identity_path, ticket_path = (
        tmp_path / "state" / "identity.json",
        tmp_path / "state" / "ticket.txt",
    )

    assert main(["init", "--identity", str(identity_path), "--ticket-out", str(ticket_path)]) == 0

    out, err = capsys.readouterr()
    assert out == ""  # the ticket went to the file
    assert stat.S_IMODE(identity_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(ticket_path.stat().st_mode) == 0o600
    ticket = Ticket.from_uri(ticket_path.read_text())
    assert ticket.public_key == DeviceIdentity.load(identity_path).public_key
    assert ticket.device_id in err


def test_init_prints_the_ticket_when_no_file_is_asked_for(tmp_path, capsys):
    path = tmp_path / "identity.json"
    assert main(["init", "--identity", str(path)]) == 0
    out, _ = capsys.readouterr()
    assert Ticket.from_uri(out).public_key == DeviceIdentity.load(path).public_key


def test_init_never_overwrites_an_identity(tmp_path, capsys):
    path = tmp_path / "identity.json"
    assert main(["init", "--identity", str(path)]) == 0
    before = path.read_bytes()
    capsys.readouterr()

    assert main(["init", "--identity", str(path)]) == 2
    assert path.read_bytes() == before
    assert "never overwritten" in capsys.readouterr().err


# ----------------------------------------------------------------------------- device


def test_device_refuses_to_start_without_an_identity(tmp_path, capsys):
    assert main(["device", "--identity", str(tmp_path / "missing.json")]) == 2
    assert "Cannot start the device" in capsys.readouterr().err


@pytest.mark.parametrize(
    "extra",
    [
        ["--listen", "nonsense"],
        ["--listen", "host:99999"],
        ["--fake-network", "no-equals-sign"],
        ["--backend", "nm", "--fake-open-network", "Guest"],
        ["--access-point"],
        ["--access-point", "--backend", "nm"],
    ],
    ids=[
        "no port",
        "port out of range",
        "fake network without a password",
        "fake network with the real adapter",
        "access point without the real adapter",
        "access point without a window",
    ],
)
def test_device_refuses_to_start_with_bad_options(tmp_path, capsys, extra):
    path = tmp_path / "identity.json"
    main(["init", "--identity", str(path)])
    capsys.readouterr()
    assert main(["device", "--identity", str(path), *extra]) == 2
    assert "Cannot start the device" in capsys.readouterr().err


# -------------------------------------------------------------------------- configure


async def test_configure_joins_a_network(device, identity, ticket_file, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO(PASSWORD + "\n"))

    code = await run(
        *configure_args(ticket_file, device, "--ssid", "Hospital WiFi", "--password-stdin")
    )

    out, err = capsys.readouterr()
    assert code == 0
    assert "Connected to Hospital WiFi" in out
    assert "10.20.0.7" in out
    assert device.backend.connected_to == "Hospital WiFi"
    assert_no_secrets(identity, out, err)


async def test_a_wrong_wifi_password_is_explained_and_the_old_network_stays(
    device, identity, ticket_file, monkeypatch, capsys
):
    monkeypatch.setattr(sys, "stdin", io.StringIO("not the right one\n"))

    code = await run(
        *configure_args(ticket_file, device, "--ssid", "Hospital WiFi", "--password-stdin")
    )

    out, err = capsys.readouterr()
    assert code == 1
    assert "did not accept the password" in err
    assert device.backend.connected_to == "Old network"
    assert "not the right one" not in out + err


async def test_an_open_network_never_asks_for_a_password(device, ticket_file, monkeypatch, capsys):
    def no_prompt(prompt=""):
        raise AssertionError("an open network needs no password")

    monkeypatch.setattr(getpass, "getpass", no_prompt)
    code = await run(*configure_args(ticket_file, device, "--ssid", "Guest"))
    assert code == 0
    assert device.backend.connected_to == "Guest"


async def test_configure_can_ask_which_network_and_ask_again_after_a_typo(
    device, identity, ticket_file, monkeypatch, capsys
):
    monkeypatch.setattr(sys, "stdin", Terminal("1\n"))
    typed = iter(["not the right one", PASSWORD])
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(typed))

    code = await run(*configure_args(ticket_file, device))

    out, err = capsys.readouterr()
    assert code == 0
    assert "1. Hospital WiFi" in out
    assert "Try again." in err
    assert device.backend.connected_to == "Hospital WiFi"
    assert_no_secrets(identity, out, err)


async def test_configure_gives_up_after_three_wrong_passwords(
    device, ticket_file, monkeypatch, capsys
):
    monkeypatch.setattr(sys, "stdin", Terminal("1\n"))
    attempts = []

    def wrong(prompt=""):
        attempts.append(prompt)
        return "never the right one"

    monkeypatch.setattr(getpass, "getpass", wrong)
    assert await run(*configure_args(ticket_file, device)) == 1
    assert len(attempts) == 3


async def test_without_a_terminal_the_network_has_to_be_named(
    device, ticket_file, monkeypatch, capsys
):
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    assert await run(*configure_args(ticket_file, device)) == 2
    assert "--ssid" in capsys.readouterr().err


async def test_a_network_the_device_cannot_see_is_reported(
    device, ticket_file, monkeypatch, capsys
):
    monkeypatch.setattr(sys, "stdin", io.StringIO("whatever password\n"))
    code = await run(*configure_args(ticket_file, device, "--ssid", "Nowhere", "--password-stdin"))
    assert code == 1
    assert "cannot see that network" in capsys.readouterr().err


async def test_a_password_that_wifi_cannot_have_is_rejected_without_repeating_it(
    device, ticket_file, monkeypatch, capsys
):
    monkeypatch.setattr(sys, "stdin", io.StringIO("tiny\n"))
    code = await run(
        *configure_args(ticket_file, device, "--ssid", "Hospital WiFi", "--password-stdin")
    )
    out, err = capsys.readouterr()
    assert code == 2
    assert "8 to 63 characters" in err
    assert "tiny" not in out + err


async def test_a_wrong_setup_code_is_explained(device, identity, tmp_path, monkeypatch, capsys):
    wrong = tmp_path / "wrong.txt"
    wrong.write_text(Ticket(identity.public_key, SetupCode.generate()).to_uri())
    monkeypatch.setattr(sys, "stdin", io.StringIO(PASSWORD + "\n"))

    code = await run(*configure_args(wrong, device, "--ssid", "Hospital WiFi", "--password-stdin"))

    out, err = capsys.readouterr()
    assert code == 3
    assert "did not accept the setup code" in err
    assert device.backend.connected_to == "Old network"
    assert_no_secrets(identity, out, err)


async def test_a_locked_device_says_how_long_to_wait(
    identity, ticket_file, tmp_path, monkeypatch, capsys
):
    agent = DeviceAgent(
        identity, FakeBackend(DEMO_NETWORKS), lockout=Lockout(max_failures=1), receive_timeout=2.0
    )
    server = await serve_tcp(agent.serve, "127.0.0.1", 0)
    device = SimpleNamespace(port=server.sockets[0].getsockname()[1])
    wrong = tmp_path / "wrong.txt"
    wrong.write_text(Ticket(identity.public_key, SetupCode.generate()).to_uri())
    monkeypatch.setattr(sys, "stdin", io.StringIO(PASSWORD + "\n"))

    assert await run(*configure_args(wrong, device, "--ssid", "Guest")) == 3
    capsys.readouterr()
    assert await run(*configure_args(ticket_file, device, "--ssid", "Guest")) == 3
    err = capsys.readouterr().err
    assert "locked" in err
    assert "5 minute" in err

    server.close()
    await server.wait_closed()


async def test_a_different_device_is_called_out(device, tmp_path, capsys):
    other = tmp_path / "other.txt"
    other.write_text(Ticket.from_identity(DeviceIdentity.generate()).to_uri())
    code = await run(*configure_args(other, device, "--ssid", "Guest"))
    assert code == 3
    assert "not the device on the sticker" in capsys.readouterr().err


async def test_nothing_listening_is_reported(ticket_file, capsys):
    server = await serve_tcp(lambda transport: asyncio.sleep(0), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()
    code = await run(
        "configure",
        "--ticket-file",
        str(ticket_file),
        "--connect",
        f"127.0.0.1:{port}",
        "--ssid",
        "Guest",
    )
    assert code == 3
    assert "Could not reach a device" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("ticket_text", "extra"),
    [("hello", []), ("", []), ("wifiprov://v1/NOPE", []), (None, ["--connect", "nonsense"])],
    ids=["not a ticket", "empty file", "truncated ticket", "bad address"],
)
def test_bad_input_is_exit_code_2(tmp_path, identity, capsys, ticket_text, extra):
    path = tmp_path / "ticket.txt"
    path.write_text(Ticket.from_identity(identity).to_uri() if ticket_text is None else ticket_text)
    assert main(["configure", "--ticket-file", str(path), *extra]) == 2
    assert "Cannot start" in capsys.readouterr().err


def test_a_missing_ticket_file_is_exit_code_2(tmp_path, capsys):
    assert main(["configure", "--ticket-file", str(tmp_path / "missing.txt")]) == 2
    assert "Cannot start" in capsys.readouterr().err


def test_standard_input_cannot_carry_both_the_ticket_and_the_password(capsys):
    assert main(["configure", "--ticket-stdin", "--password-stdin"]) == 2
    assert "not both" in capsys.readouterr().err


@pytest.mark.parametrize("secret_option", ["--password", "--code", "--setup-code"])
def test_secrets_cannot_be_given_on_the_command_line(secret_option):
    with pytest.raises(SystemExit) as exit_:
        main(["configure", secret_option, "hunter22222"])
    assert exit_.value.code == 2


def test_the_program_can_be_run_as_a_module():
    result = subprocess.run(
        [sys.executable, "-m", "wifiprov", "--help"], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0
    for command in ("init", "device", "configure", "scan", "join"):
        assert command in result.stdout


# ------------------------------------------------------------------------------- scan


class FakeNetworkManager:
    def __init__(self, interface=None):
        self.interface = interface

    async def status(self):
        return WifiStatus("wlp2s0", 100, "Hospital", "10.20.0.7")

    async def scan(self):
        return [
            WifiNetwork("Hospital", 80, Security.WPA_PSK),
            WifiNetwork("Guest", 40, Security.OPEN),
        ]


def test_scan_lists_the_networks_the_machine_can_see(monkeypatch, capsys):
    monkeypatch.setattr("wifiprov.cli.NetworkManagerBackend", FakeNetworkManager)
    assert main(["scan"]) == 0
    out, _ = capsys.readouterr()
    assert "Adapter wlp2s0 is connected to Hospital (10.20.0.7)" in out
    assert "1. Hospital  (signal 80, wpa-psk)" in out
    assert "2. Guest  (signal 40, open)" in out


def test_scan_says_so_when_the_adapter_is_not_connected(monkeypatch, capsys):
    class NotConnected(FakeNetworkManager):
        async def status(self):
            return WifiStatus("wlp2s0", 30, None, None)

    monkeypatch.setattr("wifiprov.cli.NetworkManagerBackend", NotConnected)
    assert main(["scan"]) == 0
    assert "Adapter wlp2s0 is not connected" in capsys.readouterr().out


def test_scan_passes_the_adapter_name_on(monkeypatch):
    seen = []

    class Recording(FakeNetworkManager):
        def __init__(self, interface=None):
            seen.append(interface)

    monkeypatch.setattr("wifiprov.cli.NetworkManagerBackend", Recording)
    assert main(["scan", "--interface", "wlan7"]) == 0
    assert main(["scan"]) == 0
    assert seen == ["wlan7", None]


def test_scan_says_why_it_could_not_read_the_adapter(monkeypatch, capsys):
    class Broken(FakeNetworkManager):
        async def status(self):
            raise NetworkManagerError("NetworkManager sees no Wi-Fi adapter")

    monkeypatch.setattr("wifiprov.cli.NetworkManagerBackend", Broken)
    assert main(["scan"]) == 1
    assert "no Wi-Fi adapter" in capsys.readouterr().err


# ------------------------------------------------------------------------------- join


def fake_adapter(monkeypatch, result=None, error=None):
    """Put a pretend adapter in place of NetworkManager. Returns the credentials it was given."""
    seen = []

    class Adapter:
        def __init__(self, interface=None):
            self.interface = interface

        async def connect(self, credentials):
            seen.append(credentials)
            if error:
                raise error
            return result

    monkeypatch.setattr("wifiprov.cli.NetworkManagerBackend", Adapter)
    return seen


def test_join_reports_a_success(monkeypatch, capsys):
    seen = fake_adapter(monkeypatch, ConnectResult(True, ip="10.20.0.7"))
    monkeypatch.setattr(sys, "stdin", io.StringIO(PASSWORD + "\n"))
    assert main(["join", "--ssid", "Hospital", "--password-stdin"]) == 0
    assert "Connected to Hospital. The address is 10.20.0.7." in capsys.readouterr().out
    assert seen[0].ssid == "Hospital"
    assert seen[0].password == Secret(PASSWORD)


def test_join_says_why_it_could_not_join(monkeypatch, capsys):
    fake_adapter(monkeypatch, ConnectResult(False, Failure.WRONG_PASSWORD))
    monkeypatch.setattr(sys, "stdin", io.StringIO("not the password\n"))
    assert main(["join", "--ssid", "Hospital", "--password-stdin"]) == 1
    assert "did not accept the password" in capsys.readouterr().err


def test_join_with_an_empty_password_means_an_open_network(monkeypatch):
    seen = fake_adapter(monkeypatch, ConnectResult(True, ip="192.168.50.4"))
    monkeypatch.setattr(sys, "stdin", io.StringIO("\n"))
    assert main(["join", "--ssid", "Guest", "--password-stdin"]) == 0
    assert seen[0].password is None


def test_join_asks_for_the_password_at_a_hidden_prompt(monkeypatch):
    seen = fake_adapter(monkeypatch, ConnectResult(True, ip="10.20.0.7"))
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": PASSWORD)
    assert main(["join", "--ssid", "Hospital"]) == 0
    assert seen[0].password == Secret(PASSWORD)


def test_join_refuses_a_password_that_cannot_be_a_wifi_password(monkeypatch, capsys):
    fake_adapter(monkeypatch, ConnectResult(True, ip="10.20.0.7"))
    monkeypatch.setattr(sys, "stdin", io.StringIO("tiny\n"))
    assert main(["join", "--ssid", "Hospital", "--password-stdin"]) == 2
    assert "tiny" not in capsys.readouterr().err


def test_join_says_so_when_the_adapter_cannot_be_used(monkeypatch, capsys):
    fake_adapter(monkeypatch, error=NetworkManagerError("NetworkManager sees no Wi-Fi adapter"))
    monkeypatch.setattr(sys, "stdin", io.StringIO(PASSWORD + "\n"))
    assert main(["join", "--ssid", "Hospital", "--password-stdin"]) == 1
    assert "no Wi-Fi adapter" in capsys.readouterr().err


def test_the_wifi_password_cannot_be_given_on_the_command_line_of_join():
    with pytest.raises(SystemExit) as exit_:
        main(["join", "--ssid", "Hospital", "--password", PASSWORD])
    assert exit_.value.code == 2


# ------------------------------------------------------------------------ device window


@pytest.mark.parametrize(
    ("status", "online"),
    [
        (WifiStatus("wlp2s0", 100, "Hospital", "10.20.0.7"), True),
        (WifiStatus("wlp2s0", 100, "Hospital", None), False),
        (WifiStatus("wlp2s0", 30, None, None), False),
        (NetworkManagerError("NetworkManager sees no Wi-Fi adapter"), False),
    ],
    ids=["connected with an address", "connected without an address", "not connected", "error"],
)
async def test_the_device_is_online_only_with_a_connection_and_an_address(status, online):
    class Adapter:
        async def status(self):
            if isinstance(status, Exception):
                raise status
            return status

    assert await _has_network(Adapter()) is online


async def test_the_pretend_adapter_is_online_when_it_has_joined_a_network():
    assert not await _has_network(FakeBackend(DEMO_NETWORKS))
    assert await _has_network(FakeBackend(DEMO_NETWORKS, connected_to="Old network"))


async def listening(port):
    try:
        _, writer = await asyncio.open_connection("127.0.0.1", port)
    except OSError:
        return False
    writer.close()
    return True


async def wait_until(condition, *args):
    for _ in range(200):
        if await condition(*args):
            return
        await asyncio.sleep(0.02)
    raise AssertionError("it did not happen in time")


async def not_listening(port):
    return not await listening(port)


@posix_only
async def test_the_device_listens_only_while_the_window_is_open(
    identity, ticket_file, monkeypatch, capsys
):
    monkeypatch.setattr("wifiprov.cli.NETWORK_WAIT", 0)
    backend = FakeBackend(DEMO_NETWORKS)  # a device without a network
    agent = DeviceAgent(identity, backend, receive_timeout=2.0, connect_timeout=2.0)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    device = SimpleNamespace(port=port)
    serving = asyncio.create_task(
        _serve_in_windows(identity, agent, backend, "127.0.0.1", port, 60)
    )
    try:
        await wait_until(listening, port)  # no network, so the window opens
        monkeypatch.setattr(sys, "stdin", io.StringIO(PASSWORD + "\n"))
        args = configure_args(ticket_file, device, "--ssid", "Hospital WiFi", "--password-stdin")
        assert await run(*args) == 0
        await wait_until(not_listening, port)  # it has a network now, so the window closes

        os.kill(os.getpid(), signal.SIGUSR1)  # the stand-in for the button
        await wait_until(listening, port)
    finally:
        serving.cancel()
    await asyncio.gather(serving, return_exceptions=True)
    assert not await listening(port)


# --------------------------------------------------------------------------------- ap


class FakeAccessPoint:
    """Remembers what the command asked of the adapter."""

    def __init__(self, start_error=None):
        self.events = []
        self.start_error = start_error

    async def start_access_point(self, ssid):
        if self.start_error:
            raise self.start_error
        self.events.append(("start", ssid))
        return "10.42.0.1"

    async def stop_access_point(self):
        self.events.append(("stop",))


def fake_access_point(monkeypatch, **options):
    adapter = FakeAccessPoint(**options)
    monkeypatch.setattr("wifiprov.cli.NetworkManagerBackend", lambda interface=None: adapter)
    return adapter


def test_ap_starts_waits_and_stops(monkeypatch, capsys):
    adapter = fake_access_point(monkeypatch)
    assert main(["ap", "--ssid", "wifiprov-TEST", "--seconds", "0.01"]) == 0
    out, _ = capsys.readouterr()
    assert "Access point wifiprov-TEST is up. This machine is at 10.42.0.1." in out
    assert "The access point is stopped." in out
    assert adapter.events == [("start", "wifiprov-TEST"), ("stop",)]


def test_ap_that_cannot_start_says_why_and_stops_nothing(monkeypatch, capsys):
    adapter = fake_access_point(monkeypatch, start_error=NetworkManagerError("no dnsmasq"))
    assert main(["ap", "--ssid", "wifiprov-TEST", "--seconds", "0.01"]) == 1
    assert "Cannot start the access point: no dnsmasq" in capsys.readouterr().err
    assert adapter.events == []


def test_ap_with_a_bad_name_is_bad_input(monkeypatch, capsys):
    fake_access_point(monkeypatch, start_error=ValueError("a network name has 1 to 32 bytes"))
    assert main(["ap", "--ssid", "x" * 40, "--seconds", "0.01"]) == 2
    assert "1 to 32 bytes" in capsys.readouterr().err


# ------------------------------------------------------------------------------ status


async def test_status_says_nothing_was_tried_yet(device, ticket_file, capsys):
    code = await run(
        "status", "--ticket-file", str(ticket_file), "--connect", f"127.0.0.1:{device.port}"
    )
    assert code == 1
    assert "has not tried to join a network yet" in capsys.readouterr().out


async def test_status_says_how_the_last_attempt_went(
    device, identity, ticket_file, monkeypatch, capsys
):
    where = ("--ticket-file", str(ticket_file), "--connect", f"127.0.0.1:{device.port}")
    monkeypatch.setattr(sys, "stdin", io.StringIO("not the right one\n"))
    assert await run("configure", *where, "--ssid", "Hospital WiFi", "--password-stdin") == 1
    capsys.readouterr()

    assert await run("status", *where) == 1
    out, _ = capsys.readouterr()
    assert "could not join Hospital WiFi" in out
    assert "did not accept the password" in out

    monkeypatch.setattr(sys, "stdin", io.StringIO(PASSWORD + "\n"))
    assert await run("configure", *where, "--ssid", "Hospital WiFi", "--password-stdin") == 0
    capsys.readouterr()

    assert await run("status", *where) == 0
    out, err = capsys.readouterr()
    assert "joined Hospital WiFi. Its address is 10.20.0.7." in out
    assert_no_secrets(identity, out, err)


async def test_status_of_a_different_device_is_called_out(device, tmp_path, capsys):
    other = tmp_path / "other.txt"
    other.write_text(Ticket.from_identity(DeviceIdentity.generate()).to_uri())
    code = await run("status", "--ticket-file", str(other), "--connect", f"127.0.0.1:{device.port}")
    assert code == 3
    assert "not the device on the sticker" in capsys.readouterr().err


async def test_status_with_nothing_listening_is_reported(ticket_file, capsys):
    server = await serve_tcp(lambda transport: asyncio.sleep(0), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()
    code = await run("status", "--ticket-file", str(ticket_file), "--connect", f"127.0.0.1:{port}")
    assert code == 3
    assert "Could not reach a device" in capsys.readouterr().err


def test_status_with_a_bad_ticket_is_bad_input(tmp_path, capsys):
    bad = tmp_path / "ticket.txt"
    bad.write_text("hello")
    assert main(["status", "--ticket-file", str(bad)]) == 2
    assert "Cannot start" in capsys.readouterr().err


# ------------------------------------------------------- joining that cuts the link


async def test_a_device_that_cannot_say_how_it_went_gets_its_own_exit_code(
    device, ticket_file, monkeypatch, capsys
):
    class LinkLost:
        def __init__(self, *arguments, **options):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exception):
            return None

        async def scan(self):
            return [WifiNetwork("Hospital WiFi", 80, Security.WPA_PSK)]

        async def join(self, credentials):
            return None

    monkeypatch.setattr("wifiprov.cli.Configurator", LinkLost)
    monkeypatch.setattr(sys, "stdin", io.StringIO(PASSWORD + "\n"))

    code = await run(
        *configure_args(ticket_file, device, "--ssid", "Hospital WiFi", "--password-stdin")
    )

    out, err = capsys.readouterr()
    assert code == 4
    assert "left this network to join Hospital WiFi" in err
    assert "wifiprov status" in err
    assert PASSWORD not in out + err


# ------------------------------------------------------------ the access point and the window


class FakeAccessPointBackend:
    """Opens when asked, writes down what happens, and listens on this machine."""

    def __init__(self):
        self.events = []

    async def start(self):
        self.events.append("start")
        return "127.0.0.1"

    async def stop(self):
        self.events.append("stop")


@posix_only
async def test_the_access_point_opens_with_the_window_and_closes_with_it(
    identity, ticket_file, monkeypatch
):
    monkeypatch.setattr("wifiprov.cli.NETWORK_WAIT", 0)
    backend = FakeBackend(DEMO_NETWORKS)
    agent = DeviceAgent(identity, backend, receive_timeout=2.0, connect_timeout=2.0)
    access_point = FakeAccessPointBackend()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    serving = asyncio.create_task(
        _serve_in_windows(identity, agent, backend, "0.0.0.0", port, 60, access_point)
    )
    try:
        await wait_until(listening, port)
        assert access_point.events == ["start"]

        monkeypatch.setattr(sys, "stdin", io.StringIO(PASSWORD + "\n"))
        args = configure_args(
            ticket_file, SimpleNamespace(port=port), "--ssid", "Hospital WiFi", "--password-stdin"
        )
        assert await run(*args) == 0
        await wait_until(not_listening, port)
        assert access_point.events == ["start", "stop"]
    finally:
        serving.cancel()
    await asyncio.gather(serving, return_exceptions=True)


async def test_the_access_point_does_not_count_as_a_network_to_be_on():
    class OnTheAccessPoint:
        async def status(self):
            return WifiStatus("wlp2s0", 100, "wifiprov-ap", "10.42.0.1")

    assert not await _has_network(OnTheAccessPoint())
