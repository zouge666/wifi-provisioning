import asyncio
import logging
import os

import pytest

from wifiprov.device.networkmanager import (
    ADDRESS_POLL,
    DHCP_WAIT,
    PROFILE_PREFIX,
    NetworkManagerBackend,
    NetworkManagerError,
    WifiStatus,
    classify_failure,
    parse_networks,
    parse_security,
    parse_status,
    run_nmcli,
    split_terse,
)
from wifiprov.secret import Secret
from wifiprov.wifi import ConnectResult, Failure, Security, WifiCredentials, WifiNetwork

posix_only = pytest.mark.skipif(os.name != "posix", reason="uses a shell script as a fake nmcli")

SCAN_OUTPUT = r"""
Hospital WiFi:55:WPA2
Hospital WiFi:80:WPA2
Ward 3:62:WPA2 WPA3
Guest:40:
Cafe\:Free:45:WPA3
:70:WPA2
Corp:66:WPA2 802.1X
Old router:30:WEP
医院网络:92:WPA2
Signal is missing:xx:WPA2
not a network line
"""

CONNECTED = """\
GENERAL.STATE:100 (connected)
GENERAL.CONNECTION:Hospital WiFi
GENERAL.CON-UUID:uuid-hospital
IP4.ADDRESS[1]:10.20.0.7/24
IP4.ADDRESS[2]:10.20.0.8/24
"""


# ------------------------------------------------------------------------ the parsers


@pytest.mark.parametrize(
    ("line", "fields"),
    [
        ("a:b:c", ["a", "b", "c"]),
        (r"Cafe\:Free:45", ["Cafe:Free", "45"]),
        (r"back\\slash:1", [r"back\slash", "1"]),
        ("::", ["", "", ""]),
        ("", [""]),
        ("no colon", ["no colon"]),
        ("lonely backslash\\", ["lonely backslash"]),
    ],
)
def test_split_terse_follows_the_escaping_rules(line, fields):
    assert split_terse(line) == fields


@pytest.mark.parametrize(
    ("text", "security"),
    [
        ("", Security.OPEN),
        ("--", Security.OPEN),
        ("WPA2", Security.WPA_PSK),
        ("WPA1 WPA2", Security.WPA_PSK),
        ("WPA3", Security.WPA_PSK),
        ("WPA2 WPA3", Security.WPA_PSK),
        ("802.1X", Security.ENTERPRISE),
        ("WPA2 802.1X", Security.ENTERPRISE),
        ("WEP", Security.OTHER),
        ("OWE", Security.OTHER),
        ("something new", Security.OTHER),
    ],
)
def test_parse_security(text, security):
    assert parse_security(text) is security


def test_parse_networks_lists_the_strongest_first_and_keeps_one_per_name():
    networks = parse_networks(SCAN_OUTPUT)
    assert [(n.ssid, n.signal, n.security) for n in networks] == [
        ("医院网络", 92, Security.WPA_PSK),
        ("Hospital WiFi", 80, Security.WPA_PSK),  # the weaker 55 is dropped
        ("Corp", 66, Security.ENTERPRISE),
        ("Ward 3", 62, Security.WPA_PSK),
        ("Cafe:Free", 45, Security.WPA_PSK),
        ("Guest", 40, Security.OPEN),
        ("Old router", 30, Security.OTHER),
    ]


def test_parse_networks_leaves_out_names_that_are_too_long():
    assert parse_networks("x" * 33 + ":50:WPA2\nfine:40:WPA2\n") == [
        WifiNetwork("fine", 40, Security.WPA_PSK)
    ]


def test_parse_networks_of_nothing_is_an_empty_list():
    assert parse_networks("") == []


def test_parse_status_of_a_connected_adapter():
    status = parse_status("wlp2s0", CONNECTED)
    assert status == WifiStatus("wlp2s0", 100, "Hospital WiFi", "10.20.0.7", "uuid-hospital")
    assert status.connected


@pytest.mark.parametrize("empty", ["", "--"])
def test_parse_status_of_an_adapter_that_is_not_connected(empty):
    status = parse_status(
        "wlp2s0", f"GENERAL.STATE:30 (disconnected)\nGENERAL.CONNECTION:{empty}\n"
    )
    assert status == WifiStatus("wlp2s0", 30, None, None, None)
    assert not status.connected


def test_parse_status_reads_a_connection_name_with_a_colon():
    status = parse_status(
        "wlp2s0", "GENERAL.STATE:100 (connected)\nGENERAL.CONNECTION:Cafe\\:Free\n"
    )
    assert status.connection == "Cafe:Free"


@pytest.mark.parametrize("text", ["", "GENERAL.CONNECTION:x\n", "GENERAL.STATE:\n"])
def test_parse_status_without_a_state_is_an_error(text):
    with pytest.raises(NetworkManagerError, match="state"):
        parse_status("wlp2s0", text)


@pytest.mark.parametrize(
    ("message", "failure"),
    [
        (
            "Error: Connection activation failed: (7) Secrets were required, but not provided.",
            Failure.WRONG_PASSWORD,
        ),
        (
            "Warning: password for '802-11-wireless-security.psk' not given in 'passwd-file' "
            "and nmcli cannot ask without '--ask' option.\n"
            "Error: Connection activation failed: Secrets were required, but not provided",
            Failure.WRONG_PASSWORD,
        ),
        (
            "Error: Connection activation failed: The Wi-Fi network could not be found.",
            Failure.NETWORK_NOT_FOUND,
        ),
        ("Error: No network with SSID 'Hospital' found.", Failure.NETWORK_NOT_FOUND),
        (
            "Error: Connection activation failed: IP configuration could not be reserved "
            "(no available address, timeout, etc.).",
            Failure.NO_ADDRESS,
        ),
        ("Error: Timeout expired (30 seconds)", Failure.TIMEOUT),
        ("Error: not authorized", Failure.OTHER),
    ],
)
def test_classify_failure_goes_by_what_nmcli_says(message, failure):
    assert classify_failure(message) is failure


# ------------------------------------------------------------ the backend, looking only


def make_runner(*, devices="enp1s0:ethernet\nwlp2s0:wifi\nlo:loopback\n", networks="", status=""):
    """A stand-in for nmcli that answers by what is asked and remembers the questions."""
    calls = []

    async def run(args, timeout=None, input=None):
        calls.append(args)
        if "show" in args:
            return status
        if "list" in args:
            return networks
        return devices

    return run, calls


async def test_scan_asks_for_a_fresh_scan_on_the_wifi_adapter():
    run, calls = make_runner(networks="Hospital:80:WPA2\n")
    networks = await NetworkManagerBackend(run=run).scan()
    assert networks == [WifiNetwork("Hospital", 80, Security.WPA_PSK)]
    assert calls[0] == ["-t", "-f", "DEVICE,TYPE", "device"]
    assert calls[1][-4:] == ["ifname", "wlp2s0", "--rescan", "yes"]


async def test_the_adapter_is_found_by_its_type_not_by_its_name():
    run, calls = make_runner(devices="enp1s0:ethernet\nwlx00e04c680a1b:wifi\n")
    await NetworkManagerBackend(run=run).scan()
    assert "wlx00e04c680a1b" in calls[1]


async def test_a_named_adapter_is_used_without_a_search():
    run, calls = make_runner()
    await NetworkManagerBackend("wlan7", run=run).scan()
    assert len(calls) == 1
    assert "wlan7" in calls[0]


async def test_a_machine_without_a_wifi_adapter_is_an_error():
    run, _ = make_runner(devices="enp1s0:ethernet\nlo:loopback\n")
    with pytest.raises(NetworkManagerError, match="no Wi-Fi adapter"):
        await NetworkManagerBackend(run=run).scan()


async def test_status_asks_about_the_adapter():
    run, calls = make_runner(status=CONNECTED)
    status = await NetworkManagerBackend(run=run).status()
    assert status == WifiStatus("wlp2s0", 100, "Hospital WiFi", "10.20.0.7", "uuid-hospital")
    assert calls[1][-3:] == ["device", "show", "wlp2s0"]


async def test_a_failure_of_nmcli_is_passed_on():
    async def run(args, timeout=None, input=None):
        raise NetworkManagerError("NetworkManager is not running.")

    with pytest.raises(NetworkManagerError, match="not running"):
        await NetworkManagerBackend(run=run).scan()


# ------------------------------------------------------------ the backend, joining


PASSWORD = "correct horse battery"
OLD = ("Old network", "uuid-old")


class FakeNmcli:
    """A pretend NetworkManager that understands the few nmcli commands the backend uses.

    Like the real one, it drops the old connection as soon as a new one is started, and it
    drops a connection that is deleted while it is in use. It does not bring the old one
    back by itself, so a test can only pass if the backend does. A connection that holds a
    wrong password fails at once, because the real one does not need to ask nmcli for it.
    """

    def __init__(
        self, *, active=OLD, failure=None, add_failure=None, edit_fails=False, delay=0.0, late=0
    ):
        self.networks = {
            "Hospital": (80, "WPA2"),
            "Guest": (40, ""),
            "Corp": (60, "WPA2 802.1X"),
            "Old router": (30, "WEP"),
        }
        self.active = active  # (name, uuid), or None
        self.profiles = {}  # the connections the backend made: name -> what they hold
        self.failure = failure  # what starting a connection fails with, if anything
        self.add_failure = add_failure  # what making a connection fails with, if anything
        self.edit_fails = edit_fails  # the editor cannot save the password
        self.modify_failure = None  # what changing a connection fails with, if anything
        self.delay = delay
        self.late = late  # how many looks at the new connection show no address yet
        self.calls = []
        self.inputs = []  # (arguments, standard input) of every call that got some input

    async def __call__(self, args, timeout=None, input=None):
        self.calls.append(list(args))
        if input is not None:
            self.inputs.append((list(args), input))
        args = list(args)
        if args[0] == "--wait":
            args = args[2:]
        if args[0] == "-t":
            return self._read(args)
        if args[:2] == ["connection", "add"]:
            if self.add_failure:
                raise NetworkManagerError(self.add_failure)
            name = args[args.index("con-name") + 1]
            self.profiles[name] = {
                "secured": "wifi-sec.key-mgmt" in args,
                "psk": None,
                "autoconnect": args[args.index("connection.autoconnect") + 1],
            }
            return f"Connection '{name}' successfully added.\n"
        if args[:2] == ["connection", "edit"]:
            return self._edit(args[3], input)
        if args[:2] == ["connection", "modify"]:
            if self.modify_failure:
                raise NetworkManagerError(self.modify_failure)
            self.profiles[args[3]]["autoconnect"] = args[args.index("connection.autoconnect") + 1]
            return ""
        if args[:2] == ["connection", "delete"]:
            name = args[3]
            self.profiles.pop(name, None)
            if self.active and self.active[0] == name:
                self.active = None
            return f"Connection '{name}' successfully deleted.\n"
        if args[:2] == ["connection", "up"]:
            return await self._up(args)
        raise AssertionError(f"the backend asked for something unexpected: {args}")

    def _read(self, args):
        if "DEVICE,TYPE" in args:
            return "wlp2s0:wifi\n"
        if "list" in args:
            return "".join(
                f"{ssid}:{signal}:{security}\n"
                for ssid, (signal, security) in self.networks.items()
            )
        if "device" in args and "show" in args:
            if self.active is None:
                return "GENERAL.STATE:30 (disconnected)\nGENERAL.CONNECTION:\nGENERAL.CON-UUID:\n"
            name, uuid = self.active
            address = "IP4.ADDRESS[1]:10.20.0.7/24\n"
            if name.startswith(PROFILE_PREFIX) and self.late > 0:
                # The real one says "connected" a moment before it shows the address.
                self.late -= 1
                address = ""
            return (
                f"GENERAL.STATE:100 (connected)\nGENERAL.CONNECTION:{name}\n"
                f"GENERAL.CON-UUID:{uuid}\n{address}"
            )
        if "show" in args:  # the names of all connections
            return "".join(f"{name}\n" for name in [OLD[0], *self.profiles])
        raise AssertionError(f"the backend asked for something unexpected: {args}")

    def _edit(self, name, commands):
        # The real editor echoes what it reads, and it drops spaces at both ends of a value.
        line = commands.splitlines()[0]
        if self.edit_fails:
            return (
                f"nmcli> {line}\nError: Failed to save '{name}' connection: property is invalid\n"
            )
        self.profiles[name]["psk"] = line.removeprefix("set wifi-sec.psk ").strip()
        return f"nmcli> {line}\nConnection '{name}' (uuid) successfully updated.\nnmcli> quit\n"

    async def _up(self, args):
        if args[2] == "uuid":  # going back to the old connection
            if args[3] != OLD[1]:
                raise NetworkManagerError("Error: unknown connection.")
            self.active = OLD
            return "Connection successfully activated.\n"
        name = args[3]
        assert "passwd-file" not in args
        self.active = None
        if self.delay:
            await asyncio.sleep(self.delay)
        profile = self.profiles[name]
        if profile["secured"] and profile["psk"] != PASSWORD:
            raise NetworkManagerError(
                "Error: Connection activation failed: (7) Secrets were required, but not provided."
            )
        if self.failure:
            raise NetworkManagerError(self.failure)
        self.active = (name, f"uuid-{name}")
        return "Connection successfully activated.\n"

    def changed_something(self):
        return any("add" in call or "up" in call or "delete" in call for call in self.calls)


def credentials(ssid, password=PASSWORD):
    return WifiCredentials(ssid, Secret(password) if password else None)


class Waits:
    """A clock that does not wait. It adds up how long it was asked to wait."""

    def __init__(self):
        self.total = 0.0

    async def __call__(self, seconds):
        self.total += seconds


async def join(fake, ssid, password=PASSWORD, waits=None):
    backend = NetworkManagerBackend(run=fake, sleep=waits or Waits())
    return await backend.connect(credentials(ssid, password))


async def test_joining_with_the_right_password_works():
    fake = FakeNmcli()
    result = await join(fake, "Hospital")
    assert result == ConnectResult(True, ip="10.20.0.7")
    name, _ = fake.active
    assert name.startswith(PROFILE_PREFIX)
    assert set(fake.profiles) == {name}  # the connection we made is kept
    assert fake.profiles[name]["autoconnect"] == "yes"  # and it starts by itself after a reboot
    assert ["connection", "delete", "id", OLD[0]] not in fake.calls  # the old one is left alone


async def test_an_address_that_shows_up_a_moment_late_is_waited_for():
    fake = FakeNmcli(late=3)
    waits = Waits()
    result = await join(fake, "Hospital", waits=waits)
    assert result == ConnectResult(True, ip="10.20.0.7")
    assert waits.total == 3 * ADDRESS_POLL
    assert len(fake.profiles) == 1  # the connection was kept


async def test_an_address_that_is_there_at_once_costs_no_waiting():
    waits = Waits()
    await join(FakeNmcli(), "Hospital", waits=waits)
    assert waits.total == 0


async def test_a_connection_that_never_gets_an_address_goes_back_after_the_wait():
    fake = FakeNmcli(late=10**6)
    waits = Waits()
    result = await join(fake, "Hospital", waits=waits)
    assert result == ConnectResult(False, Failure.NO_ADDRESS)
    assert waits.total == DHCP_WAIT
    assert fake.active == OLD
    assert fake.profiles == {}


async def test_the_connection_does_not_start_by_itself_until_it_has_worked():
    fake = FakeNmcli()
    await join(fake, "Hospital", "not the password")
    add = next(call for call in fake.calls if "add" in call)
    assert add[add.index("connection.autoconnect") + 1] == "no"


@pytest.mark.parametrize("password", [PASSWORD, "not the password"])
async def test_the_password_never_appears_in_the_arguments(password):
    fake = FakeNmcli()
    await join(fake, "Hospital", password)
    assert not any(password in word for call in fake.calls for word in call)


async def test_the_password_goes_to_the_editor_on_standard_input_and_nowhere_else():
    fake = FakeNmcli()
    await join(fake, "Hospital")
    assert len(fake.inputs) == 1
    arguments, text = fake.inputs[0]
    assert arguments[:2] == ["connection", "edit"]
    assert text == f"set wifi-sec.psk {PASSWORD}\nsave\nquit\n"


async def test_a_wrong_password_goes_back_to_the_old_network():
    fake = FakeNmcli()
    result = await join(fake, "Hospital", "not the password")
    assert result == ConnectResult(False, Failure.WRONG_PASSWORD)
    assert fake.active == OLD
    assert fake.profiles == {}


@pytest.mark.parametrize(
    ("message", "failure"),
    [
        (
            "Error: Connection activation failed: IP configuration could not be reserved "
            "(no available address, timeout, etc.).",
            Failure.NO_ADDRESS,
        ),
        ("Error: Timeout expired (30 seconds)", Failure.TIMEOUT),
        ("Error: something nobody expected", Failure.OTHER),
    ],
)
async def test_other_failures_are_reported_and_undone(message, failure):
    fake = FakeNmcli(failure=message)
    result = await join(fake, "Hospital")
    assert result == ConnectResult(False, failure)
    assert fake.active == OLD
    assert fake.profiles == {}


async def test_an_unknown_error_is_logged_without_the_password(caplog):
    fake = FakeNmcli(failure=f"Error: something odd happened with {PASSWORD}")
    with caplog.at_level(logging.DEBUG):
        result = await join(fake, "Hospital")
    assert result.failure is Failure.OTHER
    assert "something odd happened" in caplog.text
    assert PASSWORD not in caplog.text


async def test_a_password_the_editor_cannot_save_goes_back_and_is_not_logged(caplog):
    fake = FakeNmcli(edit_fails=True)
    with caplog.at_level(logging.DEBUG):
        result = await join(fake, "Hospital")
    assert result == ConnectResult(False, Failure.OTHER)
    assert fake.active == OLD
    assert fake.profiles == {}
    assert (
        PASSWORD not in caplog.text
    )  # the editor echoes the password, so its output is not logged


async def test_if_the_network_cannot_be_kept_for_the_next_boot_it_goes_back():
    fake = FakeNmcli()
    fake.modify_failure = "Error: Failed to modify connection"
    result = await join(fake, "Hospital")
    assert result == ConnectResult(False, Failure.OTHER)
    assert fake.active == OLD
    assert fake.profiles == {}


async def test_a_network_out_of_range_costs_nothing():
    fake = FakeNmcli()
    result = await join(fake, "Nowhere")
    assert result == ConnectResult(False, Failure.NETWORK_NOT_FOUND)
    assert fake.active == OLD
    assert not fake.changed_something()


@pytest.mark.parametrize("ssid", ["Corp", "Old router"])
async def test_enterprise_and_old_kinds_of_network_are_not_supported(ssid):
    fake = FakeNmcli()
    result = await join(fake, ssid)
    assert result == ConnectResult(False, Failure.UNSUPPORTED)
    assert not fake.changed_something()


async def test_a_secured_network_without_a_password_is_refused_at_once():
    fake = FakeNmcli()
    result = await join(fake, "Hospital", None)
    assert result == ConnectResult(False, Failure.WRONG_PASSWORD)
    assert not fake.changed_something()


@pytest.mark.parametrize("password", [None, "a password for nothing"])
async def test_an_open_network_is_joined_without_a_password(password):
    fake = FakeNmcli()
    result = await join(fake, "Guest", password)
    assert result.connected
    assert fake.inputs == []  # the editor was not needed
    add = next(call for call in fake.calls if "add" in call)
    assert "wifi-sec.key-mgmt" not in add
    assert not any("a password for nothing" in word for call in fake.calls for word in call)


async def test_after_a_success_the_older_connections_we_made_are_removed():
    fake = FakeNmcli()
    fake.profiles = {PROFILE_PREFIX + "older": {"secured": True, "psk": "x", "autoconnect": "yes"}}
    await join(fake, "Hospital")
    assert PROFILE_PREFIX + "older" not in fake.profiles
    assert len(fake.profiles) == 1


async def test_when_there_was_no_connection_a_failure_leaves_none():
    fake = FakeNmcli(active=None)
    result = await join(fake, "Hospital", "not the password")
    assert result.failure is Failure.WRONG_PASSWORD
    assert fake.active is None
    assert fake.profiles == {}
    assert not any("uuid" in call for call in fake.calls)  # there was nothing to go back to


async def test_a_failure_before_anything_changed_leaves_the_old_connection_alone():
    fake = FakeNmcli(add_failure="Error: Failed to add connection: not authorized")
    result = await join(fake, "Hospital")
    assert result == ConnectResult(False, Failure.OTHER)
    assert fake.active == OLD
    assert not any("uuid" in call for call in fake.calls)  # it was never restarted


async def test_an_attempt_that_is_cancelled_still_goes_back():
    fake = FakeNmcli(delay=5)
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(
            NetworkManagerBackend(run=fake).connect(credentials("Hospital")), 0.2
        )
    assert fake.active == OLD
    assert fake.profiles == {}


# ----------------------------------------------------------------- the real nmcli call


def fake_nmcli(tmp_path, monkeypatch, script):
    path = tmp_path / "nmcli"
    path.write_text("#!/bin/sh\n" + script + "\n")
    path.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")


@posix_only
async def test_nmcli_gets_each_word_as_it_is_and_an_english_utf8_locale(tmp_path, monkeypatch):
    fake_nmcli(tmp_path, monkeypatch, 'printf "%s|" "$@"; echo; echo "$LC_ALL"')
    output = await run_nmcli(["device", "a b; echo hacked"])
    assert output == "device|a b; echo hacked|\nC.UTF-8\n"


@posix_only
async def test_nmcli_gets_the_input_on_standard_input(tmp_path, monkeypatch):
    fake_nmcli(tmp_path, monkeypatch, "cat")
    assert await run_nmcli([], input="set a b\nsave\n") == "set a b\nsave\n"


@posix_only
async def test_without_input_nmcli_has_nothing_to_read(tmp_path, monkeypatch):
    fake_nmcli(tmp_path, monkeypatch, "cat; echo end")
    assert await run_nmcli([]) == "end\n"


@posix_only
async def test_nmcli_output_in_utf8_is_read_correctly(tmp_path, monkeypatch):
    fake_nmcli(tmp_path, monkeypatch, "echo 医院网络:80:WPA2")
    assert await run_nmcli([]) == "医院网络:80:WPA2\n"


@posix_only
async def test_a_failing_nmcli_gives_its_own_message(tmp_path, monkeypatch):
    fake_nmcli(tmp_path, monkeypatch, 'echo "Error: NetworkManager is not running." >&2; exit 8')
    with pytest.raises(NetworkManagerError, match="NetworkManager is not running"):
        await run_nmcli([])


@posix_only
async def test_a_missing_nmcli_is_said_clearly(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))  # an empty folder
    with pytest.raises(NetworkManagerError, match="not found"):
        await run_nmcli([])


@posix_only
async def test_nmcli_that_does_not_answer_is_stopped(tmp_path, monkeypatch):
    fake_nmcli(tmp_path, monkeypatch, "exec sleep 5")
    with pytest.raises(NetworkManagerError, match="in time"):
        await run_nmcli([], timeout=0.2)
