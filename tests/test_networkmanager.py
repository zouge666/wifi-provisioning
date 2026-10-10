import os

import pytest

from wifiprov.device.networkmanager import (
    NetworkManagerBackend,
    NetworkManagerError,
    WifiStatus,
    parse_networks,
    parse_security,
    parse_status,
    run_nmcli,
    split_terse,
)
from wifiprov.wifi import Security, WifiNetwork

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
    assert status == WifiStatus("wlp2s0", 100, "Hospital WiFi", "10.20.0.7")
    assert status.connected


@pytest.mark.parametrize("empty", ["", "--"])
def test_parse_status_of_an_adapter_that_is_not_connected(empty):
    status = parse_status(
        "wlp2s0", f"GENERAL.STATE:30 (disconnected)\nGENERAL.CONNECTION:{empty}\n"
    )
    assert status == WifiStatus("wlp2s0", 30, None, None)
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


# ------------------------------------------------------------------------ the backend


def make_runner(*, devices="enp1s0:ethernet\nwlp2s0:wifi\nlo:loopback\n", networks="", status=""):
    """A stand-in for nmcli that answers by what is asked and remembers the questions."""
    calls = []

    async def run(args):
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
    assert status == WifiStatus("wlp2s0", 100, "Hospital WiFi", "10.20.0.7")
    assert calls[1][-3:] == ["device", "show", "wlp2s0"]


async def test_a_failure_of_nmcli_is_passed_on():
    async def run(args):
        raise NetworkManagerError("NetworkManager is not running.")

    with pytest.raises(NetworkManagerError, match="not running"):
        await NetworkManagerBackend(run=run).scan()


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
