import asyncio

import pytest

from wifiprov.device.fake import FakeBackend, FakeNetwork
from wifiprov.secret import Secret
from wifiprov.wifi import ConnectResult, Failure, Security, WifiCredentials

NETWORKS = {
    "Hospital": FakeNetwork("correct horse", signal=80, ip="10.20.0.7"),
    "Guest": FakeNetwork(None, signal=40),
    "Ward 3": FakeNetwork("another password", signal=60),
    "No DHCP": FakeNetwork("dhcp is broken", signal=50, ip=None),
}


def credentials(ssid, password=None):
    return WifiCredentials(ssid, Secret(password) if password else None)


async def test_scan_lists_networks_strongest_first_with_their_security():
    networks = await FakeBackend(NETWORKS).scan()
    assert [(n.ssid, n.signal, n.security) for n in networks] == [
        ("Hospital", 80, Security.WPA_PSK),
        ("Ward 3", 60, Security.WPA_PSK),
        ("No DHCP", 50, Security.WPA_PSK),
        ("Guest", 40, Security.OPEN),
    ]


async def test_joining_with_the_right_password_works():
    backend = FakeBackend(NETWORKS)
    result = await backend.connect(credentials("Hospital", "correct horse"))
    assert result == ConnectResult(True, ip="10.20.0.7")
    assert backend.connected_to == "Hospital"


async def test_joining_an_open_network_needs_no_password():
    backend = FakeBackend(NETWORKS)
    assert (await backend.connect(credentials("Guest"))).connected
    assert backend.connected_to == "Guest"


@pytest.mark.parametrize(
    ("ssid", "password", "failure"),
    [
        ("Hospital", "not the password", Failure.WRONG_PASSWORD),
        ("Hospital", None, Failure.WRONG_PASSWORD),
        ("Out of range", "whatever123", Failure.NETWORK_NOT_FOUND),
        ("No DHCP", "dhcp is broken", Failure.NO_ADDRESS),
    ],
)
async def test_failures_say_why_and_leave_the_old_network_in_place(ssid, password, failure):
    backend = FakeBackend(NETWORKS, connected_to="Old network")
    result = await backend.connect(credentials(ssid, password))
    assert result == ConnectResult(False, failure)
    assert backend.connected_to == "Old network"


async def test_attempts_are_recorded():
    backend = FakeBackend(NETWORKS)
    await backend.connect(credentials("Guest"))
    await backend.connect(credentials("Hospital", "wrong password"))
    assert backend.attempts == ["Guest", "Hospital"]


async def test_a_held_connection_waits_until_released():
    hold = asyncio.Event()
    backend = FakeBackend(NETWORKS, hold=hold)
    attempt = asyncio.create_task(backend.connect(credentials("Guest")))
    await asyncio.sleep(0.02)
    assert not attempt.done()
    hold.set()
    assert (await attempt).connected


async def test_a_cancelled_connection_leaves_the_old_network_in_place():
    backend = FakeBackend(NETWORKS, connected_to="Old network", connect_delay=5)
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(backend.connect(credentials("Guest")), 0.02)
    assert backend.connected_to == "Old network"
