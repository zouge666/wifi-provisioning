import asyncio
import logging

import pytest

from wifiprov.device.accesspoint import AccessPointBackend
from wifiprov.device.networkmanager import NetworkManagerError
from wifiprov.secret import Secret
from wifiprov.wifi import ConnectResult, Failure, Security, WifiCredentials, WifiNetwork

HOSPITAL = WifiNetwork("Hospital", 80, Security.WPA_PSK)
CREDENTIALS = WifiCredentials("Hospital", Secret("correct horse"))


class FakeWifi:
    """The adapter, as far as the access point backend is concerned. It writes down what happens."""

    def __init__(self, result=None):
        self.events = []
        self.result = result or ConnectResult(True, ip="10.20.0.7")
        self.connect_error = None
        self.start_error = None
        self.delay = 0.0

    async def scan(self):
        self.events.append("scan")
        return [HOSPITAL]

    async def start_access_point(self, ssid):
        if self.start_error:
            raise self.start_error
        self.events.append(f"start {ssid}")
        return "10.42.0.1"

    async def stop_access_point(self):
        self.events.append("stop")

    async def connect(self, credentials):
        self.events.append("connect")
        await asyncio.sleep(self.delay)
        if self.connect_error:
            raise self.connect_error
        return self.result


def test_the_phone_is_cut_off_by_joining():
    assert AccessPointBackend(FakeWifi(), "wifiprov-TEST").drops_link


async def test_the_networks_are_scanned_before_the_access_point_opens():
    wifi = FakeWifi()
    address = await AccessPointBackend(wifi, "wifiprov-TEST").start()
    assert address == "10.42.0.1"
    assert wifi.events == ["scan", "start wifiprov-TEST"]


async def test_a_scan_gives_the_list_from_before_the_access_point_opened():
    wifi = FakeWifi()
    backend = AccessPointBackend(wifi, "wifiprov-TEST")
    assert await backend.scan() == []  # nothing yet
    await backend.start()
    assert await backend.scan() == [HOSPITAL]
    assert await backend.scan() == [HOSPITAL]
    assert wifi.events.count("scan") == 1  # the adapter is not asked while it is an access point


async def test_joining_closes_the_access_point_first_and_does_not_open_it_again_on_success():
    wifi = FakeWifi()
    backend = AccessPointBackend(wifi, "wifiprov-TEST")
    await backend.start()
    wifi.events.clear()

    assert await backend.connect(CREDENTIALS) == ConnectResult(True, ip="10.20.0.7")
    assert wifi.events == ["stop", "connect"]


async def test_a_failed_join_brings_the_access_point_back():
    wifi = FakeWifi(ConnectResult(False, Failure.WRONG_PASSWORD))
    backend = AccessPointBackend(wifi, "wifiprov-TEST")
    await backend.start()
    wifi.events.clear()

    assert await backend.connect(CREDENTIALS) == ConnectResult(False, Failure.WRONG_PASSWORD)
    assert wifi.events == ["stop", "connect", "scan", "start wifiprov-TEST"]
    assert await backend.scan() == [HOSPITAL]


async def test_a_join_that_breaks_brings_the_access_point_back_and_passes_the_error_on():
    wifi = FakeWifi()
    wifi.connect_error = NetworkManagerError("NetworkManager sees no Wi-Fi adapter")
    backend = AccessPointBackend(wifi, "wifiprov-TEST")
    await backend.start()
    wifi.events.clear()

    with pytest.raises(NetworkManagerError):
        await backend.connect(CREDENTIALS)
    assert wifi.events == ["stop", "connect", "scan", "start wifiprov-TEST"]


async def test_a_join_that_is_cancelled_brings_the_access_point_back():
    wifi = FakeWifi()
    wifi.delay = 5
    backend = AccessPointBackend(wifi, "wifiprov-TEST")
    await backend.start()
    wifi.events.clear()

    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(backend.connect(CREDENTIALS), 0.1)
    assert wifi.events == ["stop", "connect", "scan", "start wifiprov-TEST"]


async def test_an_access_point_that_cannot_come_back_is_logged_and_the_result_still_counts(caplog):
    wifi = FakeWifi(ConnectResult(False, Failure.TIMEOUT))
    backend = AccessPointBackend(wifi, "wifiprov-TEST")
    await backend.start()
    wifi.start_error = NetworkManagerError("no dnsmasq")

    with caplog.at_level(logging.DEBUG):
        assert await backend.connect(CREDENTIALS) == ConnectResult(False, Failure.TIMEOUT)
    assert "could not be opened again" in caplog.text
    assert "correct horse" not in caplog.text


async def test_stop_closes_the_access_point():
    wifi = FakeWifi()
    backend = AccessPointBackend(wifi, "wifiprov-TEST")
    await backend.start()
    await backend.stop()
    assert wifi.events[-1] == "stop"
