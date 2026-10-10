"""The real Wi-Fi adapter, read through NetworkManager's nmcli command."""

from __future__ import annotations

import asyncio
import contextlib
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from wifiprov.wifi import Security, WifiNetwork

NMCLI_TIMEOUT = 20.0
STATE_CONNECTED = 100  # NetworkManager's number for "the adapter has a working connection"
STATUS_FIELDS = "GENERAL.STATE,GENERAL.CONNECTION,IP4.ADDRESS"

Runner = Callable[[list[str]], Awaitable[str]]


class NetworkManagerError(Exception):
    """NetworkManager is missing, not running, or refused what we asked."""


@dataclass(frozen=True)
class WifiStatus:
    interface: str
    state: int
    connection: str | None  # the name of the connection it is using
    ip: str | None

    @property
    def connected(self) -> bool:
        return self.state == STATE_CONNECTED


async def run_nmcli(args: list[str], timeout: float = NMCLI_TIMEOUT) -> str:
    """Run nmcli and return what it printed. No shell is involved."""
    # C.UTF-8 keeps nmcli's words in English and still prints network names correctly.
    env = {**os.environ, "LC_ALL": "C.UTF-8"}
    try:
        process = await asyncio.create_subprocess_exec(
            "nmcli",
            *args,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
    except FileNotFoundError:
        raise NetworkManagerError("nmcli was not found. Is NetworkManager installed?") from None
    try:
        out, err = await asyncio.wait_for(process.communicate(), timeout)
    except asyncio.TimeoutError:
        _stop(process)
        await process.wait()
        raise NetworkManagerError("nmcli did not answer in time") from None
    except asyncio.CancelledError:
        _stop(process)
        raise
    if process.returncode != 0:
        raise NetworkManagerError(err.decode("utf-8", "replace").strip() or "nmcli failed")
    return out.decode("utf-8", "replace")


def _stop(process: asyncio.subprocess.Process) -> None:
    with contextlib.suppress(ProcessLookupError):
        process.kill()


def split_terse(line: str) -> list[str]:
    """Split one line of ``nmcli -t`` output.

    Fields are separated by ':'. A ':' or a '\\' inside a field has a '\\' in front of it.
    """
    fields: list[str] = []
    field: list[str] = []
    escaped = False
    for character in line:
        if escaped:
            field.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            fields.append("".join(field))
            field = []
        else:
            field.append(character)
    fields.append("".join(field))
    return fields


def parse_security(text: str) -> Security:
    words = text.split()
    if not words or words == ["--"]:
        return Security.OPEN
    if "802.1X" in words:
        return Security.ENTERPRISE
    if any(word.startswith("WPA") for word in words):
        return Security.WPA_PSK
    return Security.OTHER  # WEP, OWE and anything we do not know


def parse_networks(text: str) -> list[WifiNetwork]:
    """Read the output of ``nmcli -t -f SSID,SIGNAL,SECURITY device wifi list``."""
    strongest: dict[str, WifiNetwork] = {}
    for line in text.splitlines():
        fields = split_terse(line)
        if len(fields) != 3:
            continue
        ssid, signal, security = fields
        try:
            network = WifiNetwork(ssid, int(signal), parse_security(security))
        except ValueError:
            continue  # a hidden network has no name, and a bad line has no number
        # Several access points can share one name. Keep the strongest.
        if ssid not in strongest or network.signal > strongest[ssid].signal:
            strongest[ssid] = network
    return sorted(strongest.values(), key=lambda network: (-network.signal, network.ssid))


def parse_status(interface: str, text: str) -> WifiStatus:
    """Read what ``nmcli -t device show`` prints for the adapter."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, *rest = split_terse(line)
        values.setdefault(key, ":".join(rest))
    try:
        state = int(values["GENERAL.STATE"].split()[0])
    except (KeyError, IndexError, ValueError):
        raise NetworkManagerError("nmcli did not say what state the adapter is in") from None
    connection = values.get("GENERAL.CONNECTION", "")
    address = next((v for k, v in values.items() if k.startswith("IP4.ADDRESS")), "")
    return WifiStatus(
        interface=interface,
        state=state,
        connection=None if connection in ("", "--") else connection,
        ip=address.split("/")[0] or None,
    )


class NetworkManagerBackend:
    """Looks at the Wi-Fi adapter through nmcli. It changes nothing."""

    def __init__(self, interface: str | None = None, *, run: Runner = run_nmcli) -> None:
        self._interface = interface
        self._run = run

    async def scan(self) -> list[WifiNetwork]:
        interface = await self._find_interface()
        # --rescan yes asks for a fresh scan and waits for it. NetworkManager only allows that
        # for root or for someone at the machine. Without permission nmcli still prints the
        # list from the last scan, which is good enough.
        text = await self._run(
            ["-t", "-f", "SSID,SIGNAL,SECURITY", "device", "wifi", "list"]
            + ["ifname", interface, "--rescan", "yes"]
        )
        return parse_networks(text)

    async def status(self) -> WifiStatus:
        interface = await self._find_interface()
        text = await self._run(["-t", "-f", STATUS_FIELDS, "device", "show", interface])
        return parse_status(interface, text)

    async def _find_interface(self) -> str:
        if self._interface:
            return self._interface
        text = await self._run(["-t", "-f", "DEVICE,TYPE", "device"])
        for line in text.splitlines():
            fields = split_terse(line)
            if len(fields) == 2 and fields[1] == "wifi":
                return fields[0]
        raise NetworkManagerError("NetworkManager sees no Wi-Fi adapter")
