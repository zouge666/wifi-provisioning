"""The real Wi-Fi adapter, driven through NetworkManager's nmcli command."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from wifiprov.wifi import ConnectResult, Failure, Security, WifiCredentials, WifiNetwork

logger = logging.getLogger(__name__)

NMCLI_TIMEOUT = 20.0
JOIN_WAIT = 30  # seconds nmcli may wait for a network to accept us
DHCP_WAIT = 20  # seconds the network has to give us an address
ADDRESS_POLL = 0.5  # seconds between two looks for the address
STATE_CONNECTED = 100  # NetworkManager's number for "the adapter has a working connection"
STATUS_FIELDS = "GENERAL.STATE,GENERAL.CONNECTION,GENERAL.CON-UUID,IP4.ADDRESS"
PROFILE_PREFIX = "wifiprov-"  # every connection we create starts with this

# Part of what nmcli says when joining fails, and what it means for the technician.
FAILURE_WORDS = (
    ("secrets were required", Failure.WRONG_PASSWORD),
    ("could not be found", Failure.NETWORK_NOT_FOUND),
    ("no network with ssid", Failure.NETWORK_NOT_FOUND),
    ("ip configuration", Failure.NO_ADDRESS),
    ("timeout expired", Failure.TIMEOUT),
)

# Called as run(args). The optional timeout= says how long a slow command may take, and
# input= is the text to send to the command on its standard input.
Runner = Callable[..., Awaitable[str]]


class NetworkManagerError(Exception):
    """NetworkManager is missing, not running, or refused what we asked."""


@dataclass(frozen=True)
class WifiStatus:
    interface: str
    state: int
    connection: str | None  # the name of the connection it is using
    ip: str | None
    uuid: str | None = None  # the id of that connection, which stays the same if it is renamed

    @property
    def connected(self) -> bool:
        return self.state == STATE_CONNECTED


async def run_nmcli(
    args: list[str], timeout: float = NMCLI_TIMEOUT, input: str | None = None
) -> str:
    """Run nmcli and return what it printed. No shell is involved."""
    # C.UTF-8 keeps nmcli's words in English and still prints network names correctly.
    env = {**os.environ, "LC_ALL": "C.UTF-8"}
    stdin = asyncio.subprocess.DEVNULL if input is None else asyncio.subprocess.PIPE
    try:
        process = await asyncio.create_subprocess_exec(
            "nmcli",
            *args,
            stdin=stdin,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
    except FileNotFoundError:
        raise NetworkManagerError("nmcli was not found. Is NetworkManager installed?") from None
    try:
        data = None if input is None else input.encode("utf-8")
        out, err = await asyncio.wait_for(process.communicate(data), timeout)
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
        uuid=values.get("GENERAL.CON-UUID") or None,
    )


def classify_failure(message: str, password: str | None = None) -> Failure:
    """Say why nmcli could not join a network, going by what it printed."""
    lower = message.lower()
    for words, failure in FAILURE_WORDS:
        if words in lower:
            return failure
    # An unknown message is logged so it can be learned from. Never with the password in it.
    if password:
        message = message.replace(password, "[hidden]")
    logger.warning("nmcli could not join the network: %s", message)
    return Failure.OTHER


class NetworkManagerBackend:
    """The Wi-Fi adapter of this machine, seen and changed through nmcli.

    Changing the network needs root, or someone at the machine: NetworkManager asks
    polkit, and a normal user over SSH is refused.
    """

    def __init__(
        self,
        interface: str | None = None,
        *,
        run: Runner = run_nmcli,
        sleep: Callable[[float], Awaitable[object]] = asyncio.sleep,
    ) -> None:
        self._interface = interface
        self._run = run
        self._sleep = sleep
        self._busy = asyncio.Lock()  # one attempt at a time, even while an old one cleans up

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

    async def connect(self, credentials: WifiCredentials) -> ConnectResult:
        """Join a network. If that does not work, the adapter goes back to what it had."""
        async with self._busy:
            interface = await self._find_interface()
            # Look first. A network we cannot join should not cost us the one we have.
            networks = await self.scan()
            network = next((n for n in networks if n.ssid == credentials.ssid), None)
            if network is None:
                return ConnectResult(False, Failure.NETWORK_NOT_FOUND)
            if network.security in (Security.ENTERPRISE, Security.OTHER):
                return ConnectResult(False, Failure.UNSUPPORTED)
            secured = network.security is Security.WPA_PSK
            if secured and credentials.password is None:
                return ConnectResult(False, Failure.WRONG_PASSWORD)

            before = await self.status()
            name = PROFILE_PREFIX + secrets.token_hex(4)
            try:
                result = await self._join(interface, name, credentials, secured)
            except asyncio.CancelledError:
                # For example the agent ran out of time. Cleaning up must not be cancelled too.
                await asyncio.shield(self._go_back(interface, name, before))
                raise
            if result.connected:
                await self._forget_other_profiles(keep=name)
            else:
                await self._go_back(interface, name, before)
            outcome = "worked" if result.connected else f"failed ({result.failure})"
            logger.info("joining a network %s", outcome)
            return result

    async def _join(
        self, interface: str, name: str, credentials: WifiCredentials, secured: bool
    ) -> ConnectResult:
        # The connection is made without a password and does not start by itself yet.
        add = ["connection", "add", "type", "wifi", "ifname", interface, "con-name", name]
        add += ["ssid", credentials.ssid, "ipv4.dhcp-timeout", str(DHCP_WAIT)]
        add += ["connection.autoconnect", "no"]
        up = ["--wait", str(JOIN_WAIT), "connection", "up", "id", name, "ifname", interface]
        password = credentials.password.reveal() if secured and credentials.password else None
        if password is not None:
            add += ["wifi-sec.key-mgmt", "wpa-psk"]

        try:
            await self._run(add)
            if password is not None:
                await self._set_password(name, password)
            await self._run(up, timeout=JOIN_WAIT + 15)
        except NetworkManagerError as error:
            return ConnectResult(False, classify_failure(str(error), password))

        try:
            status = await self._status_with_address(name)
        except NetworkManagerError:
            return ConnectResult(False, Failure.OTHER)
        if not status.connected or status.connection != name:
            return ConnectResult(False, Failure.OTHER)
        if status.ip is None:
            return ConnectResult(False, Failure.NO_ADDRESS)

        # It works. Now let NetworkManager join this network by itself after a reboot.
        try:
            await self._run(["connection", "modify", "id", name, "connection.autoconnect", "yes"])
        except NetworkManagerError:
            return ConnectResult(False, Failure.OTHER)
        return ConnectResult(True, ip=status.ip)

    async def _status_with_address(self, name: str) -> WifiStatus:
        # NetworkManager says "connected" a moment before it shows the address. On the real
        # laptop the first look came too early and a working connection was thrown away.
        # So look again for a while.
        status = await self.status()
        waited = 0.0
        while status.connected and status.connection == name and status.ip is None:
            if waited >= DHCP_WAIT:
                break
            await self._sleep(ADDRESS_POLL)
            waited += ADDRESS_POLL
            status = await self.status()
        return status

    async def _set_password(self, name: str, password: str) -> None:
        # The password goes to the editor of nmcli on standard input, so it is never in the
        # arguments of a program, where every user of the machine could read it. NetworkManager
        # then keeps it in the connection. The editor echoes what it reads, so its output is
        # never logged. It also drops spaces at both ends of the password, so the credentials
        # do not accept such passwords.
        commands = f"set wifi-sec.psk {password}\nsave\nquit\n"
        output = await self._run(["connection", "edit", "id", name], input=commands)
        if "successfully" not in output:
            raise NetworkManagerError("nmcli could not save the password")

    async def _go_back(self, interface: str, name: str, before: WifiStatus) -> None:
        await self._try(["connection", "delete", "id", name])
        if not before.uuid:
            return  # it had no connection, so there is nothing to go back to
        try:
            now = await self.status()
        except NetworkManagerError:
            now = None
        if now is None or not now.connected or now.uuid != before.uuid:
            up = ["--wait", str(JOIN_WAIT), "connection", "up", "uuid", before.uuid]
            await self._try(up + ["ifname", interface], timeout=JOIN_WAIT + 15)

    async def _forget_other_profiles(self, keep: str) -> None:
        try:
            text = await self._run(["-t", "-f", "NAME", "connection", "show"])
        except NetworkManagerError:
            return
        for line in text.splitlines():
            name = split_terse(line)[0]
            if name.startswith(PROFILE_PREFIX) and name != keep:
                await self._try(["connection", "delete", "id", name])

    async def _try(self, args: list[str], **options: float) -> None:
        # Cleaning up is best effort: one step failing must not stop the next one.
        try:
            await self._run(args, **options)
        except NetworkManagerError as error:
            logger.warning("a clean-up step failed: %s", error)

    async def _find_interface(self) -> str:
        if self._interface:
            return self._interface
        text = await self._run(["-t", "-f", "DEVICE,TYPE", "device"])
        for line in text.splitlines():
            fields = split_terse(line)
            if len(fields) == 2 and fields[1] == "wifi":
                return fields[0]
        raise NetworkManagerError("NetworkManager sees no Wi-Fi adapter")
