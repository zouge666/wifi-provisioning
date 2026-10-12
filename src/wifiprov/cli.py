"""Command line for running the device and the configurator as two programs.

Secrets never go on the command line, where any other user of the machine can read
them with ``ps``. The Wi-Fi password is typed at a hidden prompt or read from
standard input, and the sticker ticket is read from a file, standard input or a
hidden prompt.

Exit codes: 0 joined the network, 1 did not join it, 2 bad input, 3 the device
refused, did not answer or is not the one on the sticker.
The scan command exits with 0 when it listed the networks and 1 when it could not.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import getpass
import logging
import os
import signal
import sys
from collections.abc import Sequence
from pathlib import Path

from wifiprov.configurator.client import (
    Configurator,
    DeviceRefused,
    DeviceUnreachable,
    NotTheExpectedDevice,
    ProvisioningError,
)
from wifiprov.device.agent import DeviceAgent, Outcome
from wifiprov.device.fake import FakeBackend, FakeNetwork
from wifiprov.device.networkmanager import NetworkManagerBackend, NetworkManagerError
from wifiprov.device.window import Window
from wifiprov.identity import DeviceIdentity, IdentityError
from wifiprov.secret import Secret
from wifiprov.ticket import Ticket, TicketError
from wifiprov.transport.base import Transport
from wifiprov.transport.tcp import connect_tcp, serve_tcp
from wifiprov.wifi import Failure, Security, WifiCredentials, WifiNetwork, describe_failure
from wifiprov.wire import RejectReason

EXIT_JOINED = 0
EXIT_NOT_JOINED = 1
EXIT_BAD_INPUT = 2
EXIT_NO_DEVICE = 3
EXIT_SCAN_FAILED = 1

DEFAULT_ADDRESS = "127.0.0.1:8765"
DEMO_NETWORKS = {
    "Hospital WiFi": FakeNetwork("correct horse battery", signal=80, ip="10.20.0.7"),
    "Ward 3": FakeNetwork("another password", signal=60, ip="10.30.0.9"),
    "Guest": FakeNetwork(None, signal=40, ip="192.168.50.4"),
}
MAX_PASSWORD_PROMPTS = 3
NETWORK_WAIT = 30.0  # seconds a device waits for its network after a start


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        return args.run(args)
    except KeyboardInterrupt:
        return 130


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wifiprov",
        description="Hand Wi-Fi credentials to a device without any shared network.",
        epilog=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="create a device identity and its sticker ticket")
    init.add_argument(
        "--identity", required=True, metavar="FILE", help="where to save the identity"
    )
    init.add_argument(
        "--ticket-out", metavar="FILE", help="write the ticket here instead of printing it"
    )
    init.set_defaults(run=_run_init)

    device = commands.add_parser("device", help="run the device side")
    device.add_argument("--identity", required=True, metavar="FILE")
    device.add_argument("--listen", default=DEFAULT_ADDRESS, metavar="HOST:PORT")
    device.add_argument(
        "--backend",
        choices=["fake", "nm"],
        default="fake",
        help="the Wi-Fi adapter: a pretend one, or the real one through NetworkManager",
    )
    device.add_argument(
        "--interface",
        metavar="NAME",
        help="the Wi-Fi adapter for --backend nm; by default the first one",
    )
    device.add_argument(
        "--window",
        type=float,
        default=0,
        metavar="SECONDS",
        help="listen only this long, and only while the device has no network; 0 means always",
    )
    device.add_argument(
        "--fake-network",
        action="append",
        metavar="NAME=PASSWORD",
        help="a pretend network with this password; repeat for several (not real secrets)",
    )
    device.add_argument(
        "--fake-open-network", action="append", metavar="NAME", help="a pretend open network"
    )
    device.set_defaults(run=_run_device)

    configure = commands.add_parser("configure", help="run the configurator side")
    configure.add_argument("--connect", default=DEFAULT_ADDRESS, metavar="HOST:PORT")
    source = configure.add_mutually_exclusive_group()
    source.add_argument("--ticket-file", metavar="FILE", help="file holding the sticker ticket")
    source.add_argument(
        "--ticket-stdin", action="store_true", help="read the ticket from the first line of stdin"
    )
    configure.add_argument("--ssid", help="the network to join; otherwise choose from a list")
    configure.add_argument(
        "--password-stdin",
        action="store_true",
        help="read the Wi-Fi password from stdin instead of asking for it",
    )
    configure.add_argument(
        "--timeout", type=float, default=30.0, help="seconds to wait for the device"
    )
    configure.set_defaults(run=_run_configure)

    scan = commands.add_parser("scan", help="list the Wi-Fi networks this machine can see")
    scan.add_argument(
        "--interface", metavar="NAME", help="the Wi-Fi adapter; by default the first one"
    )
    scan.set_defaults(run=_run_scan)

    join = commands.add_parser(
        "join", help="join a Wi-Fi network on this machine through NetworkManager (needs root)"
    )
    join.add_argument("--ssid", required=True, help="the network to join")
    join.add_argument(
        "--password-stdin",
        action="store_true",
        help="read the Wi-Fi password from stdin instead of asking; an empty one means open",
    )
    join.add_argument(
        "--interface", metavar="NAME", help="the Wi-Fi adapter; by default the first one"
    )
    join.set_defaults(run=_run_join)

    ap = commands.add_parser(
        "ap", help="make this machine a Wi-Fi access point for a while (needs root)"
    )
    ap.add_argument("--ssid", required=True, help="the name of the new Wi-Fi network")
    ap.add_argument(
        "--seconds", type=float, default=300, metavar="SECONDS", help="how long it stays up"
    )
    ap.add_argument(
        "--interface", metavar="NAME", help="the Wi-Fi adapter; by default the first one"
    )
    ap.set_defaults(run=_run_ap)
    return parser


# ----------------------------------------------------------------------------- init


def _run_init(args: argparse.Namespace) -> int:
    identity = DeviceIdentity.generate()
    try:
        identity.save(args.identity)
    except FileExistsError:
        print(f"{args.identity} already exists. An identity is never overwritten.", file=sys.stderr)
        return EXIT_BAD_INPUT
    uri = Ticket.from_identity(identity).to_uri()
    print(f"Created device {identity.device_id} in {args.identity}", file=sys.stderr)
    if args.ticket_out:
        try:
            _write_private(Path(args.ticket_out), uri + "\n")
        except FileExistsError:
            print(f"{args.ticket_out} already exists.", file=sys.stderr)
            return EXIT_BAD_INPUT
        print(f"Sticker ticket written to {args.ticket_out}", file=sys.stderr)
    else:
        print(uri)
    return EXIT_JOINED


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        file.write(text)


# --------------------------------------------------------------------------- device


def _run_device(args: argparse.Namespace) -> int:
    try:
        identity = DeviceIdentity.load(args.identity)
        host, port = _parse_address(args.listen)
        backend = _device_backend(args)
    except (OSError, IdentityError, ValueError) as error:
        print(f"Cannot start the device: {error}", file=sys.stderr)
        return EXIT_BAD_INPUT
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    with contextlib.suppress(AttributeError):  # show output at once, even when redirected
        sys.stdout.reconfigure(line_buffering=True)  # type: ignore[union-attr]
    asyncio.run(_serve_device(identity, backend, host, port, args.window))
    return EXIT_JOINED


async def _serve_device(
    identity: DeviceIdentity,
    backend: FakeBackend | NetworkManagerBackend,
    host: str,
    port: int,
    window_seconds: float,
) -> None:
    agent = DeviceAgent(identity, backend)
    if window_seconds > 0:
        await _serve_in_windows(identity, agent, backend, host, port, window_seconds)
        return
    server = await serve_tcp(agent.serve, host, port)
    address = server.sockets[0].getsockname()
    print(f"Device {identity.device_id} is listening on {address[0]}:{address[1]}")
    if isinstance(backend, FakeBackend):
        print(
            "It uses a fake Wi-Fi adapter: nothing on this machine will change. Pretend networks:"
        )
        for ssid, network in backend.networks.items():
            password = "open" if network.password is None else f"password: {network.password}"
            print(f"  {ssid} ({password})")
    else:
        print("It uses the Wi-Fi adapter of this machine, through NetworkManager.")
    async with server:
        await server.serve_forever()


async def _serve_in_windows(
    identity: DeviceIdentity,
    agent: DeviceAgent,
    backend: FakeBackend | NetworkManagerBackend,
    host: str,
    port: int,
    seconds: float,
) -> None:
    async def handle(transport: Transport) -> None:
        if await agent.serve(transport) is Outcome.CONNECTED:
            window.provisioned()

    async def has_network() -> bool:
        return await _has_network(backend)

    window = Window(
        lambda: serve_tcp(handle, host, port), has_network, seconds=seconds, grace=NETWORK_WAIT
    )
    reopen = asyncio.Event()
    # SIGUSR1 opens the window again. It stands in for a button on the device.
    with contextlib.suppress(NotImplementedError):
        asyncio.get_running_loop().add_signal_handler(signal.SIGUSR1, reopen.set)
    logging.getLogger(__name__).info(
        "device %s: the window opens for %s seconds when there is no network, "
        "and SIGUSR1 opens it again",
        identity.device_id,
        seconds,
    )
    force = False
    while True:
        await window.run(force=force)
        await reopen.wait()
        reopen.clear()
        force = True


async def _has_network(backend: FakeBackend | NetworkManagerBackend) -> bool:
    if isinstance(backend, FakeBackend):
        return backend.connected_to is not None
    try:
        status = await backend.status()
    except NetworkManagerError:
        return False
    return status.connected and status.ip is not None


def _fake_backend(secured: list[str] | None, open_networks: list[str] | None) -> FakeBackend:
    if not secured and not open_networks:
        return FakeBackend(DEMO_NETWORKS)
    networks: dict[str, FakeNetwork] = {}
    for spec in secured or []:
        ssid, separator, password = spec.partition("=")
        if not separator or not ssid or not password:
            raise ValueError(f"--fake-network wants NAME=PASSWORD, not {ssid!r}")
        networks[ssid] = FakeNetwork(password, signal=max(20, 80 - 10 * len(networks)))
    for ssid in open_networks or []:
        networks[ssid] = FakeNetwork(None, signal=max(20, 80 - 10 * len(networks)))
    return FakeBackend(networks)


def _device_backend(args: argparse.Namespace) -> FakeBackend | NetworkManagerBackend:
    if args.backend == "nm":
        if args.fake_network or args.fake_open_network:
            raise ValueError("--fake-network and --fake-open-network go with --backend fake")
        return NetworkManagerBackend(args.interface)
    return _fake_backend(args.fake_network, args.fake_open_network)


# ------------------------------------------------------------------------ configure


def _run_configure(args: argparse.Namespace) -> int:
    if args.ticket_stdin and args.password_stdin:
        print("Standard input can carry the ticket or the password, not both.", file=sys.stderr)
        return EXIT_BAD_INPUT
    try:
        ticket = _read_ticket(args)
        host, port = _parse_address(args.connect)
    except (OSError, TicketError, ValueError) as error:
        print(f"Cannot start: {error}", file=sys.stderr)
        return EXIT_BAD_INPUT
    return asyncio.run(_configure(args, ticket, host, port))


async def _configure(args: argparse.Namespace, ticket: Ticket, host: str, port: int) -> int:
    try:
        transport = await connect_tcp(host, port)
    except OSError:
        print(f"Could not reach a device at {host}:{port}.", file=sys.stderr)
        return EXIT_NO_DEVICE
    try:
        async with Configurator(ticket, transport, timeout=args.timeout) as phone:
            return await _provision(phone, args)
    except ProvisioningError as error:
        print(_describe(error), file=sys.stderr)
        return EXIT_NO_DEVICE


async def _provision(phone: Configurator, args: argparse.Namespace) -> int:
    networks = await phone.scan()
    if not networks:
        print("The device cannot see any Wi-Fi network.", file=sys.stderr)
        return EXIT_NOT_JOINED
    chosen = _choose(networks, args.ssid)
    if chosen is None:
        return EXIT_BAD_INPUT
    ssid, needs_password = chosen

    for attempt in range(1, MAX_PASSWORD_PROMPTS + 1):
        try:
            password = _ask_password(args) if needs_password else None
            credentials = WifiCredentials(ssid, Secret(password) if password is not None else None)
        except ValueError as error:
            print(error, file=sys.stderr)
            if args.password_stdin:
                return EXIT_BAD_INPUT
            continue
        result = await phone.join(credentials)
        if result.connected:
            print(f"Connected to {ssid}. The device's address is {result.ip}.")
            return EXIT_JOINED
        print(f"Could not join {ssid}. {describe_failure(result.failure)}", file=sys.stderr)
        if result.failure is not Failure.WRONG_PASSWORD or args.password_stdin:
            return EXIT_NOT_JOINED
        if attempt < MAX_PASSWORD_PROMPTS:
            print("Try again.", file=sys.stderr)
    return EXIT_NOT_JOINED


def _choose(networks: list[WifiNetwork], ssid: str | None) -> tuple[str, bool] | None:
    """Pick the network to join. Returns its name and whether it needs a password."""
    if ssid is not None:
        known = next((network for network in networks if network.ssid == ssid), None)
        return ssid, known is None or known.security is not Security.OPEN
    if not sys.stdin.isatty():
        print("Several networks are visible. Say which one with --ssid.", file=sys.stderr)
        return None
    for number, network in enumerate(networks, start=1):
        lock = "open" if network.security is Security.OPEN else "password"
        print(f"  {number}. {network.ssid}  (signal {network.signal}, {lock})")
    answer = input(f"Choose a network [1-{len(networks)}]: ").strip()
    if not answer.isdigit() or not 1 <= int(answer) <= len(networks):
        print("That is not one of the numbers in the list.", file=sys.stderr)
        return None
    picked = networks[int(answer) - 1]
    return picked.ssid, picked.security is not Security.OPEN


def _ask_password(args: argparse.Namespace) -> str:
    if args.password_stdin:
        line = sys.stdin.readline()
        if not line:
            raise ValueError("no password was provided on standard input")
        return line.rstrip("\r\n")
    return getpass.getpass("Wi-Fi password: ")


def _read_ticket(args: argparse.Namespace) -> Ticket:
    if args.ticket_file:
        text = Path(args.ticket_file).read_text(encoding="utf-8")
    elif args.ticket_stdin:
        text = sys.stdin.readline()
    else:
        text = getpass.getpass("Ticket from the sticker: ")
    return Ticket.from_uri(text)


def _describe(error: ProvisioningError) -> str:
    if isinstance(error, DeviceRefused):
        if error.reason is RejectReason.AUTH_FAILED:
            return "The device did not accept the setup code. Check the sticker and try again."
        if error.reason is RejectReason.LOCKED:
            minutes = max(1, -(-error.retry_after // 60))
            return (
                "The device is locked after too many wrong codes. "
                f"Try again in {minutes} minute(s)."
            )
        return "The device is busy with another phone. Try again in a moment."
    if isinstance(error, NotTheExpectedDevice):
        return "That is not the device on the sticker. You may be connected to a different device."
    if isinstance(error, DeviceUnreachable):
        return f"The device did not answer: {error}."
    return f"The device sent something unexpected: {error}."


def _parse_address(text: str) -> tuple[str, int]:
    host, separator, port = text.rpartition(":")
    if not separator or not host or not port.isdigit() or not 0 <= int(port) <= 65535:
        raise ValueError(f"an address looks like HOST:PORT, not {text!r}")
    return host, int(port)


# ----------------------------------------------------------------------------- scan


def _run_scan(args: argparse.Namespace) -> int:
    return asyncio.run(_scan(NetworkManagerBackend(args.interface)))


async def _scan(backend: NetworkManagerBackend) -> int:
    try:
        status = await backend.status()
        networks = await backend.scan()
    except NetworkManagerError as error:
        print(f"Cannot read the Wi-Fi adapter: {error}", file=sys.stderr)
        return EXIT_SCAN_FAILED
    if status.connected:
        print(f"Adapter {status.interface} is connected to {status.connection} ({status.ip})")
    else:
        print(f"Adapter {status.interface} is not connected")
    print("Networks in range, strongest first:")
    for number, network in enumerate(networks, start=1):
        print(f"  {number}. {network.ssid}  (signal {network.signal}, {network.security.value})")
    return EXIT_JOINED


# ----------------------------------------------------------------------------- join


def _run_join(args: argparse.Namespace) -> int:
    try:
        password = _ask_password(args)
        credentials = WifiCredentials(args.ssid, Secret(password) if password else None)
    except ValueError as error:
        print(error, file=sys.stderr)
        return EXIT_BAD_INPUT
    return asyncio.run(_join_network(NetworkManagerBackend(args.interface), credentials))


async def _join_network(backend: NetworkManagerBackend, credentials: WifiCredentials) -> int:
    try:
        result = await backend.connect(credentials)
    except NetworkManagerError as error:
        print(f"Cannot use the Wi-Fi adapter: {error}", file=sys.stderr)
        return EXIT_NOT_JOINED
    if result.connected:
        print(f"Connected to {credentials.ssid}. The address is {result.ip}.")
        return EXIT_JOINED
    print(f"Could not join {credentials.ssid}. {describe_failure(result.failure)}", file=sys.stderr)
    return EXIT_NOT_JOINED


# ------------------------------------------------------------------------------- ap


def _run_ap(args: argparse.Namespace) -> int:
    backend = NetworkManagerBackend(args.interface)
    return asyncio.run(_access_point(backend, args.ssid, args.seconds))


async def _access_point(backend: NetworkManagerBackend, ssid: str, seconds: float) -> int:
    try:
        address = await backend.start_access_point(ssid)
    except ValueError as error:
        print(error, file=sys.stderr)
        return EXIT_BAD_INPUT
    except NetworkManagerError as error:
        print(f"Cannot start the access point: {error}", file=sys.stderr)
        return EXIT_NOT_JOINED
    print(f"Access point {ssid} is up. This machine is at {address}.", flush=True)
    print(f"It stops in {seconds:g} seconds. Press Ctrl-C to stop it sooner.", flush=True)
    try:
        await asyncio.sleep(seconds)
    finally:
        await asyncio.shield(backend.stop_access_point())
    print("The access point is stopped.", flush=True)
    return EXIT_JOINED
