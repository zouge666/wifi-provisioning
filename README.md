# wifi-provisioning

Offline Wi-Fi provisioning for headless Linux devices.

The design, a real run with photos and the trade-offs are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Setup

Requires [uv](https://docs.astral.sh/uv/). Supports Python 3.10 and newer.

```bash
uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

The configurator for the browser is in `web/`. It needs Node 22.18 or newer. The protocol is
described in [docs/PROTOCOL.md](docs/PROTOCOL.md), and both implementations are tested against
`protocol/vectors.json`.

```bash
cd web && npm ci && npm test
cd web && npm run test:e2e   # the browser code against the real device, needs uv
```

## Local demo

Two terminals on one machine, no hardware: the device uses a fake Wi-Fi adapter.

```bash
uv run wifiprov init --identity state/identity.json --ticket-out state/ticket.txt
uv run wifiprov device --identity state/identity.json
```

In the second terminal:

```bash
uv run wifiprov configure --ticket-file state/ticket.txt
```

## Phone page

The device can also serve a web page for the configurator. Start the demo with a web port:

```bash
uv run wifiprov device --identity state/identity.json --web-port 8080
```

Open `http://127.0.0.1:8080/` in a browser and paste the text from `state/ticket.txt`. A link
with that text after a `#` skips the pasting.

The page is built from `web/src/main.ts` into `src/wifiprov/web/app.js`. The built file is
committed, because the device has no Node. After a change in `web/src`:

```bash
cd web && npm run build
```

## On a device

I tested this on Ubuntu 24.04 with NetworkManager. The Wi-Fi adapter must be able to make a hotspot. Run `scripts/check-hardware.sh` to check your computer.

Install the service. You need the internet one time, to download the Python packages:

```bash
sudo deploy/install.sh
```

When the device has no network, it makes its own Wi-Fi for 10 minutes. The name is `wifiprov-` and the device ID. If the device already has a network, you can open it yourself:

```bash
sudo systemctl kill --kill-whom=main -s SIGUSR1 wifiprov-device
```

The text for the sticker is in `/var/lib/wifiprov/ticket.txt`. Only root can read it. The QR code on the sticker is a link to the page: `http://10.42.0.1:8080/#` and then this text. Copy the file to your computer, then make the QR code:

```bash
uvx --from segno==1.6.1 segno --scale 10 --error m -o sticker.png "http://10.42.0.1:8080/#$(cat ticket.txt)"
```

The picture has the setup code in it. Keep it private, like the sticker. The steps on the phone are in [docs/TECHNICIAN.md](docs/TECHNICIAN.md).

## Assumptions

I do not know the real hardware of the devices, so I assume as little as I can:

- The device runs Ubuntu with NetworkManager and has a Wi-Fi adapter that can make a hotspot.
- I do not rely on a screen, a button, a light, a camera or Bluetooth on the device.
- The device has no network the first time. It opens its own Wi-Fi after about 30 seconds.
- The Wi-Fi network to join uses a password or is open. Enterprise Wi-Fi is not supported.

The full list is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#6-assumptions).
