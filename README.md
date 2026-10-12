# wifi-provisioning

Offline Wi-Fi provisioning for headless Linux devices.

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
