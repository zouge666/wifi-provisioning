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
