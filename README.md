# wifi-provisioning

Offline Wi-Fi provisioning for headless Linux devices.

## Setup

Requires [uv](https://docs.astral.sh/uv/). Supports Python 3.10 and newer.

```bash
uv sync
uv run pytest
uv run ruff check .
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
