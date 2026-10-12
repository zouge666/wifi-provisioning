#!/usr/bin/env bash
# Installs the device agent as a systemd service.
# Run it as root, from anywhere: sudo deploy/install.sh
# To remove it again: systemctl disable --now wifiprov-device, then delete
# /etc/systemd/system/wifiprov-device.service, /opt/wifiprov and /var/lib/wifiprov.
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this as root: sudo $0" >&2
    exit 1
fi

project=$(cd "$(dirname "$0")/.." && pwd)
state=/var/lib/wifiprov

# This step needs the internet, to download the Python packages. Ubuntu does not
# always have the venv module, so it is installed when it is missing.
if ! python3 -c "import ensurepip" 2> /dev/null; then
    apt-get install -y python3-venv
fi
python3 -m venv /opt/wifiprov
/opt/wifiprov/bin/pip install --quiet "$project"
install -m 644 "$project/deploy/wifiprov-device.service" /etc/systemd/system/

# The identity is made once. Installing again keeps it.
install -d -m 700 "$state"
if [ ! -e "$state/identity.json" ]; then
    /opt/wifiprov/bin/wifiprov init --identity "$state/identity.json" --ticket-out "$state/ticket.txt"
fi

systemctl daemon-reload
systemctl enable wifiprov-device.service
systemctl restart wifiprov-device.service
echo "The agent is running. Its log: journalctl -u wifiprov-device"
echo "The text for the sticker, with the setup code in it, is in $state/ticket.txt"
