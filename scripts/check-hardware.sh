#!/usr/bin/env bash
# Checks if this machine can run the device side of wifi-provisioning.
# It only reads information and never changes a setting.
# Exit code: 0 if all required checks pass, 1 if one of them fails.

fails=0
warns=0

ok()   { echo "[ ok ]  $1"; }
warn() { echo "[warn]  $1"; warns=$((warns + 1)); }
fail() { echo "[FAIL]  $1"; fails=$((fails + 1)); }
have() { command -v "$1" >/dev/null 2>&1; }

echo "== System =="
os=$(grep '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"')
echo "OS:      ${os:-unknown}"
echo "Kernel:  $(uname -r)"
echo "Machine: $(cat /sys/class/dmi/id/product_name 2>/dev/null || echo unknown)"

echo
echo "== NetworkManager and Wi-Fi =="
if have nmcli; then
    ok "$(nmcli --version)"
    if systemctl is-active --quiet NetworkManager; then
        ok "NetworkManager is running"
    else
        fail "NetworkManager is not running"
    fi
    wifi=$(nmcli -t -f DEVICE,TYPE device | awk -F: '$2 == "wifi" { print $1 }' | paste -sd ' ' -)
    if [ -n "$wifi" ]; then
        ok "Wi-Fi adapter: $wifi"
    else
        fail "NetworkManager sees no Wi-Fi adapter"
    fi
else
    fail "nmcli not found (sudo apt install network-manager)"
fi

# Access point mode is only needed if the channel is a hotspot instead of Bluetooth.
if have iw; then
    if iw list | grep -A12 "Supported interface modes" | grep -Eq '\* AP[[:space:]]*$'; then
        ok "Wi-Fi card supports access point mode"
    else
        warn "Wi-Fi card does not list access point mode"
    fi
else
    warn "iw not found, cannot check access point mode (sudo apt install iw)"
fi

echo
echo "== Bluetooth =="
if ! have bluetoothctl; then
    fail "bluetoothctl not found (sudo apt install bluez)"
elif ! timeout 5 bluetoothctl list | grep -q '^Controller'; then
    fail "no Bluetooth controller found"
else
    ok "Bluetooth controller found"
    if timeout 5 bluetoothctl show | grep -q 'Powered: yes'; then
        ok "controller is powered on"
    else
        warn "controller is powered off (try: bluetoothctl power on)"
    fi
    # The device code needs these two BlueZ interfaces. hci0 is the first adapter.
    tree=$(busctl introspect org.bluez /org/bluez/hci0 2>/dev/null)
    if echo "$tree" | grep -q 'org.bluez.GattManager1'; then
        ok "BlueZ can host a GATT service"
    else
        fail "BlueZ has no GATT manager on hci0"
    fi
    if echo "$tree" | grep -q 'org.bluez.LEAdvertisingManager1'; then
        ok "BlueZ can advertise over Bluetooth LE"
    else
        fail "BlueZ has no LE advertising manager on hci0"
    fi
fi

echo
echo "== Radios =="
if have rfkill; then
    if rfkill list | grep -q 'blocked: yes'; then
        fail "a radio is blocked, see: rfkill list"
    else
        ok "no radio is blocked"
    fi
else
    warn "rfkill not found"
fi

echo
echo "== Tools =="
for tool in git python3 uv; do
    if have "$tool"; then
        ok "$($tool --version 2>&1 | head -n 1)"
    else
        warn "$tool not found"
    fi
done

echo
if [ "$fails" -gt 0 ]; then
    echo "Result: $fails check(s) failed, $warns warning(s)."
    exit 1
fi
echo "Result: all required checks passed, $warns warning(s)."
