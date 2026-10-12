#!/usr/bin/env bash
# Records what goes through the Wi-Fi adapter of this machine, to see what is on the air.
# Run it on the device while a configurator provisions it. It needs root and tcpdump.
#
#   sudo scripts/capture.sh [-i ADAPTER] [-s SECONDS] [-o FILE]
#
# The defaults are the first Wi-Fi adapter, 600 seconds and capture.pcap. Ctrl-C stops it sooner.
# Exit code 3 means the recording stopped by itself before the time was up. That happens when
# the adapter changes state, for example when the device opens or closes its own Wi-Fi network.
# Start it again to go on recording into another file.
# The device's own Wi-Fi network is open, so the adapter sees the same bytes that anyone
# nearby can pick up. To look for a word in the file (0 means it is not there):
#
#   grep -a -c -F 'the word' capture.pcap

set -u

interface=""
seconds=600
out="capture.pcap"

usage() {
    echo "Usage: sudo $0 [-i ADAPTER] [-s SECONDS] [-o FILE]" >&2
    exit 2
}

while getopts "i:s:o:" option; do
    case "$option" in
        i) interface=$OPTARG ;;
        s) seconds=$OPTARG ;;
        o) out=$OPTARG ;;
        *) usage ;;
    esac
done

if ! command -v tcpdump > /dev/null 2>&1; then
    echo "tcpdump is not installed. Install it with: sudo apt install tcpdump" >&2
    exit 1
fi
if [ -z "$interface" ]; then
    interface=$(nmcli -t -f DEVICE,TYPE device 2> /dev/null | awk -F: '$2 == "wifi" { print $1; exit }')
fi
if [ -z "$interface" ]; then
    echo "No Wi-Fi adapter found. Name it with -i." >&2
    exit 1
fi

umask 077 # the file shows who talked to the device, so only its owner may read it
echo "Recording $interface into $out for $seconds seconds. Press Ctrl-C to stop sooner."
tcpdump -i "$interface" -n -U -s 0 -w "$out" > /dev/null 2>&1 &
recorder=$!
interrupted=0
trap 'interrupted=1; kill "$recorder" 2> /dev/null' INT TERM

waited=0
while [ "$waited" -lt "$seconds" ] && [ "$interrupted" = 0 ]; do
    kill -0 "$recorder" 2> /dev/null || break
    sleep 1
    waited=$((waited + 1))
done

stopped_early=0
if [ "$waited" -lt "$seconds" ] && [ "$interrupted" = 0 ]; then
    stopped_early=1
fi
kill "$recorder" 2> /dev/null
wait "$recorder" 2> /dev/null
echo "Done. $(tcpdump -nr "$out" 2> /dev/null | wc -l | tr -d ' ') packets are in $out."
if [ "$stopped_early" = 1 ]; then
    echo "The recording stopped early. The adapter probably changed state." >&2
    exit 3
fi
