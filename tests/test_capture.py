import os
import stat
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).parent.parent / "scripts" / "capture.sh"

# A tcpdump that writes down how it was called. Recording makes a file and waits to be stopped,
# reading a file prints two lines.
FAKE_TCPDUMP = """#!/bin/bash
echo "$@" >> "$FAKE_LOG"
if [ "$1" = "-nr" ]; then
    printf 'packet one\\npacket two\\n'
    exit 0
fi
while [ $# -gt 0 ]; do
    [ "$1" = "-w" ] && out=$2
    shift
done
echo data > "$out"
[ "$FAKE_DIES" = 1 ] && exit 1
exec sleep 30
"""


def tools(tmp_path, *, tcpdump=True, adapters="enp1s0:ethernet\n"):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    if tcpdump:
        (bin_dir / "tcpdump").write_text(FAKE_TCPDUMP)
        (bin_dir / "tcpdump").chmod(0o755)
    # A pretend nmcli, so that the machine the test runs on does not matter.
    (bin_dir / "nmcli").write_text(f"#!/bin/bash\nprintf '{adapters}'\n")
    (bin_dir / "nmcli").chmod(0o755)
    return bin_dir


def run(tmp_path, bin_dir, *arguments, dies=False):
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:/usr/bin:/bin",
        "FAKE_LOG": str(tmp_path / "calls.txt"),
        "FAKE_DIES": "1" if dies else "0",
    }
    return subprocess.run(
        ["/bin/bash", str(SCRIPT), *arguments],
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
        timeout=30,
    )


def test_it_records_the_named_adapter_into_the_file(tmp_path):
    result = run(tmp_path, tools(tmp_path), "-i", "wlan9", "-s", "1", "-o", "air.pcap")

    assert result.returncode == 0
    calls = (tmp_path / "calls.txt").read_text()
    assert "-i wlan9" in calls
    assert "-w air.pcap" in calls
    assert "-s 0" in calls  # whole packets, not only their headers
    assert "2 packets are in air.pcap" in result.stdout
    assert stat.S_IMODE((tmp_path / "air.pcap").stat().st_mode) == 0o600


def test_without_a_name_it_uses_the_wifi_adapter_that_networkmanager_lists(tmp_path):
    result = run(tmp_path, tools(tmp_path, adapters="enp1s0:ethernet\\nwlan7:wifi\\n"), "-s", "1")

    assert result.returncode == 0
    assert "-i wlan7" in (tmp_path / "calls.txt").read_text()
    assert (tmp_path / "capture.pcap").exists()  # the default file name


def test_without_tcpdump_it_says_how_to_get_it(tmp_path):
    result = subprocess.run(
        ["/bin/bash", str(SCRIPT), "-i", "wlan0"],
        capture_output=True,
        text=True,
        env={"PATH": str(tmp_path)},  # nothing to find here
        cwd=tmp_path,
        timeout=30,
    )
    assert result.returncode == 1
    assert "sudo apt install tcpdump" in result.stderr


def test_an_unknown_option_shows_how_to_use_it(tmp_path):
    result = run(tmp_path, tools(tmp_path), "-x")
    assert result.returncode == 2
    assert "Usage:" in result.stderr


def test_without_a_wifi_adapter_it_asks_for_a_name(tmp_path):
    result = run(tmp_path, tools(tmp_path))  # only a cable adapter, and no -i
    assert result.returncode == 1
    assert "Name it with -i" in result.stderr


def test_a_recording_that_stops_by_itself_is_reported_and_keeps_what_it_got(tmp_path):
    result = run(tmp_path, tools(tmp_path), "-i", "wlan9", "-s", "20", "-o", "air.pcap", dies=True)

    assert result.returncode == 3  # long before the 20 seconds were over
    assert "stopped early" in result.stderr
    assert (tmp_path / "air.pcap").exists()
