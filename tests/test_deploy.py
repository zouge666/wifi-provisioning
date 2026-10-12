import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

from wifiprov.cli import _build_parser

DEPLOY = Path(__file__).parent.parent / "deploy"


def service_settings():
    settings = {}
    for line in (DEPLOY / "wifiprov-device.service").read_text().splitlines():
        if "=" in line and not line.startswith(("#", "[")):
            name, _, value = line.partition("=")
            settings[name] = value
    return settings


def test_the_service_runs_a_command_the_program_really_has():
    command = shlex.split(service_settings()["ExecStart"])
    args = _build_parser().parse_args(command[1:])
    assert (args.command, args.backend) == ("device", "nm")
    assert args.window > 0  # the device must not listen all the time
    assert args.access_point  # and it talks to configurators over its own Wi-Fi network


def test_the_service_is_locked_down_and_comes_back_after_a_crash():
    settings = service_settings()
    wanted = {
        "Restart": "on-failure",
        "NoNewPrivileges": "yes",
        "CapabilityBoundingSet": "",
        "ProtectSystem": "strict",
        "ProtectHome": "yes",
        "PrivateTmp": "yes",
        "UMask": "0077",
    }
    for name, value in wanted.items():
        assert settings.get(name) == value, name


def test_the_service_keeps_its_state_where_only_root_can_read_it():
    settings = service_settings()
    assert settings["StateDirectory"] == "wifiprov"
    assert settings["StateDirectoryMode"] == "0700"
    assert "/var/lib/wifiprov/" in settings["ExecStart"]


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_the_install_script_is_valid_shell():
    script = DEPLOY / "install.sh"
    subprocess.run(["bash", "-n", str(script)], check=True)
    assert os.access(script, os.X_OK)
