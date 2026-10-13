import base64
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote

import pytest

SCRIPT = Path(__file__).parent.parent / "scripts" / "leakcheck.py"
spec = importlib.util.spec_from_file_location("leakcheck", SCRIPT)
leakcheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(leakcheck)

SECRET = "correct horse 42"
CONTROL = "Add this device to Wi-Fi"
NOISE = bytes(range(256)) * 4
CLEAN = NOISE + CONTROL.encode()  # a recording with the control and no secret


def make_files(tmp_path, *, capture=CLEAN, secrets=(SECRET,)):
    (tmp_path / "capture.pcap").write_bytes(capture)
    (tmp_path / "secrets.txt").write_text("\n".join(secrets) + "\n", encoding="utf-8")
    return str(tmp_path / "capture.pcap")


def check(tmp_path, capsys, *files, controls=(CONTROL,)):
    arguments = ["--secrets", str(tmp_path / "secrets.txt")]
    for control in controls:
        arguments += ["--control", control]
    code = leakcheck.main([*arguments, *files])
    output = capsys.readouterr()
    return code, output.out + output.err


def test_it_passes_when_no_secret_is_there_and_the_control_is(tmp_path, capsys):
    capture = make_files(tmp_path)

    code, output = check(tmp_path, capsys, capture)

    assert code == 0
    assert "Secret 1 (16 characters): not found" in output
    assert f'Control "{CONTROL}": found 1 times' in output
    assert "OK" in output


def test_it_fails_when_a_secret_is_there(tmp_path, capsys):
    capture = make_files(tmp_path, capture=NOISE + b"pw=" + SECRET.encode() + CONTROL.encode())

    code, output = check(tmp_path, capsys, capture)

    assert code == 1
    assert "FOUND" in output
    assert "FAIL" in output


def test_it_finds_a_secret_that_is_percent_encoded(tmp_path, capsys):
    text = quote(SECRET, safe="").encode()
    capture = make_files(tmp_path, capture=NOISE + text + CONTROL.encode())

    code, _ = check(tmp_path, capsys, capture)

    assert code == 1


def test_it_finds_a_secret_that_is_written_as_json_text(tmp_path, capsys):
    secret = "Ward 的名字 abc"
    message = json.dumps({"ssid": secret}).encode()  # the Chinese characters become \u escapes
    capture = make_files(tmp_path, capture=NOISE + message + CONTROL.encode(), secrets=(secret,))

    code, _ = check(tmp_path, capsys, capture)

    assert code == 1


@pytest.mark.parametrize("offset", [0, 1, 2])
def test_it_finds_a_secret_in_base64_wherever_it_starts(tmp_path, capsys, offset):
    # Base64 codes the same text in another way when it starts at another place in a group.
    text = b"x" * offset + SECRET.encode() + b"yz"
    capture = make_files(tmp_path, capture=NOISE + base64.b64encode(text) + CONTROL.encode())

    code, _ = check(tmp_path, capsys, capture)

    assert code == 1


def test_it_fails_when_a_control_is_missing(tmp_path, capsys):
    capture = make_files(tmp_path, capture=NOISE)

    code, output = check(tmp_path, capsys, capture)

    assert code == 2
    assert "NOT FOUND" in output
    assert "proves nothing" in output


def test_a_leak_counts_even_when_a_control_is_missing(tmp_path, capsys):
    capture = make_files(tmp_path, capture=NOISE + SECRET.encode())

    code, _ = check(tmp_path, capsys, capture)

    assert code == 1


def test_it_never_prints_a_secret(tmp_path, capsys):
    leaking = make_files(tmp_path, capture=NOISE + SECRET.encode() + CONTROL.encode())
    _, output_when_found = check(tmp_path, capsys, leaking)
    clean = make_files(tmp_path)
    _, output_when_not_found = check(tmp_path, capsys, clean)

    assert SECRET not in output_when_found
    assert SECRET not in output_when_not_found


def test_it_searches_every_file_and_names_the_one_with_the_leak(tmp_path, capsys):
    first = make_files(tmp_path)
    second = tmp_path / "run.log"
    second.write_text(f"the password was {SECRET}\n", encoding="utf-8")

    code, output = check(tmp_path, capsys, first, str(second))

    assert code == 1
    assert "run.log" in output
    assert "capture.pcap" not in output


def test_it_refuses_a_secret_that_is_too_short(tmp_path, capsys):
    capture = make_files(tmp_path, secrets=("abc",))

    code, output = check(tmp_path, capsys, capture)

    assert code == 2
    assert "at least 6" in output


def test_it_refuses_a_file_that_is_not_there(tmp_path, capsys):
    make_files(tmp_path)

    code, output = check(tmp_path, capsys, str(tmp_path / "nothing.pcap"))

    assert code == 2
    assert "nothing.pcap" in output


def test_it_refuses_an_empty_list_of_secrets(tmp_path, capsys):
    capture = make_files(tmp_path, secrets=())

    code, output = check(tmp_path, capsys, capture)

    assert code == 2
    assert "empty" in output


def test_it_runs_as_a_script(tmp_path):
    capture = make_files(tmp_path)
    secrets = str(tmp_path / "secrets.txt")

    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--secrets", secrets, "--control", CONTROL, capture],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0
    assert "OK" in result.stdout
