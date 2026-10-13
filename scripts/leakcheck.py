#!/usr/bin/env python3
"""Look for secrets in a recording or a log.

  python3 scripts/leakcheck.py --secrets secrets.txt --control "some text" capture.pcap run.log

secrets.txt has one secret on each line. Examples are the Wi-Fi password, the network name
and the setup code. The files after the options are searched. Any kind of file is fine.

I look for each secret as it is, as JSON text, percent-encoded and in base64.
I never print a secret, only how long it is.

A control is a text that is in the files for sure. The device sends it in clear.
The title of the web page is a good one. If a control is not found, the search proves
nothing, so the check fails.

Exit code 0: no secret was found and every control was found.
Exit code 1: a secret is in a file.
Exit code 2: bad input, or a control is missing.
"""

import argparse
import base64
import json
import sys
from pathlib import Path
from urllib.parse import quote

MIN_LENGTH = 6  # a shorter text would be found by chance


def base64_forms(raw: bytes) -> list[bytes]:
    # Base64 codes groups of 3 bytes. In a longer text the secret can start at any place
    # in a group. Each start gives other characters. Some characters at the start and the end
    # depend on the bytes next to the secret. I leave them out.
    forms = []
    for shift, skip in ((0, 0), (1, 2), (2, 3)):
        encoded = base64.b64encode(b"\0" * shift + raw).rstrip(b"=")
        forms.append(encoded[skip:-2])
    return forms


def forms_of(secret: str) -> dict[str, list[bytes]]:
    raw = secret.encode()
    return {
        "as it is": [raw],
        "as JSON text": [json.dumps(secret)[1:-1].encode()],
        "percent-encoded": [quote(secret, safe="").encode()],
        "in base64": base64_forms(raw),
    }


def read_secrets(path: Path) -> list[str]:
    secrets = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]
    return [secret for secret in secrets if secret]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Look for secrets in a recording or a log.")
    parser.add_argument("files", nargs="+", help="the recordings and logs to search")
    parser.add_argument("--secrets", required=True, help="a file with one secret on each line")
    parser.add_argument(
        "--control", action="append", default=[], help="a text that must be found, can be repeated"
    )
    args = parser.parse_args(argv)

    try:
        secrets = read_secrets(Path(args.secrets))
        contents = {name: Path(name).read_bytes() for name in args.files}
    except OSError as error:
        print(f"Cannot read {error.filename}: {error.strerror}", file=sys.stderr)
        return 2
    if not secrets:
        print("The secrets file is empty.", file=sys.stderr)
        return 2
    for number, secret in enumerate(secrets, 1):
        if len(secret) < MIN_LENGTH:
            print(
                f"Secret {number} has {len(secret)} characters. "
                f"Use at least {MIN_LENGTH}, or the search finds it by chance.",
                file=sys.stderr,
            )
            return 2

    megabytes = sum(len(data) for data in contents.values()) / 1_000_000
    print(f"Searched {len(contents)} files, {megabytes:.1f} MB.")

    leaked = False
    for number, secret in enumerate(secrets, 1):
        hits = []
        for form, patterns in forms_of(secret).items():
            for name, data in contents.items():
                count = sum(data.count(pattern) for pattern in patterns)
                if count:
                    hits.append(f"{form}, in {name}, {count} times")
        if hits:
            leaked = True
            print(f"Secret {number} ({len(secret)} characters): FOUND, " + "; ".join(hits))
        else:
            print(f"Secret {number} ({len(secret)} characters): not found")

    missing = False
    for control in args.control:
        count = sum(data.count(control.encode()) for data in contents.values())
        if count:
            print(f'Control "{control}": found {count} times')
        else:
            missing = True
            print(f'Control "{control}": NOT FOUND')

    if leaked:
        print("FAIL: a secret is in the files.")
        return 1
    if missing:
        print("FAIL: a control was not found, so this search proves nothing.")
        return 2
    print("OK: no secret was found, and every control was found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
