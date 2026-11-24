#!/usr/bin/env python3
import argparse
import json
import pathlib
import re
import subprocess
import sys


def parse_kat_first(path: pathlib.Path) -> dict[str, str]:
    text = path.read_text(encoding="ascii")
    values = {}
    for line in text.splitlines():
        match = re.match(r"^(PK|SK) = ([0-9A-F]+)$", line)
        if match:
            values[match.group(1)] = match.group(2)
        if "PK" in values and "SK" in values:
            return values
    raise ValueError("PK/SK not found")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kat", type=pathlib.Path, required=True)
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()

    values = parse_kat_first(args.kat)
    proc = subprocess.run(
        [str(args.binary), values["PK"], values["SK"]],
        text=True,
        capture_output=True,
        timeout=300,
    )
    fields = {}
    for line in proc.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            fields[key] = value
    result = {
        "kat": str(args.kat),
        "binary": str(args.binary),
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "fields": fields,
        "expected": {
            "short_len": "1",
            "long_len": str(2**32 + 1),
            "short_verify": "0",
            "long_verify": "0",
            "mutated_distinct_signature_long_verify": "0",
            "changed_first_long_verify": "1",
        },
    }
    result["all_expected"] = all(
        fields.get(key) == value for key, value in result["expected"].items()
    )
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    printable = {k: v for k, v in result.items() if k != "stdout"}
    printable["stdout_lines_except_signature"] = [
        line for line in proc.stdout.splitlines() if not line.startswith("signature=")
    ]
    print(json.dumps(printable, indent=2))
    return 0 if result["all_expected"] else 1


if __name__ == "__main__":
    sys.exit(main())
