#!/usr/bin/env python3
import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys


def parse_kat(path: pathlib.Path, count: int = 0) -> dict[str, str]:
    text = path.read_text(encoding="ascii")
    records = re.split(r"(?m)^Count = ", text)
    for record in records[1:]:
        number, body = record.split("\n", 1)
        if int(number) != count:
            continue
        values: dict[str, str] = {}
        for line in body.splitlines():
            match = re.match(r"^(PK|SK|M|Sn) = ([0-9A-F]+)$", line)
            if match:
                values[match.group(1)] = match.group(2)
        missing = {"PK", "M", "Sn"} - values.keys()
        if missing:
            raise ValueError(f"missing fields: {sorted(missing)}")
        return values
    raise ValueError(f"count {count} not found")


def flip_hex_byte(value: str, offset: int) -> str:
    raw = bytearray.fromhex(value)
    raw[offset] ^= 0x01
    return raw.hex().upper()


def run(binary: pathlib.Path, pk: str, sig: str, msg: str) -> dict:
    command = [str(binary), pk, sig, msg]
    proc = subprocess.run(command, text=True, capture_output=True)
    return {
        "returncode": proc.returncode,
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kat", type=pathlib.Path, required=True)
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--count", type=int, default=0)
    args = parser.parse_args()

    values = parse_kat(args.kat, args.count)
    signature = values["Sn"]
    sig_raw = bytes.fromhex(signature)

    # CS-128 fixed regions. Each 16-bit little-endian count is followed by the
    # only bytes consumed by rANS decoding; the remainder of each region is
    # fixed storage, not an encoded symbol.
    offsets = {
        "cwave": [0, 32],
        "z0_rans": [32, 272],
        "z1_low": [272, 848],
        "z1_rans": [848, 1393],
        "z2_rans": [1393, 1548],
    }
    counts = {
        "z0_rans": int.from_bytes(sig_raw[32:34], "little"),
        "z1_rans": int.from_bytes(sig_raw[848:850], "little"),
        "z2_rans": int.from_bytes(sig_raw[1393:1395], "little"),
    }
    unused = {
        name: start + 2 + counts[name]
        for name, (start, _end) in offsets.items()
        if name in counts
    }
    unused_ranges = {
        name: [offset, offsets[name][1] - 1]
        for name, offset in unused.items()
    }

    if any(offset >= offsets[name][1] for name, offset in unused.items()):
        raise ValueError(f"no unused suffix in at least one rANS segment: {unused_ranges}")

    tests = {
        "positive_original": run(args.binary, values["PK"], signature, values["M"]),
        "positive_mutated_unused_z0": run(
            args.binary,
            values["PK"],
            flip_hex_byte(signature, unused["z0_rans"]),
            values["M"],
        ),
        "positive_mutated_unused_z1": run(
            args.binary,
            values["PK"],
            flip_hex_byte(signature, unused["z1_rans"]),
            values["M"],
        ),
        "positive_mutated_unused_z2": run(
            args.binary,
            values["PK"],
            flip_hex_byte(signature, unused["z2_rans"]),
            values["M"],
        ),
        "negative_mutated_used_z0": run(
            args.binary,
            values["PK"],
            flip_hex_byte(signature, 34),
            values["M"],
        ),
        "negative_mutated_used_z1": run(
            args.binary,
            values["PK"],
            flip_hex_byte(signature, 850),
            values["M"],
        ),
        "negative_wrong_message": run(
            args.binary,
            values["PK"],
            signature,
            flip_hex_byte(values["M"], 0),
        ),
    }

    result = {
        "kat": str(args.kat),
        "kat_sha256": hashlib.sha256(args.kat.read_bytes()).hexdigest(),
        "count": args.count,
        "binary": str(args.binary),
        "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        "signature_bytes": len(sig_raw),
        "ranges": offsets,
        "declared_rans_counts": counts,
        "first_unused_offsets": unused,
        "unused_ranges": unused_ranges,
        "tests": tests,
        "all_expected": (
            tests["positive_original"]["returncode"] == 0
            and tests["positive_mutated_unused_z0"]["returncode"] == 0
            and tests["positive_mutated_unused_z1"]["returncode"] == 0
            and tests["positive_mutated_unused_z2"]["returncode"] == 0
            and tests["negative_mutated_used_z0"]["returncode"] == 1
            and tests["negative_mutated_used_z1"]["returncode"] == 1
            and tests["negative_wrong_message"]["returncode"] == 1
        ),
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result["all_expected"] else 1


if __name__ == "__main__":
    sys.exit(main())
