#!/usr/bin/env python3
"""Independently check the SM4th-EM public-key relation from the submitted KAT."""

from __future__ import annotations

import pathlib
import subprocess
import sys


def fields(path: pathlib.Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        if " = " not in line:
            continue
        key, value = line.split(" = ", 1)
        if key not in values:
            values[key] = value
    return values


def main() -> int:
    path = pathlib.Path(sys.argv[1])
    kat = fields(path)
    pk = bytes.fromhex(kat["PK"])
    sk = bytes.fromhex(kat["SK"])
    x, y = pk[:16], pk[16:]
    k = sk[16:]
    ciphertext = subprocess.check_output(
        ["openssl", "enc", "-sm4-ecb", "-K", x.hex(), "-nopad"],
        input=k,
    )
    expected = bytes(a ^ b for a, b in zip(ciphertext, k))
    print(f"source={path}")
    print(f"public_x={x.hex()}")
    print(f"secret_k={k.hex()}")
    print(f"sm4_x_k={ciphertext.hex()}")
    print(f"expected_y={expected.hex()}")
    print(f"submitted_y={y.hex()}")
    print(f"match={expected == y}")
    return 0 if expected == y else 1


if __name__ == "__main__":
    raise SystemExit(main())
