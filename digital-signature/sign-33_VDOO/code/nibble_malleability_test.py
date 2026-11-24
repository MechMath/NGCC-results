#!/usr/bin/env python3
"""Reproduce VDOO-128 unused-nibble signature malleability on KAT vector 0."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent
KAT = ROOT / "source-vdoo/Test_Vectors/KAT_SIG_VDOO-128.txt"
VERIFIER = ROOT / "vdoo-verif"


def read_first_vector() -> dict[str, str]:
    values: dict[str, str] = {}
    with KAT.open(encoding="ascii") as handle:
        for line in handle:
            if " = " not in line:
                continue
            key, value = line.rstrip("\n").split(" = ", 1)
            values[key] = value
            if key == "Sn":
                return values
    raise RuntimeError("KAT vector 0 is incomplete")


def write_inputs(values: dict[str, str]) -> tuple[bytes, str]:
    (ROOT / "pk.hex").write_text(f"PK = {values['PK']}\n", encoding="ascii")
    (ROOT / "sk.hex").write_text(f"SK = {values['SK']}\n", encoding="ascii")
    message = bytes.fromhex(values["M"])
    (ROOT / "msg.bin").write_bytes(message)
    return message, values["Sn"]


def verify(signature_hex: str) -> tuple[int, str]:
    signature_file = ROOT / "candidate-signature.hex"
    signature_file.write_text(
        f"VDOO-128 signature = {signature_hex}\n", encoding="ascii"
    )
    result = subprocess.run(
        [str(VERIFIER), "pk.hex", signature_file.name, "msg.bin"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode, result.stdout + result.stderr


def main() -> None:
    values = read_first_vector()
    _, signature_hex = write_inputs(values)
    signature = bytearray.fromhex(signature_hex)

    # VDOO-128 has N=137 GF(16) coordinates in N_BYTE=69 bytes.
    # Coordinate 136 is the low nibble of byte 68; the high nibble is unused.
    assert len(signature) == 85
    assert signature[68] >> 4 == 0

    high_nibble_results = []
    for value in range(16):
        candidate = bytearray(signature)
        candidate[68] = (value << 4) | (candidate[68] & 0x0F)
        code, output = verify(candidate.hex())
        high_nibble_results.append(
            {
                "unused_high_nibble": value,
                "signature_byte_68": candidate[68],
                "accepted": code == 0,
                "exit_code": code,
            }
        )

    # Negative control: changing the low nibble changes coordinate 136 itself.
    negative_controls = []
    for value in range(16):
        candidate = bytearray(signature)
        candidate[68] = (candidate[68] & 0xF0) | value
        code, output = verify(candidate.hex())
        negative_controls.append(
            {
                "used_low_nibble": value,
                "signature_byte_68": candidate[68],
                "accepted": code == 0,
                "exit_code": code,
            }
        )

    report = {
        "kat": str(KAT.relative_to(ROOT)),
        "kat_count": 0,
        "message_hex": values["M"],
        "original_signature_hex": signature_hex,
        "signature_bytes": len(signature),
        "field_elements": 137,
        "final_coordinate": 136,
        "final_coordinate_byte": 68,
        "final_coordinate_nibble": "low",
        "high_nibble_results": high_nibble_results,
        "low_nibble_negative_controls": negative_controls,
    }
    (ROOT / "nibble_malleability_results.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="ascii"
    )
    print(
        json.dumps(
            {
                "accepted_distinct_high_nibbles": sum(
                    row["accepted"] for row in high_nibble_results
                ),
                "accepted_low_nibble_negative_controls": sum(
                    row["accepted"] for row in negative_controls
                ),
                "high_nibble_acceptance": [
                    row["unused_high_nibble"]
                    for row in high_nibble_results
                    if row["accepted"]
                ],
                "low_nibble_acceptance": [
                    row["used_low_nibble"]
                    for row in negative_controls
                    if row["accepted"]
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
