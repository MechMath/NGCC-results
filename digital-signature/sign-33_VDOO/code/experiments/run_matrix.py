#!/usr/bin/env python3
"""Run a focused malformed-signature matrix against the unmodified VDOO-128 CLIs."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "experiments" / "vdoo128_matrix"
REF = ROOT / "builds" / "ref"
OPT = ROOT / "builds" / "opt"
EXPECTED_ZIP_SHA256 = "4b7bb0f15388b395b9308ae480f25622105a734f0ab4a6bd16398438c4b9752a"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(argv: list[str], *, cwd: Path = OUT) -> dict:
    completed = subprocess.run(argv, cwd=cwd, capture_output=True)
    return {
        "argv": argv,
        "cwd": str(cwd),
        "exit": completed.returncode,
        "stdout": completed.stdout.decode("utf-8", "replace"),
        "stderr": completed.stderr.decode("utf-8", "replace"),
    }


def signature_hex(stdout: str) -> bytes:
    match = re.search(r"^VDOO-128 signature = ([0-9a-f]+)\s*$", stdout, re.MULTILINE)
    if not match:
        raise RuntimeError(f"signature line absent from stdout: {stdout!r}")
    return bytes.fromhex(match.group(1))


def write_signature(path: Path, signature: bytes, trailing: bytes = b"") -> None:
    text = f"VDOO-128 signature = {signature.hex()}\n".encode("ascii")
    path.write_bytes(text + trailing)


def main() -> int:
    if sha256(ROOT / "source" / "VDOO.zip") != EXPECTED_ZIP_SHA256:
        raise RuntimeError("original ZIP SHA256 mismatch")
    OUT.mkdir(parents=True, exist_ok=True)

    # A fixed 48-byte zero seed makes key generation reproducible. Signing uses
    # the original RNG and intentionally produces fresh randomized salts.
    (OUT / "keygen_seed.bin").write_bytes(bytes(48))
    (OUT / "message.bin").write_bytes(b"VDOO-128 malformed-input matrix message\n")
    (OUT / "changed_message.bin").write_bytes(b"VDOO-128 malformed-input matrix messagf\n")

    records: list[dict] = []
    records.append(run([str(REF / "vdoo-keygen"), "pk.txt", "sk.txt", "keygen_seed.bin"]))
    records.append(run([str(REF / "vdoo-sign"), "sk.txt", "message.bin"], cwd=OUT))
    ref_sig_a = signature_hex(records[-1]["stdout"])
    records.append(run([str(REF / "vdoo-sign"), "sk.txt", "message.bin"], cwd=OUT))
    ref_sig_b = signature_hex(records[-1]["stdout"])
    records.append(run([str(OPT / "vdoo-sign"), "sk.txt", "message.bin"], cwd=OUT))
    opt_sig = signature_hex(records[-1]["stdout"])

    if len(ref_sig_a) != 85 or len(ref_sig_b) != 85 or len(opt_sig) != 85:
        raise RuntimeError("unexpected VDOO-128 signature length")

    changed_message_sig = bytearray(ref_sig_a)
    changed_salt_sig = bytearray(ref_sig_a)
    changed_salt_sig[69] ^= 1  # salt starts at byte 69
    changed_field_sig = bytearray(ref_sig_a)
    changed_field_sig[0] ^= 1
    unused_nibble_sig = bytearray(ref_sig_a)
    unused_nibble_sig[68] ^= 0x10  # N=137 leaves high nibble unused

    cases: dict[str, tuple[Path, Path, bytes]] = {
        "positive_ref_sig_ref_verify": (Path("message.bin"), Path("sig_ref_a.txt"), ref_sig_a),
        "positive_opt_sig_ref_verify": (Path("message.bin"), Path("sig_opt.txt"), opt_sig),
        "control_changed_message": (Path("changed_message.bin"), Path("sig_changed_message.txt"), bytes(changed_message_sig)),
        "control_changed_salt": (Path("message.bin"), Path("sig_changed_salt.txt"), bytes(changed_salt_sig)),
        "control_changed_field_byte": (Path("message.bin"), Path("sig_changed_field.txt"), bytes(changed_field_sig)),
        "boundary_unused_high_nibble_changed": (Path("message.bin"), Path("sig_unused_nibble.txt"), bytes(unused_nibble_sig)),
        "boundary_truncated_84_bytes": (Path("message.bin"), Path("sig_truncated.txt"), ref_sig_a[:-1]),
    }
    for _, (_, sig_path, signature) in cases.items():
        write_signature(OUT / sig_path, signature)
    write_signature(OUT / "sig_extra_1_byte.txt", ref_sig_a, b"X")
    write_signature(OUT / "sig_extra_16_bytes.txt", ref_sig_a, bytes(range(16)))
    write_signature(OUT / "sig_extra_1024_bytes.txt", ref_sig_a, b"A" * 1024)
    write_signature(OUT / "sig_extra_hex.txt", ref_sig_a, b"00" * 32)
    cases["boundary_extra_1_byte"] = (Path("message.bin"), Path("sig_extra_1_byte.txt"), ref_sig_a)
    cases["boundary_extra_16_bytes"] = (Path("message.bin"), Path("sig_extra_16_bytes.txt"), ref_sig_a)
    cases["boundary_extra_1024_bytes"] = (Path("message.bin"), Path("sig_extra_1024_bytes.txt"), ref_sig_a)
    cases["boundary_extra_hex_32_bytes"] = (Path("message.bin"), Path("sig_extra_hex.txt"), ref_sig_a)

    # Retain the exact duplicate-sign comparison. Fresh salts should make the
    # signatures differ while both remain valid.
    duplicate = {
        "signature_a_hex": ref_sig_a.hex(),
        "signature_b_hex": ref_sig_b.hex(),
        "equal": ref_sig_a == ref_sig_b,
    }

    # First save the reference duplicate for an independent verification.
    write_signature(OUT / "sig_ref_b.txt", ref_sig_b)
    cases["positive_duplicate_signing_b"] = (Path("message.bin"), Path("sig_ref_b.txt"), ref_sig_b)

    results: dict[str, dict] = {}
    for name, (message, sig_path, _) in cases.items():
        observations = {}
        for verifier in ("ref", "opt"):
            observations[verifier] = run(
                [str(REF.parent / verifier / "vdoo-verif"), "pk.txt", str(sig_path), str(message)],
                cwd=OUT,
            )
        results[name] = {
            "signature_sha256": sha256(OUT / sig_path),
            "message_sha256": sha256(OUT / message),
            "observations": observations,
            "accepted_by": [
                verifier for verifier, obs in observations.items() if obs["exit"] == 0
            ],
        }

    report = {
        "source_zip_sha256": sha256(ROOT / "source" / "VDOO.zip"),
        "keygen_pk_sha256": sha256(OUT / "pk.txt"),
        "keygen_sk_sha256": sha256(OUT / "sk.txt"),
        "keygen_seed_sha256": sha256(OUT / "keygen_seed.bin"),
        "message_sha256": sha256(OUT / "message.bin"),
        "changed_message_sha256": sha256(OUT / "changed_message.bin"),
        "duplicate_signing": duplicate,
        "setup_and_signing_commands": records,
        "matrix": results,
        "interpretation_limits": [
            "CLI execution verifies VDOO-128 reference and AVX2-optimized binaries built from the original ZIP.",
            "Extra-byte acceptance is an observed property of the supplied vdoo-verif file parser and may not apply to callers that pass exact lengths.",
            "The unused high nibble of signature byte 68 is ignored by the original packed-GF(16) accessor; this is an actual crypto_sign_open API input alias.",
            "No claim is made that accepting a noncanonical encoding reaches NGCC Low without the original criterion.",
        ],
    }
    (OUT / "matrix_results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({
        name: {
            "accepted_by": value["accepted_by"],
            "exit": {k: v["exit"] for k, v in value["observations"].items()},
        }
        for name, value in results.items()
    }, indent=2))
    print("duplicate_signatures_equal", duplicate["equal"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
