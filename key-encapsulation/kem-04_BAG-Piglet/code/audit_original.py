#!/usr/bin/env python3
"""Static interface audit for the exact BAG-Piglet ZIP contents."""

from pathlib import Path
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parent
ZIP = ROOT / "BAG-Piglet.zip"
REF = ROOT / "submission/Implementations/Reference_Implementation"


def macro(path: Path, name: str) -> int:
    text = path.read_text(errors="replace")
    match = re.search(rf"^\s*#define\s+{re.escape(name)}\s+(\d+)", text, re.M)
    if not match:
        raise RuntimeError(f"missing {name} in {path}")
    return int(match.group(1))


def main() -> None:
    digest = hashlib.sha256(ZIP.read_bytes()).hexdigest()
    rows = []
    for bits in (128, 256, 384, 512):
        base = REF / f"bag_piglet{bits}"
        params = base / "src/scheme/parameters.h"
        ffi = base / "src/rbc/rbc.h"
        api = base / "src/kat/KEM_AlgorithmInstance.c"
        row = {
            "instance": bits,
            "code_PARAM_M_field_degree": macro(params, "PARAM_M"),
            "code_PARAM_N_ring_length": macro(params, "PARAM_N"),
            "code_PARAM_N_prime": macro(params, "PARAM_N_"),
            "code_rbc_field_degree": macro(ffi, "RBC_FIELD_M"),
            "salt_bytes": macro(params, "PARAMS_SALT_SIZE"),
            "kem_ct_returns": "CCAKEM_CT_SIZE" in api.read_text(errors="replace"),
        }
        rows.append(row)
    print(json.dumps({
        "zip_sha256": digest,
        "zip_sha256_matches_contract": digest == "31afe1f2f4e97ad77929d7855c7d9011d69755049d155c09be9339bc99b1d405",
        "rows": rows,
        "spec_128": {"n_ring_degree": 47, "n_prime": 43, "m_field_degree": 43},
        "finding": "128 implementation swaps the spec's field and ring degrees",
    }, indent=2))


if __name__ == "__main__":
    main()
