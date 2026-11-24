#!/usr/bin/env python3
"""Check the pinned input hash and the exploratory Wish audit invariants."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


EXPECTED_PDF_SHA256 = "a84b946a93f0fe772c1b08d29c90f894d928ea13cef9ee6ed1fd2fdee118dd2c"
EXPECTED_REPORT_SHA256 = "73827f995fdc5b6e6f7da6d2c1d8f247af3e60bceaf6e457fcb3f3751bb05fbd"


def sha256(path: str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main() -> None:
    assert sha256("hash-35-spec.pdf") == EXPECTED_PDF_SHA256
    assert sha256("wish_ref_report.json") == EXPECTED_REPORT_SHA256

    report = json.loads(Path("wish_ref_report.json").read_text())
    audit = report["audit"]
    assert audit["sbox_bijection"]
    assert audit["sbox_inverse"]
    assert audit["sbox_known_values"] == {"00": "63", "53": "ed", "ff": "16"}
    assert audit["aes_mix_known_vector"] == "8e4da1bc"
    assert all(audit["rcon_generated_matches_printed"])

    for variant in ("Wish-512", "Wish-1024"):
        checks = audit[variant]
        assert checks["table_bijection"]
        for transform in ("direct", "inverse", "shiftrows_composed"):
            assert all(checks[transform].values())
        assert set(checks["truncation_counts_inverse_output_columns"]) == {2}
        assert checks["full_permutation_roundtrips_passed"] == [True] * 4

    comparisons = report["comparisons"]
    assert len(comparisons) == 14
    assert all(row["differ"] for row in comparisons)
    print("PASS: pinned input and all 14 recorded θ comparisons validated")


if __name__ == "__main__":
    main()
