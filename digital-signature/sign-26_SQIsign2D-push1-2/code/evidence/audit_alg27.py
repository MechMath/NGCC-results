#!/usr/bin/env python3
"""Reproduce the sign-26 Algorithm 27 control-flow/evidence check."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pymupdf


ROOT = Path(__file__).resolve().parent.parent
PDF = ROOT / "inputs" / "sign-26-spec.pdf"
SIGN_C = ROOT / "evidence" / "sign.c"
EXPECTED_PDF_SHA256 = (
    "1363945ff198e9ca48e7a7dbe39d488c590580d746c56b7f10e30d51f86059f6"
)


def main() -> None:
    pdf_sha256 = hashlib.sha256(PDF.read_bytes()).hexdigest()
    doc = pymupdf.open(PDF)
    page = doc[33]  # PDF page 34.
    words = page.get_text("words")

    located: dict[str, list[dict[str, object]]] = {}
    for target in ("do", "while(found=1)", "Compute", "return"):
        located[target] = [
            {"x0": round(float(w[0]), 2), "y0": round(float(w[1]), 2), "text": w[4]}
            for w in words
            if w[4] == target
        ]

    source = SIGN_C.read_text()
    source_loop = re.search(
        r"do\{(?P<body>.*?)while\s*\(\s*ibz_cmp\s*\(\s*&tmp2\s*,\s*"
        r"&ibz_const_zero\s*\)\s*==\s*0\s*\)\s*;",
        source,
        re.S,
    )

    checks = {
        "pdf_sha256_matches_authorized_copy": pdf_sha256 == EXPECTED_PDF_SHA256,
        "do_and_while_have_same_code_indent": (
            abs(located["do"][0]["x0"] - located["while(found=1)"][0]["x0"])
            < 0.01
        ),
        "post_test_is_found_equals_one": bool(located["while(found=1)"]),
        "reference_retry_is_norm_mod_three_zero_failure": bool(source_loop),
    }
    report = {
        "inputs": {
            "pdf": str(PDF.relative_to(ROOT)),
            "pdf_sha256": pdf_sha256,
            "reference_sign_c": str(SIGN_C.relative_to(ROOT)),
        },
        "pdf_page_34_locations": located,
        "reference_loop_match": (
            source_loop.group(0) if source_loop is not None else None
        ),
        "checks": checks,
        "interpretation": (
            "The bare do at Algorithm 27 line 1 is closed by while(found=1) "
            "at line 11; lines 12-31 follow the loop. The reference source "
            "repeats on the mod-3 failure condition instead."
        ),
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    if not all(checks.values()):
        raise SystemExit("one or more reproducibility checks failed")


if __name__ == "__main__":
    main()
