#!/usr/bin/env python3
"""Extract the fixed-commit sign-26 response-loop semantics."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pypdf import PdfReader


ROOT = Path(__file__).resolve().parents[1]
CHECKOUT = ROOT / "artifacts" / "checkout" / "sign-26"
SPEC = CHECKOUT / "sign-26-spec.pdf"
SIGN = (
    CHECKOUT
    / "Implementations"
    / "sqisign2d_lvl1"
    / "src"
    / "sqisigndim2"
    / "ref"
    / "sqisigndim2x"
    / "sign.c"
)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def matching_lines(path: Path, needles: tuple[str, ...]) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        for needle in needles:
            if needle in line:
                out.append(
                    {
                        "line": number,
                        "needle": needle,
                        "text": line.strip(),
                    }
                )
    return out


def main() -> None:
    needles = (
        "int found = 0;",
        "while (!found && count < 50)",
        "found = ibz_cmp(&norm, &bound) < 0",
        "if (!found)",
        "found = 1;",
        "}while(ibz_cmp(&tmp2, &ibz_const_zero)==0);",
    )
    copies = sorted(CHECKOUT.glob("Implementations/sqisign2d_lvl*/src/sqisigndim2/ref/sqisigndim2x/sign.c"))
    spec_pages = PdfReader(SPEC).pages
    page34 = spec_pages[33].extract_text() or ""
    result = {
        "checkout_commit": "dc66c6cb3c06e75bdea0048e21fa4e13c63f00af",
        "spec_sha256": sha256(SPEC),
        "spec_algorithm_27_fragments": {
            "algorithm_18_found_definition": "found: 1 if we find the target ideal, and 0 otherwise"
            in (spec_pages[18].extract_text() or ""),
            "algorithm_18_success_returns_found_1": "return 1, J" in (spec_pages[18].extract_text() or ""),
            "algorithm_27_condition_present": "while(found=1)" in page34,
        },
        "sign_c_sha256": {str(path.relative_to(CHECKOUT)): sha256(path) for path in copies},
        "sign_c_evidence": matching_lines(SIGN, needles),
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
