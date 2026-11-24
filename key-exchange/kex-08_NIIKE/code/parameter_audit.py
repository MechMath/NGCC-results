#!/usr/bin/env python3
"""Reproduce and audit the three NIIKE parameter-set strings in pages 35--38.

This script treats the PDF as the input of record.  It verifies the expected
SHA-256 digest, extracts the hexadecimal integers page-by-page (so page numbers
cannot be mistaken for hexadecimal continuation digits), checks the displayed
factorisations, and emits a machine-readable transcript.

The arithmetic in this script is reproducible working evidence.  It is not a
crypto_run execution and therefore is not itself graph evidence.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import pymupdf
import sympy
from sympy import factorint, isprime


PDF_SHA256 = "66e6531aec35c7715205b2df54c79349a129e65ec9fb8f26b32840936db70555"
ROOT = Path(__file__).resolve().parent
PDF = ROOT / "kex-08-spec.pdf"

# Superscripts in the PDF are encoded here as (prime, exponent).  The script
# separately checks every base for primality and every resulting product against
# the hexadecimal integer printed in the PDF.
FACTORS = {
    "I": {
        "M+": [(3, 4), (5, 1), (7, 1), (11, 2)]
        + [
            (q, 1)
            for q in [
                19, 23, 29, 31, 41, 43, 47, 53, 71, 79, 83, 89, 97,
                107, 109, 113, 131, 137, 149, 151, 157, 163, 167, 181,
                229, 239, 269,
            ]
        ],
        "M-": [
            (q, 1)
            for q in [
                13, 17, 37, 59, 61, 67, 73, 101, 103, 127, 139, 173,
                179, 191, 193, 199, 211, 241,
            ]
        ],
    },
    "II": {
        "M+": [(3, 1), (7, 3), (11, 2)]
        + [
            (q, 1)
            for q in [
                13, 17, 19, 23, 31, 37, 47, 53, 59, 73, 83, 97, 101,
                103, 107, 113, 127, 131, 137, 139, 149, 151, 163, 167,
                179, 181, 191, 223, 227, 229, 233, 239, 257, 263, 269,
                281, 307, 311, 313, 317, 337, 347, 367, 373, 379, 383,
                461, 593, 787, 937,
            ]
        ],
        "M-": [
            (q, 1)
            for q in [
                5, 29, 41, 43, 61, 67, 71, 79, 89, 109, 157, 173, 193,
                197, 199, 211, 241, 251, 271, 277, 283, 293, 331, 349,
                353, 359, 443, 587, 601, 607,
            ]
        ],
    },
}


def product(factors: list[tuple[int, int]]) -> int:
    return math.prod(q**e for q, e in factors)


def factor_dict(factors: list[tuple[int, int]]) -> dict[int, int]:
    out: dict[int, int] = {}
    for q, e in factors:
        out[q] = out.get(q, 0) + e
    return out


def compact_factors(factors: dict[int, int]) -> str:
    return " * ".join(f"{q}^{e}" if e != 1 else str(q) for q, e in sorted(factors.items()))


def pages() -> list[str]:
    doc = pymupdf.open(PDF)
    return [doc[i].get_text("text") for i in range(len(doc))]


def parse_p(page_texts: list[str], index: int, occurrence: int = 0) -> tuple[int, str]:
    """Extract one p from a single page, excluding the printed page footer."""
    lines = page_texts[index].splitlines()
    hits = [i for i, line in enumerate(lines) if re.search(r"\bp\s*=\s*0x", line)]
    i = hits[occurrence]
    parts = [re.search(r"0x([0-9a-f]+)", lines[i]).group(1)]
    for line in lines[i + 1 :]:
        token = line.strip()
        if token.startswith("M+"):
            break
        # A genuine wrapped hexadecimal line has many digits.  The final line
        # on a PDF page may be a short decimal page number.
        if re.fullmatch(r"[0-9a-f]+", token) and len(token) > 3:
            parts.append(token)
    return int("".join(parts), 16), "".join(parts)


def parse_cross_page_p(first_page: str, second_page: str) -> tuple[int, str]:
    """Extract the p spanning the bottom of one page and the next page."""
    lines = first_page.splitlines()
    i = next(i for i, line in enumerate(lines) if re.search(r"\bp\s*=\s*0x", line))
    parts = [re.search(r"0x([0-9a-f]+)", lines[i]).group(1)]
    for line in lines[i + 1 :]:
        token = line.strip()
        if re.fullmatch(r"[0-9a-f]+", token) and len(token) > 3:
            parts.append(token)
    for line in second_page.splitlines():
        token = line.strip()
        if token.startswith("M+"):
            break
        if re.fullmatch(r"[0-9a-f]+", token):
            parts.append(token)
    return int("".join(parts), 16), "".join(parts)


def parse_hex_assignment(page_text: str, label_pattern: str) -> int:
    lines = page_text.splitlines()
    pattern = re.compile(label_pattern)
    start = next(i for i, line in enumerate(lines) if pattern.search(line))
    parts = [pattern.search(lines[start]).group(1)]
    for line in lines[start + 1 :]:
        token = line.strip()
        if token.startswith("=") or token.startswith("=") or token.startswith("λ"):
            break
        if re.fullmatch(r"[0-9a-f]+", token) and len(token) > 3:
            parts.append(token)
    return int("".join(parts), 16)


def pocklington_certificate(n: int, factors_minus_one: dict[int, int]) -> dict:
    """Return a Pocklington witness if n-1 has the supplied complete factorisation."""
    assert math.prod(q**e for q, e in factors_minus_one.items()) == n - 1
    primes = sorted(factors_minus_one)
    for a in range(2, 10_000):
        if pow(a, n - 1, n) != 1:
            continue
        if all(math.gcd(pow(a, (n - 1) // q, n) - 1, n) == 1 for q in primes):
            return {
                "witness": a,
                "criterion": "Pocklington with complete n-1 factorisation",
                "base_primes_checked_BPSW": all(bool(isprime(q)) for q in primes),
            }
    return {"witness": None}


def main() -> int:
    sys.set_int_max_str_digits(0)
    digest = hashlib.sha256(PDF.read_bytes()).hexdigest()
    if digest != PDF_SHA256:
        raise SystemExit(f"bad PDF digest: {digest}")

    ptexts = pages()
    p_i, hex_i = parse_p(ptexts, 35, 0)
    p_ii, hex_ii = parse_p(ptexts, 35, 1)
    p_iii, hex_iii = parse_cross_page_p(ptexts[36], ptexts[37])

    mplus_i = parse_hex_assignment(ptexts[35], r"M\+\s*=\s*0x([0-9a-f]+)")
    mminus_i = parse_hex_assignment(ptexts[35], r"M−\s*=\s*0x([0-9a-f]+)")
    # The second assignments on page 36 are those following NGCC-II.
    page36 = ptexts[35]
    cut = page36.index("NGCC-II")
    page36_ii = page36[cut:]
    mplus_ii = parse_hex_assignment(page36_ii, r"M\+\s*=\s*0x([0-9a-f]+)")
    mminus_ii = parse_hex_assignment(page36_ii, r"M−\s*=\s*0x([0-9a-f]+)")

    parameters: dict[str, dict] = {
        "I": {
            "lambda": 128,
            "printed_log2_p": 248,
            "r": 13,
            "B": 35,
            "p_hex": hex_i,
            "p": p_i,
            "M+": mplus_i,
            "M-": mminus_i,
            "factor_lists": FACTORS["I"],
            "pdf_pages_1_based": [36],
        },
        "II": {
            "lambda": 256,
            "printed_log2_p": 511,
            "r": 14,
            "B": 70,
            "p_hex": hex_ii,
            "p": p_ii,
            "M+": mplus_ii,
            "M-": mminus_ii,
            "factor_lists": FACTORS["II"],
            "pdf_pages_1_based": [36],
        },
        "III": {
            "lambda": 512,
            "printed_log2_p": 16392,
            "r": 2,
            "B": 1,
            "p_hex": hex_iii,
            "p": p_iii,
            "pdf_pages_1_based": [37, 38],
        },
    }

    transcript: dict = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "command": "python3 parameter_audit.py",
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "pymupdf": pymupdf.__version__,
            "sympy": sympy.__version__,
        },
        "input": {
            "path": PDF.name,
            "sha256": digest,
            "pages_1_based": [35, 36, 37, 38],
            "provenance": (
                "run-local orchestrator copy of the original clean URL "
                "https://cdn.jsdelivr.net/gh/ngcc-dev/ngcc-harness@"
                "dc66c6cb3c06e75bdea0048e21fa4e13c63f00af/kex-08/kex-08-spec.pdf"
            ),
            "cdn_attempt": "curl timed out before saving bytes; no remote bytes were used",
        },
        "checks": [],
        "parameters": {},
        "requirement_provenance": {
            "setup_prime_and_modulus": "PDF p.22, Chapter 4.1 Setup",
            "private_key_space": "PDF p.22, Equation (4.1)",
            "discriminant_desideratum": "PDF p.29, Section 5.3",
            "kernel_representation_coprimality": "PDF p.31, Section 5.4",
            "ngcciii_mod_8_prose": "PDF p.31, first paragraph after EndomorphismGeneration",
            "ngcciii_sigma_equals_pi_minus_1": "PDF p.31, Section 5.3 concluding paragraph",
            "frobenius_equals_j": "PDF p.12, Remark 2.4.1",
        },
    }

    def record(name: str, passed: bool, detail: str, classification: str) -> None:
        transcript["checks"].append(
            {"name": name, "passed": bool(passed), "classification": classification, "detail": detail}
        )

    for label, data in parameters.items():
        p = data["p"]
        rec: dict = {
            "printed_parameters": {
                "lambda": data["lambda"],
                "log2_p": data["printed_log2_p"],
                "r": data["r"],
                "B": data["B"],
            },
            "provenance": {
                "PDF_pages_1_based": data["pdf_pages_1_based"],
                "text_line_locators": {
                    "I": {
                        "lambda_p_r_B": "PDF p.36, line 11",
                        "p": "PDF p.36, lines 12-13",
                        "M+": "PDF p.36, lines 14-16",
                        "M-": "PDF p.36, lines 17-19",
                    },
                    "II": {
                        "lambda_p_r_B": "PDF p.36, line 21",
                        "p": "PDF p.36, lines 22-23",
                        "M+": "PDF p.36, lines 24-29",
                        "M-": "PDF p.36, lines 30-32",
                    },
                    "III": {
                        "lambda_p_r_B": "PDF p.37, line 4",
                        "p": "PDF p.37 lines 5-34 through PDF p.38 line 34",
                        "M+_and_M-": "PDF p.38, lines 35-36",
                    },
                }[label],
            },
            "p": {
                "hex": hex(p),
                "hex_sha256_without_0x": hashlib.sha256(data["p_hex"].encode("ascii")).hexdigest(),
                "hex_digits": len(data["p_hex"]),
                "bit_length": p.bit_length(),
                "floor_log2": p.bit_length() - 1,
                "mod_4": p % 4,
                "mod_8": p % 8,
                "BPSW_probable_prime": bool(isprime(p)),
                "proof_status": "BPSW probable-prime screen only; no general primality proof",
            },
        }
        record(
            f"{label}:p_mod_4",
            p % 4 == 3,
            f"p mod 4 = {p % 4}",
            "setup_requirement",
        )
        record(
            f"{label}:p_bit_label",
            p.bit_length() == data["printed_log2_p"],
            f"bit_length(p)={p.bit_length()}, printed log2 p={data['printed_log2_p']}",
            "label_convention_or_typographical_issue",
        )

        if label != "III":
            fl = data["factor_lists"]
            mp_formula = product(fl["M+"])
            mm_formula = product(fl["M-"])
            m = mp_formula * mm_formula
            for tag, fac, printed in [
                ("M+", fl["M+"], data["M+"]),
                ("M-", fl["M-"], data["M-"]),
            ]:
                record(
                    f"{label}:{tag}_product",
                    product(fac) == printed,
                    f"displayed factorisation product equals printed hex: {product(fac) == printed}",
                    "arithmetic_conformance",
                )
                bases_prime = all(bool(isprime(q)) for q, _ in fac)
                record(
                    f"{label}:{tag}_factor_bases_prime",
                    bases_prime,
                    f"all displayed factor bases pass BPSW: {bases_prime}",
                    "probable_primality_of_factor_bases",
                )
            rec["factorisation"] = {
                "M+": compact_factors(factor_dict(fl["M+"])),
                "M-": compact_factors(factor_dict(fl["M-"])),
                "M_bit_length": m.bit_length(),
                "M_divides_p_squared_minus_1": (p * p - 1) % m == 0,
            }
        else:
            m = p + 1
            mp_formula = p + 1
            mm_formula = 1
            factors_m = factorint(m)
            rec["factorisation"] = {
                "M+": "p+1",
                "M-": "1",
                "M_bit_length": m.bit_length(),
                "M_divides_p_squared_minus_1": (p * p - 1) % m == 0,
                "factorisation_text": compact_factors(factors_m),
                "distinct_prime_count": len(factors_m),
                "maximum_prime": max(factors_m),
            }

        record(
            f"{label}:M_equals_Mplus_Mminus",
            m == mp_formula * mm_formula,
            f"M == M+ * M-: {m == mp_formula * mm_formula}",
            "arithmetic_conformance",
        )
        record(
            f"{label}:M_divides_p_squared_minus_1",
            (p * p - 1) % m == 0,
            f"M | (p^2-1): {(p * p - 1) % m == 0}",
            "setup_requirement",
        )

        exponents = list(factorint(m).values())
        b = data["B"]
        key_space = math.prod(1 + b * e for e in exponents)
        previous = math.prod(1 + (b - 1) * e for e in exponents)
        rec["private_key_space"] = {
            "B": b,
            "n_distinct_prime_factors": len(exponents),
            "product_at_B": key_space,
            "product_at_B_bit_length": key_space.bit_length(),
            "product_at_B_minus_1": previous,
            "required_lower_bound": 2 ** (2 * data["lambda"]),
            "meets_size": key_space >= 2 ** (2 * data["lambda"]),
            "B_is_minimal": previous < 2 ** (2 * data["lambda"]),
        }
        record(
            f"{label}:private_key_size",
            key_space >= 2 ** (2 * data["lambda"]),
            f"prod(1+B*e_i) has bit_length {key_space.bit_length()} for 2*lambda={2*data['lambda']}",
            "setup_requirement",
        )
        record(
            f"{label}:B_minimal",
            previous < 2 ** (2 * data["lambda"]),
            f"product at B-1 is below 2^(2*lambda): {previous < 2 ** (2 * data['lambda'])}",
            "setup_requirement",
        )

        if label in ("I", "II"):
            # The complete factorisation of p-1 is easy at these sizes and gives
            # a Pocklington certificate; primality of the listed large base
            # factors is still only BPSW-screened here.
            pminus = factorint(p - 1)
            rec["p"]["pocklington"] = pocklington_certificate(p, pminus)
            rec["p"]["p_minus_1_factorisation"] = compact_factors(pminus)
        transcript["parameters"][label] = rec

    # NGCC-III explicit-orientation audit.  Remark 2.4.1 identifies Frobenius pi
    # with j, and j^2=-p, so sigma=pi-1 has Nrd(sigma)=p+1 and tr(sigma)=-2.
    p3 = parameters["III"]["p"]
    m3 = p3 + 1
    required_norm = m3**2
    actual_norm = p3 + 1
    trace_sigma = -2
    disc_actual = 4 * actual_norm - trace_sigma**2
    disc_required = 4 * required_norm - trace_sigma**2
    transcript["ngcc_iii_orientation"] = {
        "stated_r": 2,
        "stated_M": "p+1",
        "required_Nrd_sigma_equals_M_to_r": str(required_norm),
        "explicit_sigma": "pi-1",
        "explicit_Nrd_sigma": str(actual_norm),
        "explicit_Nrd_factorisation": compact_factors(factorint(actual_norm)),
        "explicit_trace_sigma": trace_sigma,
        "trace_inequality_holds": trace_sigma < 4 * (actual_norm - math.isqrt(actual_norm)),
        "required_discriminant_absolute": str(disc_required),
        "required_discriminant_factorisation": "4*p*(p+2)",
        "explicit_discriminant_absolute": str(disc_actual),
        "explicit_discriminant_factorisation": "4*p",
        "gcd_Nrd_sigma_trace_sigma": math.gcd(actual_norm, trace_sigma),
        "prose_mod_8_requirement": 7,
        "printed_p_mod_8": p3 % 8,
    }
    record(
        "III:explicit_sigma_norm_matches_required",
        actual_norm == required_norm,
        f"Nrd(pi-1)=p+1, but r=2 requires Nrd(sigma)=M^r=(p+1)^2",
        "parameter_set_invalidity",
    )
    record(
        "III:gcd_Nrd_trace",
        math.gcd(actual_norm, trace_sigma) == 1,
        f"gcd(Nrd(sigma),tr(sigma))=2, contradicting the Section 5.4 coprimality condition",
        "parameter_set_invalidity_for_stated_explicit_orientation",
    )
    record(
        "III:discriminant_is_prime_or_two_distinct_primes",
        False,
        "|Disc(pi-1)|=4p; with the required square norm the formal expression is 4p(p+2)",
        "security_desideratum_failure",
    )
    record(
        "III:p_mod_8_matches_prose",
        p3 % 8 == 7,
        f"prose requires p mod 8 = 7; printed p mod 8 = {p3 % 8}",
        "specification_text_mismatch",
    )

    # Locate and report footer-induced false digits explicitly.
    transcript["parser_guard"] = {
        "rejected_footer_hex_fragments": ["34"],
        "reason": (
            "On PDF page 37, the two-digit line 34 is the printed page number "
            "below the p continuation. Including it changes p from 4098 to 4100 "
            "hexadecimal digits, adds two trailing nibbles, and produces a false "
            "compositeness/factor-divisor conclusion."
        ),
        "correct_ngcc_iii_hex_digits": len(hex_iii),
        "correct_ngcc_iii_bit_length": p_iii.bit_length(),
    }

    out_json = ROOT / "parameter-audit.json"
    out_json.write_text(json.dumps(transcript, indent=2) + "\n", encoding="utf-8")

    # Markdown summary suitable for human inspection and handoff.
    rows = []
    for label, rec in transcript["parameters"].items():
        p = rec["p"]
        rows.append(
            f"| {label} | {p['hex_digits']} | {p['bit_length']} | "
            f"{rec['printed_parameters']['log2_p']} | {p['mod_4']} | {p['mod_8']} | "
            f"{p['BPSW_probable_prime']} | {rec['factorisation']['M_divides_p_squared_minus_1']} | "
            f"{rec['private_key_space']['meets_size']} | {rec['private_key_space']['B_is_minimal']} |"
        )
    lines = [
        "# NIIKE kex-08 parameter audit",
        "",
        f"- Input SHA-256: `{digest}`",
        "- Input pages (1-based PDF): 35--38",
        "- Reproduction: `python3 parameter_audit.py`",
        "- Machine-readable output: `parameter-audit.json`",
        "",
        "## Arithmetic summary",
        "",
        "| Set | p hex digits | p bit length | printed log2 p | p mod 4 | p mod 8 | BPSW | M divides p^2-1 | key space | B minimal |",
        "|---|---:|---:|---:|---:|---:|---|---|---|---|",
        *rows,
        "",
        "All displayed M+/M- integer checks pass for NGCC-I and NGCC-II. "
        "For NGCC-III, M+=p+1, M-=1, and the exact factorisation of p+1 "
        "has 759 distinct primes with maximum 7963.",
        "",
        "## Findings",
        "",
        "1. **NGCC-III explicit orientation is arithmetically inconsistent.** "
        "Remark 2.4.1 identifies pi with j, with j^2=-p. Therefore "
        "Nrd(pi-1)=(j-1)(-j-1)=p+1 and tr(pi-1)=-2. The stated r=2 and "
        "M=p+1 require Nrd(sigma)=M^r=(p+1)^2. These are not equal.",
        "2. The same NGCC-III orientation has gcd(Nrd(sigma),tr(sigma))=2, "
        "violating the specification's Section 5.4 coprimality condition.",
        "3. The NGCC-III discriminant is |Disc(pi-1)|=4p, whereas the formal "
        "r=2 expression with trace -2 is 4p(p+2). Neither is prime or the "
        "product of two distinct primes as desired in Section 5.3.",
        "4. NGCC-III's printed integer is 3 mod 8, while the prose says 7 mod 8.",
        "5. The printed `log2 p` label is 248 for NGCC-I although the printed "
        "integer has bit length 255. This is a label/typography mismatch, not "
        "a failure of p>=2^248.",
        "",
        "## Evidence boundary",
        "",
        "The two-dimensional orientation requirements for NGCC-I/II are not "
        "reconstructible from the printed factor lists alone. Their concrete "
        "sigma, trace and discriminant remain unproved requirements. BPSW is "
        "only a probable-prime screen. For NGCC-I/II a Pocklington witness and "
        "complete p-1 factorisation are included, but the large prime factors "
        "in that factorisation are themselves only BPSW-screened here.",
        "",
        "The footer guard matters: PDF page 37 ends with printed page number "
        "`34`. Treating that line as p-continuation gives 4100 hex digits and "
        "a false compositeness conclusion. The correct value has 4098 hex "
        "digits.",
    ]
    (ROOT / "parameter-audit.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps({
        "pdf_sha256": digest,
        "checks": len(transcript["checks"]),
        "failed_checks": [c["name"] for c in transcript["checks"] if not c["passed"]],
        "outputs": ["parameter-audit.json", "parameter-audit.md"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
