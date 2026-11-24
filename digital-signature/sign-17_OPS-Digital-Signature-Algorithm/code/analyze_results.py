#!/usr/bin/env python3
import csv
import hashlib
import json
from decimal import Decimal, getcontext
from math import comb
from pathlib import Path

getcontext().prec = 80
ROOT = Path(__file__).resolve().parent
Q = Decimal(67104769)
PROFILES = [
    ("OPSsig-128", 16, 512 * 3),
    ("OPSsig-256", 48, 512 * 4),
    ("OPSsig-512", 24, 1024 * 4),
]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def binomial_prob(x, j, n):
    if j > 0 and x == 0:
        return Decimal(0)
    if n - j > 0 and x == 1:
        return Decimal(0)
    return (
        Decimal(comb(n, j))
        * (Decimal(1) if j == 0 else x**j)
        * ((1 - x) ** (n - j))
    )


def clopper_pearson(k, n, alpha=Decimal("0.025")):
    lower = Decimal(0)
    if k:
        lo, hi = Decimal(0), Decimal(1)
        for _ in range(180):
            x = (lo + hi) / 2
            tail = sum(
                (binomial_prob(x, j, n) for j in range(k, n + 1)), Decimal(0)
            )
            if tail < alpha:
                lo = x
            else:
                hi = x
        lower = (lo + hi) / 2
    lo, hi = Decimal(0), Decimal(1)
    for _ in range(180):
        x = (lo + hi) / 2
        tail = sum(
            (binomial_prob(x, j, n) for j in range(0, k + 1)), Decimal(0)
        )
        if tail > alpha:
            lo = x
        else:
            hi = x
    return lower, (lo + hi) / 2


def parse_attempts(path):
    with open(path, newline="") as f:
        rows = [row for row in csv.DictReader(f) if row["query"].isdigit()]
    assert len(rows) == 256
    assert [int(row["query"]) for row in rows] == list(range(256))
    assert len({row["message_hex"] for row in rows}) == 256
    assert all(int(row["submitted_accept"]) == 1 for row in rows)
    return rows


def arm_result(directory):
    rows = parse_attempts(directory / "attempts.csv")
    hit_rows = [row for row in rows if int(row["usehint_mismatches"]) > 0]
    reject_rows = [row for row in rows if int(row["spec_reject"]) == 1]
    lo, hi = clopper_pearson(len(hit_rows), len(rows))
    summary = json.loads((directory / "summary.json").read_text())
    return {
        "attempts": len(rows),
        "submitted_accept": sum(int(row["submitted_accept"]) for row in rows),
        "spec_verifier_valid": summary["spec_verifier_valid"],
        "spec_accept": summary["spec_accept"],
        "spec_reject": summary["spec_reject"],
        "raw_boundary_hit_attempts": len(hit_rows),
        "raw_coefficient_mismatch_count": sum(
            int(row["usehint_mismatches"]) for row in rows
        ),
        "raw_boundary_hit_clopper_pearson_95": [str(lo), str(hi)],
        "hit_witnesses": [
            {
                key: int(row[key])
                for key in (
                    "query",
                    "usehint_mismatches",
                    "first_poly",
                    "first_coeff",
                    "first_a",
                    "submitted_high",
                    "spec_high",
                    "hint",
                )
            }
            for row in hit_rows
        ],
        "reject_queries": [int(row["query"]) for row in reject_rows],
        "negative_control_submitted_accept": summary[
            "submitted_negative_accept"
        ],
        "negative_control_spec_accept": summary["spec_negative_accept"],
        "stderr_bytes": (directory / "stderr.txt").stat().st_size,
        "summary": summary,
        "artifacts": {
            name: sha256(directory / name)
            for name in [
                "attempts.csv",
                "signatures.bin",
                "publickey.bin",
                "summary.json",
                "stderr.txt",
            ]
        },
    }


result = {
    "schema": "ops-sign17-boundary-reachability-results/v3-all-reference",
    "source_zip_sha256": "02322c6792259231ab8eb3cc094be32be02a1b9b6b1d7c86b0029c37b0f04d09",
    "permitted_spec_sha256": "1b5dc50ff728b2698bda90928251bae4e6cac4e138c82359f6f263cb6914078f",
    "predeclared_queries_per_profile": 256,
    "admitted_mathematical_dependency": "b26ef46dd25e642a",
    "exact_boundary_lemma": "89e06c2e60c37a69",
    "profiles": {},
    "limitations": [
        "The uniform coefficient law is an explicit hypothesis, not a distribution theorem for the submitted signer.",
        "The observations are for one deterministic key and one ordered set of 256 messages per profile; they are not an estimate of deployment-wide behavior.",
        "Raw UseHint/W1 boundary hits and challenge-hash specification-verifier rejections are reported separately.",
        "No forgery, key recovery, natural deployment rate, or NGCC Low-equivalence claim follows.",
    ],
}

for name, m, coeffs in PROFILES:
    p = Decimal(1) - (Decimal(1) - Decimal(m) / Q) ** coeffs
    all_avoid_q = (Decimal(1) - p) ** 256
    ref = arm_result(ROOT / "artifacts" / "corrected" / name)
    avx = arm_result(ROOT / "artifacts" / "avx2" / name)
    ref_pk = ROOT / "artifacts" / "corrected" / name / "publickey.bin"
    avx_pk = ROOT / "artifacts" / "avx2" / name / "publickey.bin"
    ref_sig = ROOT / "artifacts" / "corrected" / name / "signatures.bin"
    avx_sig = ROOT / "artifacts" / "avx2" / name / "signatures.bin"
    result["profiles"][name] = {
        "n": 1024 if name == "OPSsig-512" else 512,
        "k": 3 if name == "OPSsig-128" else 4,
        "m": m,
        "coefficients_per_signature": coeffs,
        "uniform_model": {
            "per_signature_boundary_probability": str(p),
            "expected_boundary_hit_attempts_in_256": str(p * 256),
            "probability_at_least_one_hit_in_256": str(1 - all_avoid_q),
        },
        "reference": ref,
        "avx2_same_message_crosscheck": {
            **avx,
            "public_key_byte_identical": ref_pk.read_bytes() == avx_pk.read_bytes(),
            "all_signatures_byte_identical": ref_sig.read_bytes()
            == avx_sig.read_bytes(),
        },
    }

(ROOT / "results.json").write_text(json.dumps(result, indent=2) + "\n")
