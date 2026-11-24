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
    return (Decimal(comb(n, j)) *
            (Decimal(1) if j == 0 else x ** j) *
            ((1 - x) ** (n - j)))


def clopper_pearson(k, n, alpha=Decimal("0.025")):
    """Two-sided 1-2*alpha Clopper-Pearson interval."""
    lower = Decimal(0)
    if k:
        lo, hi = Decimal(0), Decimal(1)
        for _ in range(180):
            x = (lo + hi) / 2
            tail = sum((binomial_prob(x, j, n)
                        for j in range(k, n + 1)), Decimal(0))
            if tail < alpha:
                lo = x
            else:
                hi = x
        lower = (lo + hi) / 2
    lo, hi = Decimal(0), Decimal(1)
    for _ in range(180):
        x = (lo + hi) / 2
        tail = sum((binomial_prob(x, j, n)
                    for j in range(0, k + 1)), Decimal(0))
        if tail > alpha:
            lo = x
        else:
            hi = x
    return lower, (lo + hi) / 2


result = {
    "schema": "ops-sign17-boundary-reachability-results/v2-hash-corrected",
    "source_zip_sha256": "02322c6792259231ab8eb3cc094be32be02a1b9b6b1d7c86b0029c37b0f04d09",
    "permitted_spec_sha256": "1b5dc50ff728b2698bda90928251bae4e6cac4e138c82359f6f263cb6914078f",
    "predeclared_queries_per_profile": 256,
    "profiles": {},
    "admitted_mathematical_dependency": "b26ef46dd25e642a",
    "exact_boundary_lemma": "89e06c2e60c37a69",
    "limitations": [
        "The uniform coefficient law is an explicit hypothesis, not a distribution theorem for the submitted signer.",
        "The earlier v1 copied verifier incorrectly called sm3hash for 512/1024-bit challenges. The submitted signer and verifier use pseudohash for those lengths; this run restores that exact submitted challenge-hash path and changes only Decompose/UseHint.",
        "No forgery, key recovery, deployment-frequency, or NGCC Low-equivalence claim follows."
    ]
}

for name, m, coeffs in PROFILES:
    p = Decimal(1) - (Decimal(1) - Decimal(m) / Q) ** coeffs
    all_avoid_q = (Decimal(1) - p) ** 256
    rows = []
    with open(ROOT / "artifacts-v2" / name / "attempts.csv", newline="") as f:
        for row in csv.DictReader(f):
            if row["query"].isdigit():
                rows.append(row)
    raw_hits = sum(int(r["usehint_mismatches"]) > 0 for r in rows)
    lo, hi = clopper_pearson(raw_hits, len(rows))
    summary = json.loads((ROOT / "artifacts-v2" / name / "summary.json").read_text())
    result["profiles"][name] = {
        "n": 1024 if name == "OPSsig-512" else 512,
        "k": 4 if name != "OPSsig-128" else 3,
        "m": m,
        "coefficients_per_signature": coeffs,
        "uniform_model": {
            "per_signature_boundary_probability": str(p),
            "expected_boundary_hits_in_256": str(p * 256),
            "probability_at_least_one_in_256": str(1 - all_avoid_q),
        },
        "observed": {
            "attempts": len(rows),
            "submitted_accept": sum(int(r["submitted_accept"]) for r in rows),
            "raw_usehint_mismatch_attempts": raw_hits,
            "spec_verifier_valid": summary["spec_verifier_valid"],
            "spec_accept": summary["spec_accept"],
            "spec_reject": summary["spec_reject"],
            "raw_boundary_hit_clopper_pearson_95": [str(lo), str(hi)],
        },
        "artifacts": {
            n: sha256(ROOT / "artifacts-v2" / name / n)
            for n in ["attempts.csv", "signatures.bin", "publickey.bin",
                      "summary.json", "stderr.txt"]
        }
    }

(ROOT / "results-v2.json").write_text(json.dumps(result, indent=2) + "\n")
