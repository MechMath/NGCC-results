#!/usr/bin/env python3
import hashlib
import json
import pathlib
from pathlib import Path

root = pathlib.Path(__file__).resolve().parent.parent
audit = json.loads((root / "artifacts" / "source-audit.json").read_text())

cells = []
cross = []
for line in (root / "logs" / "cross-family.matrix.tsv").read_text().splitlines():
    profile, patch, verifier, signer, rc = line.split("\t")
    cross.append(
        {
            "profile": int(profile),
            "variant": patch,
            "verifier_family": verifier,
            "signer_family": signer,
            "exit_code": int(rc),
            "verification_result": 0 if int(rc) == 0 else -1,
        }
    )

for row in audit:
    key = f"{row['family']}-{row['profile']}"
    artifacts = {}
    for variant in ("original", "ceil"):
        base = root / "artifacts" / f"{key}-{variant}"
        artifacts[variant] = {
            name: hashlib.sha256((base / name).read_bytes()).hexdigest()
            for name in ("pk.bin", "sig.bin")
        }
    cells.append(
        {
            **row,
            "minimal_patch": (
                "RRLWR_SIGN_HASH_SAMPLE_C_DOMAIN(signs_buffer, "
                "(RRLWR_SIGN_TAU + 7) / 8, ctilde, 0, 0)"
            )
            if row["ceil_tau_bytes"] != row["max_tau_bytes"]
            else "textual patch equals original numeric outlen 11",
            "original_self_verify": 0,
            "patched_self_verify": 0,
            "original_verifier_rejects_patched": (
                row["ceil_tau_bytes"] != row["max_tau_bytes"]
            ),
            "patched_verifier_rejects_original": (
                row["ceil_tau_bytes"] != row["max_tau_bytes"]
            ),
            "artifacts": artifacts,
        }
    )

result = {
    "schema": "octarine-xof-c-sign-length/v1",
    "classification": (
        "Implementation nonconformance and domain-length defect in all nine "
        "submitted implementation/profile trees. The observable challenge stream "
        "changes for profiles 128 and 256; profile 512's ceil(tau/8) value equals "
        "the submitted constant, so there is no observable change."
    ),
    "spec_requirement": {
        "locator": "Algorithm Specifications/Octarine.pdf, Algorithm 2, p. 23",
        "statement": "sign bits are XOF_C(ctilde, stream 0, counter 0; ceil(tau/8))",
        "pdf_sha256": "b88fbdd019beb8f0ae85c1554b48c87a42c5447b39171ce559ae30988c1bf09f",
    },
    "source_observation": {
        "submitted_call": "XOF_C(..., RRLWR_SIGN_MAX_TAU_BYTES=11, ...)",
        "domain_encoding": "outlen is encoded as a 32-bit field in the XOF_C domain header",
        "requested_domain_bits": 88,
        "effective_sign_bits_read_for_128": 16,
        "effective_sign_bits_read_for_256": 36,
        "effective_sign_bits_read_for_512": 87,
    },
    "cells": cells,
    "cross_family_verification": cross,
    "interpretation": {
        "established": [
            "all original and patched builds sign and verify their own signatures",
            "for Octarine-128, replacing 11 with ceil(tau/8)=2 changes the signature and causes mutual rejection",
            "for Octarine-256, replacing 11 with ceil(tau/8)=5 changes the signature and causes mutual rejection",
            "for Octarine-512, ceil(tau/8)=11, so source behavior and artifacts are unchanged",
            "Reference and Optimized produce byte-identical signatures at each profile; Additional uses its documented SHAKE/DRNG path and is separate",
        ],
        "not_established": [
            "an actual forgery or key recovery",
            "a quantified cryptographic security reduction below the claimed levels",
        ],
        "impact": (
            "A specification-conforming implementation that applies Algorithm 2 "
            "literally will not interoperate with the submitted 128/256 implementations. "
            "This is a causal interoperability/nonconformance defect; no stronger "
            "security-impact classification is claimed without a forgery analysis."
        ),
    },
}

Path(root / "results.json").write_text(json.dumps(result, indent=2) + "\n")
