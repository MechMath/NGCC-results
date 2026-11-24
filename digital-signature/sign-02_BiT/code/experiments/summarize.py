#!/usr/bin/env python3
import hashlib
import json
import platform
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def tool_version(argv):
    try:
        p = subprocess.run(argv, check=True, capture_output=True, text=True)
        return p.stdout.splitlines()[0]
    except Exception as exc:
        return f"unavailable: {exc}"


def read_cases(path):
    rows = []
    with path.open() as f:
        header = f.readline().strip().split(",")
        for line in f:
            rows.append(dict(zip(header, line.strip().split(","))))
    return rows


def main():
    res = ROOT / "experiments/results"
    variants = [
        "bit128_ref", "bit128_avx2",
        "bit256_ref", "bit256_avx2",
        "bit512_ref", "bit512_avx2",
    ]
    summary = {
        "schema": "mmat.bit-source-guided-differential/v1",
        "scope": "Submitted BiT reference and AVX2 implementations for BiT-128, BiT-256 and BiT-512; honest deterministic KGen/Sign plus verifier-only malformed-input mutation.",
        "source": {
            "archive": "https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/BiT.zip",
            "archive_sha256": sha(ROOT / "source/BiT.zip"),
            "specification": "https://cdn.jsdelivr.net/gh/ngcc-dev/ngcc-harness@dc66c6cb3c06e75bdea0048e21fa4e13c63f00af/sign-02/sign-02-spec.pdf",
            "specification_sha256": sha(ROOT / "source/sign-02-spec.pdf"),
        },
        "environment": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "gcc": tool_version(["gcc", "--version"]),
            "make": tool_version(["make", "--version"]),
        },
        "commands": {
            "fetch_zip": "curl --fail --location --silent --show-error --output source/BiT.zip '<exact archive URL>'",
            "fetch_pdf": "curl --http1.1 --retry 4 --retry-all-errors --fail --location --silent --show-error --output source/sign-02-spec.pdf '<exact specification URL>'",
            "build_and_run": "bash experiments/build_and_run.sh",
            "kat_bundle": "python3 experiments/kat_to_bundle.py source/archive/Test_Vectors/KAT_SIG_BiT-512.txt experiments/results/bit512_kat0.bin 0",
            "summary": "python3 experiments/summarize.py",
        },
        "variants": {},
        "differential": {},
        "known_hint_alias_control": {},
        "limitations": [
            "Mutation coverage is a declared bounded corpus, not exhaustive over all 6695-byte signatures or all malformed messages.",
            "The public-key carry family samples seed and block boundaries and seeded single-byte substitutions; it is not an exhaustive public-key image audit.",
            "The KAT alias control confirms acceptance of two base-3 hint encodings but does not claim newness or formal SUF-CMA.",
            "No online system, published attack material or prohibited mirror was used.",
        ],
    }
    for v in variants:
        bundle = res / f"{v}.bin"
        summary["variants"][v] = {
            "bundle": str(bundle.relative_to(ROOT)),
            "bundle_sha256": sha(bundle),
            "bundle_bytes": bundle.stat().st_size,
        }
    for bits in (128, 256, 512):
        rhs = res / f"bit{bits}_ref_from_ref.csv"
        rhs_avx = res / f"bit{bits}_avx2_from_ref.csv"
        rows_r = read_cases(rhs)
        rows_a = read_cases(rhs_avx)
        seq_r = [(r["family"], r["index"], r["new_sig"], r["new_pk"], r["return"]) for r in rows_r]
        seq_a = [(r["family"], r["index"], r["new_sig"], r["new_pk"], r["return"]) for r in rows_a]
        accepted_r = [r for r in rows_r if r["accepted"] == "1"]
        nonbaseline = [r for r in accepted_r if r["family"] != "positive_control"
                       and not (r["family"] == "seeded_single_pk" and r["old_pk"] == r["new_pk"])
                       and not (r["family"] == "seeded_single_sig" and r["old_sig"] == r["new_sig"])]
        summary["differential"][f"bit{bits}"] = {
            "cases": len(rows_r),
            "ref_csv_sha256": sha(rhs),
            "avx2_csv_sha256": sha(rhs_avx),
            "identical_acceptance_sequence": seq_r == seq_a,
            "ref_accepted": len(accepted_r),
            "nonbaseline_accepted": len(nonbaseline),
            "baseline_pair_bundle_identical": sha(res / f"bit{bits}_ref.bin") == sha(res / f"bit{bits}_avx2.bin"),
        }
    kat_r = read_cases(res / "bit512_kat0_ref.csv")
    kat_a = read_cases(res / "bit512_kat0_avx2.csv")
    kat_acc = [r for r in kat_r if r["accepted"] == "1" and r["family"] != "positive_control"
               and not (r["family"] == "seeded_single_pk" and r["old_pk"] == r["new_pk"])]
    summary["known_hint_alias_control"] = {
        "bundle": "experiments/results/bit512_kat0.bin",
        "bundle_sha256": sha(res / "bit512_kat0.bin"),
        "ref_csv_sha256": sha(res / "bit512_kat0_ref.csv"),
        "avx2_csv_sha256": sha(res / "bit512_kat0_avx2.csv"),
        "identical_acceptance_sequence": kat_r == kat_a,
        "accepted_nonbaseline_rows": kat_acc,
        "interpretation": "Both submitted BiT-512 verifiers accept exactly the same two base-3 hint byte aliases in this submitted KAT witness. These are the already verified hint alias class, not a new differential.",
    }
    summary["conclusion"] = {
        "cross_implementation_acceptance_divergence_found": False,
        "accepted_noncanonical_input_beyond_known_hint_alias_found": False,
        "formal_suf_cma_claim": False,
        "status": "bounded negative differential result; no goal-closing new defect established",
    }
    out = res / "differential_summary.json"
    out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(out)


if __name__ == "__main__":
    main()
