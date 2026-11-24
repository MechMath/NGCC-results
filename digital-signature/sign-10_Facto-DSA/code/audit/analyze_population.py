#!/usr/bin/env python3
import csv
import json
import math
import sys
from collections import Counter


def main(path: str) -> None:
    rows = []
    summary = None
    with open(path, newline="", encoding="utf-8") as f:
        lines = f.readlines()
    for line in lines:
        if line.startswith("summary,"):
            summary = line.strip()
    scale_success_by_index = {}
    for line in lines:
        if line.startswith("scale_success_index,"):
            _, index, count = line.strip().split(",")
            scale_success_by_index[int(index)] = int(count)
    header = next(i for i, line in enumerate(lines) if line.startswith("kind,"))
    data = [line for line in lines[header + 1:] if line.startswith("population,")]
    reader = csv.DictReader([lines[header]] + data)
    rows = [dict(row) for row in reader]

    if not rows:
        raise SystemExit("no population rows")

    for row in rows:
        for key in list(row):
            if key not in ("kind", "pk_fnv", "sk_fnv", "msg_fnv", "sig_fnv"):
                row[key] = int(row[key])

    calls = len(rows)
    failures = sum(r["sign_rc"] != 0 for r in rows)
    verify_failures = sum(r["sign_rc"] == 0 and r["verify_rc"] != 0 for r in rows)
    keygen_failures = sum(r["keygen_rc"] != 0 for r in rows)
    total_trials = sum(r["trials"] for r in rows)
    split_successes = sum(r["split_success"] for r in rows)
    scale_attempts = sum(r["scale_attempts"] for r in rows)
    scale_successes = sum(r["scale_success"] for r in rows)
    lengths = Counter(r["length"] for r in rows)
    trial_hist = Counter(r["trials"] for r in rows)
    scale_hist = Counter(r["scale_attempts"] for r in rows)
    success_scale_hist = Counter(
        r["scale_attempts"] for r in rows if r["scale_success"] == 1
    )

    # Rule-of-three 95% upper bound for zero observed failures.
    empirical_upper_95 = 3.0 / calls if failures == 0 else None
    output = {
        "source": path,
        "summary_line": summary,
        "calls": calls,
        "unique_keys": len({r["key"] for r in rows}),
        "lengths": dict(sorted(lengths.items())),
        "keygen_failures": keygen_failures,
        "sign_failures": failures,
        "verify_failures_after_successful_sign": verify_failures,
        "all_signatures_verified": failures == 0 and verify_failures == 0,
        "total_trial_attempts": total_trials,
        "mean_trials_per_sign": total_trials / calls,
        "max_trials": max(r["trials"] for r in rows),
        "trial_histogram": dict(sorted(trial_hist.items())),
        "successful_split_events": split_successes,
        "split_failures_before_success": sum(r["split_fail"] for r in rows),
        "scale_attempts": scale_attempts,
        "scale_successes": scale_successes,
        "max_scale_attempts": max(r["scale_attempts"] for r in rows),
        "scale_attempt_histogram": dict(sorted(scale_hist.items())),
        "success_scale_attempt_histogram": dict(sorted(success_scale_hist.items())),
        "global_scale_success_index_histogram": scale_success_by_index,
        "split_choices_that_exhausted_all_scales": split_successes - calls,
        "empirical_failure_fraction": failures / calls,
        "zero_failure_rule_of_three_95pct_upper_bound": empirical_upper_95,
        "interpretation_limit": (
            "The 64k bounded population is not a proof of the PDF probability "
            "bound; the analytical bound below uses the declared independence/model."
        ),
    }

    q = 65519
    survival_zero = 0.0
    for _ in range(10):
        survival_zero = (
            (q - 1) / (2 * q)
            + survival_zero / q
            + ((q - 1) / (2 * q)) * survival_zero * survival_zero
        )
    p_q = 1.0 - survival_zero
    p_trial_64 = 0.26 * (1.0 - (1.0 - p_q) ** 64)
    expected_sign_failure_64 = (1.0 - p_trial_64) ** 512
    expected_sign_failure_full_scale = (1.0 - 0.26) ** 512
    output["derived_from_pdf_model"] = {
        "q": q,
        "n": 10,
        "triangle_survival_probability_pQ": p_q,
        "implementation_scale_cap": 64,
        "p_trial_lower_bound_with_64_scales": p_trial_64,
        "sign_failure_upper_bound_with_64_scales": expected_sign_failure_64,
        "sign_failure_upper_bound_with_full_nonzero_scales": expected_sign_failure_full_scale,
        "sign_failure_upper_bound_with_64_scales_log2": math.log2(
            expected_sign_failure_64
        ),
        "pdf_declared_bound_log2": -222,
        "violates_pdf_declared_bound": expected_sign_failure_64 >= 2.0 ** -222,
    }
    json.dump(output, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main(sys.argv[1])
