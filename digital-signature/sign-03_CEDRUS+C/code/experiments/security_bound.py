#!/usr/bin/env python3
"""Expected work for the forced-tree-zero FORS forgery.

The calculation models the specified ideal hash primitives. It is not an
executed full forgery: the smallest expected offline work is about 2^11.
"""

import json
import math


PARAMETERS = [
    # name, h, d, a, k, a_prime, n, sig_bytes, claimed_classical,
    # claimed_quantum
    ("CEDRUS+C-160s", 67, 9, 12, 13, 15, 20, 9460, 160, 80),
    ("CEDRUS+C-160f", 66, 17, 7, 30, 9, 20, 19812, 160, 80),
    ("CEDRUS+C-256s", 65, 9, 13, 22, 14, 32, 24104, 256, 128),
    ("CEDRUS+C-256f", 66, 14, 8, 44, 10, 32, 43548, 256, 128),
    ("CEDRUS+C-384s", 67, 8, 13, 33, 17, 48, 61572, 384, 192),
    ("CEDRUS+C-384f", 64, 12, 10, 55, 12, 48, 75988, 384, 192),
    ("CEDRUS+C-512s", 65, 8, 14, 44, 15, 64, 98212, 512, 256),
    ("CEDRUS+C-512f", 67, 11, 11, 59, 12, 64, 121520, 512, 256),
]


def bottom_height(h, d):
    q, r = divmod(h, d)
    return q + (1 if r else 0)


def log2_leaf_success(q, a, k, a_prime):
    # f(q) = ((1-(1-2^-a)^q)^k) * 2^-a'.
    if q == 0:
        return -math.inf
    inner = -math.expm1(q * math.log1p(-(2.0 ** -a)))
    return k * math.log2(inner) - a_prime


def best_balance(a, k, a_prime, tree_count):
    best = None
    # Search around the continuous balance point q = 2^((ak+a')/(k+1)).
    center = (a * k + a_prime) / (k + 1)
    lo = max(1, int(2.0 ** max(0.0, center - 3.0)))
    hi = min(1 << 24, int(2.0 ** min(24.0, center + 3.0)) + 3)
    for q in range(lo, hi + 1):
        log_leaf = log2_leaf_success(q, a, k, a_prime)
        log_sign = math.log2(tree_count * q)
        log_offline = math.log2(tree_count) - log_leaf
        m = max(log_sign, log_offline)
        cost_log2 = m + math.log2(2.0 ** (log_sign - m) + 2.0 ** (log_offline - m))
        if best is None or cost_log2 < best["expected_total_log2"]:
            best = {
                "q_per_target_fors_instance": q,
                "signing_queries": tree_count * q,
                "local_digest_trials_expected": 2.0 ** log_offline,
                "log2_signing_queries": log_sign,
                "log2_local_digest_trials": log_offline,
                "log2_leaf_forgery_after_q": log_leaf,
                "log2_any_fors_instance_after_balanced_batch": (
                    math.log2(tree_count) + log_leaf
                ),
                "expected_total_log2": cost_log2,
            }
    return best


def main():
    rows = []
    for name, h, d, a, k, a_prime, n, sig_bytes, claimed_c, claimed_q in PARAMETERS:
        h0 = bottom_height(h, d)
        trees = 1 << h0
        balanced = best_balance(a, k, a_prime, trees)
        # Keep only signatures that land on the selected target FORS leaf.
        estimated_signature_memory = (
            balanced["q_per_target_fors_instance"] * sig_bytes
        )
        rows.append(
            {
                "parameter_set": name,
                "h": h,
                "d": d,
                "h0": h0,
                "effective_fors_instances": trees,
                "declared_classical_bits": claimed_c,
                "declared_quantum_bits": claimed_q,
                **balanced,
                "conservative_signature_storage_bytes": estimated_signature_memory,
                "claimed_classical_minus_estimated_work_log2": (
                    claimed_c - balanced["expected_total_log2"]
                ),
            }
        )

    result = {
        "status": "conditional_theoretical_calculation_not_executed_forgery",
        "model": "ideal hash primitives / random oracle; source defect forces one bottom XMSS tree",
        "assumption": "Each ballot signature on the fixed FORS instance reveals one selected leaf per each of k FORS subtrees; q is the number on one leaf.",
        "formula": {
            "leaf_forgery_after_q": "((1-(1-2^-a)^q)^k)*2^-a'",
            "signing_queries_to_target_leaf_expected": "2^h0*q",
            "local_digest_trials_to_target_leaf_expected": "2^h0/f(q)",
            "balance": "q approximately 2^((a*k+a_prime)/(k+1))",
        },
        "rows": rows,
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
