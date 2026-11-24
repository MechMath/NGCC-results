#!/usr/bin/env python3
"""Deterministic arithmetic checks for the hash-13 handoff.

This script checks only block-count combinatorics and substitution arithmetic.
It does not model hash chaining, success probabilities, or security.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import platform
import sys
from collections import Counter
from pathlib import Path


K_SMALL_MAX = 12
LARGE_N_EXP = 54
JOIN_MIN_I = 109


def path_length(k: int, bits: tuple[int, ...]) -> int:
    """Length using short=2 and long=base 2 plus increment 2^stage."""
    if len(bits) != k:
        raise ValueError("bit vector length does not equal k")
    length = 0
    for stage, long_selected in enumerate(bits):
        if long_selected not in (0, 1):
            raise ValueError("path choices must be bits")
        length += 2
        if long_selected:
            length += 1 << stage
    return length


def check_small_k(k: int) -> dict:
    expected_lo = 2 * k
    expected_hi = 2 * k + (1 << k) - 1
    expected_lengths = list(range(expected_lo, expected_hi + 1))

    witnessed: dict[int, tuple[int, ...]] = {}
    all_path_lengths: list[int] = []
    for bits in itertools.product((0, 1), repeat=k):
        length = path_length(k, bits)
        all_path_lengths.append(length)
        witnessed.setdefault(length, bits)

    missing = [n for n in expected_lengths if n not in witnessed]
    extras = sorted(set(witnessed) - set(expected_lengths))
    duplicates = sorted(
        length for length, count in Counter(all_path_lengths).items() if count != 1
    )

    canonical_checks = []
    for b in range(1 << k):
        bits = tuple((b >> stage) & 1 for stage in range(k))
        length = path_length(k, bits)
        canonical_checks.append(
            {
                "binary_value": b,
                "selected_stages": [j for j, bit in enumerate(bits) if bit],
                "length": length,
                "expected": 2 * k + b,
            }
        )

    canonical_ok = all(row["length"] == row["expected"] for row in canonical_checks)
    return {
        "k": k,
        "increments": [1 << stage for stage in range(k)],
        "expected_interval": [expected_lo, expected_hi],
        "expected_count": len(expected_lengths),
        "enumerated_paths": 1 << k,
        "distinct_lengths": len(witnessed),
        "missing": missing,
        "extras": extras,
        "duplicate_lengths": duplicates,
        "canonical_identity_2k_plus_binary_value": canonical_ok,
        "covers_every_integer": not missing and not extras,
        "pass": (
            not missing
            and not extras
            and not duplicates
            and canonical_ok
            and len(expected_lengths) == 1 << k
            and set(witnessed) == set(expected_lengths)
        ),
        # Keep the artifact finite while retaining witness construction data.
        "witness_examples": [
            {
                "length": expected_lo,
                "choices": witnessed[expected_lo],
            },
            {
                "length": expected_hi,
                "choices": witnessed[expected_hi],
            },
        ],
    }


def poly_add(
    left: dict[tuple[int, int], int], right: dict[tuple[int, int], int]
) -> dict[tuple[int, int], int]:
    result = dict(left)
    for monomial, coefficient in right.items():
        result[monomial] = result.get(monomial, 0) + coefficient
    return {monomial: coefficient for monomial, coefficient in result.items() if coefficient}


def poly_scale(
    expression: dict[tuple[int, int], int], scalar: int
) -> dict[tuple[int, int], int]:
    return {
        monomial: scalar * coefficient
        for monomial, coefficient in expression.items()
        if scalar * coefficient
    }


def compact_poly(expression: dict[tuple[int, int], int]) -> dict[str, int]:
    """Serialize a bivariate integer polynomial as {N^a*i^b: coefficient}."""
    return {
        f"N^{n_power}*i^{i_power}": coefficient
        for (n_power, i_power), coefficient in sorted(expression.items())
    }


def check_symbolic_substitution() -> dict:
    # Components:
    # expandable message: i-1 blocks
    # connector: 1 block
    # target-derived join: 1 block
    # suffix i+2,...,N: N-(i+2)+1 = N-i-1 blocks
    terms = {
        "expandable": {(0, 1): 1, (0, 0): -1},
        "connector": {(0, 0): 1},
        "target_derived_join": {(0, 0): 1},
        "suffix": {(1, 0): 1, (0, 1): -1, (0, 0): -1},
    }
    total: dict[tuple[int, int], int] = {}
    for term in terms.values():
        total = poly_add(total, term)

    expected_total = {(1, 0): 1}
    total_minus_expected = poly_add(total, poly_scale(expected_total, -1))

    N = (1 << LARGE_N_EXP) + 1
    max_i = N - 3
    min_i = JOIN_MIN_I
    k = LARGE_N_EXP
    expandable_lo = 2 * k
    expandable_hi = 2 * k + (1 << k) - 1

    endpoint_checks = []
    for i in (min_i, max_i):
        expandable = i - 1
        connector = 1
        join = 1
        suffix_start = i + 2
        suffix_count = N - i - 1
        total_count = expandable + connector + join + suffix_count
        endpoint_checks.append(
            {
                "i": i,
                "expandable_length": expandable,
                "connector_blocks": connector,
                "target_derived_join_blocks": join,
                "suffix_first_block": suffix_start,
                "suffix_last_block": N,
                "suffix_count": suffix_count,
                "total": total_count,
                "total_equals_N": total_count == N,
                "expandable_in_k54_range": expandable_lo <= expandable <= expandable_hi,
                "suffix_starts_at_i_plus_2": suffix_start == i + 2,
                "suffix_ends_at_length_block": N,
                "suffix_includes_target_final_content_block_N_minus_1": (
                    suffix_start <= N - 1 <= N
                ),
            }
        )

    # Range proof facts:
    # i in [109,N-3] gives i>=109, so i-1>=108=2k.
    # It also gives i-1<=N-4=2^54-3<=2^54+107=2k+2^k-1.
    # The suffix starts at i+2<=N-1, hence contains N-1 and N.
    range_proof_checks = {
        "lower_expandable_bound": min_i - 1 == expandable_lo,
        "upper_expandable_difference": expandable_hi - (max_i - 1),
        "upper_expandable_bound_holds": max_i - 1 <= expandable_hi,
        "suffix_start_at_max_i": max_i + 2,
        "target_final_content_block": N - 1,
        "length_block": N,
        "max_i_inclusion_boundary_holds": max_i + 2 <= N - 1,
        "i_upper_bound_used": max_i == N - 3,
    }

    return {
        "symbolic_identity": {
            "terms": {name: compact_poly(term) for name, term in terms.items()},
            "sum": compact_poly(total),
            "expected_N": compact_poly(expected_total),
            "difference_from_N": compact_poly(total_minus_expected),
            "holds_as_bivariate_polynomial_identity": total == expected_total,
        },
        "large_parameter": {
            "N": N,
            "N_expression": "2^54+1",
            "i_interval": [min_i, max_i],
            "i_interval_expression": "[109,N-3]",
            "k": k,
            "expandable_range": [expandable_lo, expandable_hi],
            "expandable_range_expression": "[2k,2k+2^k-1]",
        },
        "endpoint_checks": endpoint_checks,
        "range_proof_checks": range_proof_checks,
        "proof_note": (
            "The bivariate polynomial identity is exact. For all integer i in the "
            "stated interval, i-1 lies in the k=54 expandable range, and i+2<=N-1, "
            "so the retained suffix includes both final target content block N-1 "
            "and length block N."
        ),
        "pass": (
            total == expected_total
            and all(
                row["total_equals_N"]
                and row["expandable_in_k54_range"]
                and row["suffix_starts_at_i_plus_2"]
                and row["suffix_ends_at_length_block"]
                and row["suffix_includes_target_final_content_block_N_minus_1"]
                for row in endpoint_checks
            )
            and range_proof_checks["lower_expandable_bound"]
            and range_proof_checks["upper_expandable_bound_holds"]
            and range_proof_checks["max_i_inclusion_boundary_holds"]
        ),
    }


def main() -> int:
    script_path = Path(__file__).resolve()
    small_checks = [check_small_k(k) for k in range(1, K_SMALL_MAX + 1)]
    symbolic = check_symbolic_substitution()
    result = {
        "purpose": (
            "Arithmetic and combinatorial validation only; not cryptographic "
            "evidence, a probability proof, or a security claim."
        ),
        "environment": {
            "python_executable": sys.executable,
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "script_path": str(script_path),
            "script_sha256": hashlib.sha256(script_path.read_bytes()).hexdigest(),
        },
        "model": {
            "stages": "0,...,k-1",
            "short_path": "2 blocks at every stage",
            "long_path": "2+2^stage blocks",
            "reachable_lengths": (
                "{2k + sum(bit[stage]*2^stage) : bit in {0,1}^k} "
                "= every integer in [2k,2k+2^k-1]"
            ),
        },
        "small_k_exhaustive_checks": small_checks,
        "symbolic_substitution_check": symbolic,
        "overall_pass": all(row["pass"] for row in small_checks) and symbolic["pass"],
    }
    output_path = Path("arithmetic_results.json")
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(
        {
            "overall_pass": result["overall_pass"],
            "small_k_range": [1, K_SMALL_MAX],
            "script_sha256": result["environment"]["script_sha256"],
            "output_path": str(output_path.resolve()),
            "output_sha256": hashlib.sha256(output_path.read_bytes()).hexdigest(),
            "symbolic_difference_from_N": symbolic["symbolic_identity"][
                "difference_from_N"
            ],
            "large_N": symbolic["large_parameter"]["N"],
            "i_interval": symbolic["large_parameter"]["i_interval"],
        },
        indent=2,
        sort_keys=True,
    ))
    return 0 if result["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
