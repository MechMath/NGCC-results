#!/usr/bin/env python3
"""Check the Furue--Ikematsu truncated-Macaulay applicability condition.

This is an attack adapter, not a solver.  It evaluates the source's
semi-regular complexity model for the public UOV core tuple of TSUOV.
No tensor/whipping matrices E are used: TSUOV publishes the core tuple
(P_1,...,P_m1) separately over F_(31^2).
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from math import comb, log2


PROFILES = (
    # name, n, o, m1, p, extension_degree
    ("TSUOV-128", 64, 4, 61, 31, 2),
    ("TSUOV-256", 119, 5, 114, 31, 2),
    ("TSUOV-512", 230, 12, 218, 31, 2),
)


def truncated_monomials(n: int, truncation: int, degree: int) -> int:
    """T(n, p^ell, d) from TSUOV Eq. (56)."""
    if degree < 0:
        return 0
    stop = min(n, degree // truncation)
    return sum(
        (-1) ** i
        * comb(n, i)
        * comb(degree - i * truncation + n - 1, n - 1)
        for i in range(stop + 1)
    )


def predicted_kernel_dimension(
    n: int, equations: int, truncation: int, degree: int
) -> int:
    """Coefficient of TSUOV Eq. (58).

    [(1+...+z^(s-1))^n / (1+z^2+...+z^(2(s-1)))^equations]_degree

    The denominator has the compact form (1-z^2)/(1-z^(2s)).
    This dimension is the source's Conjecture 1 (semi-regularity) model,
    not an unconditionally determined rank.
    """
    period = 2 * truncation
    value = 0
    shift = 0
    while shift <= degree:
        value += truncated_monomials(n, truncation, degree - shift)
        if shift + 2 <= degree:
            value -= truncated_monomials(n, truncation, degree - shift - 2)
        shift += period
    return value


def first_solving_degree(
    n: int, equations: int, oil_dimension: int, truncation: int
) -> tuple[int | None, int | None]:
    """Return the source's D and the predicted kernel dimension at D."""
    maximum = oil_dimension * (truncation - 1)
    for degree in range(2, maximum + 1):
        target = truncated_monomials(oil_dimension, truncation, degree)
        kernel = predicted_kernel_dimension(
            n, equations, truncation, degree
        )
        if kernel <= target:
            return degree, kernel
    return None, None


def wedge_complexity(
    n: int, oil_dimension: int, equations: int, truncation: int
) -> dict:
    degree, kernel = first_solving_degree(
        n, equations, oil_dimension, truncation
    )
    result = {
        "n": n,
        "oil_dimension": oil_dimension,
        "equations": equations,
        "truncation": truncation,
        "maximum_degree_checked": oil_dimension * (truncation - 1),
        "D": degree,
        "predicted_kernel_dimension": kernel,
        "complexity_field_multiplications": None,
        "log2_complexity": None,
    }
    if degree is not None:
        source_monomials = truncated_monomials(n, truncation, degree)
        target_monomials = truncated_monomials(
            oil_dimension, truncation, degree
        )
        complexity = (
            3
            * comb(n + 1, 2)
            * (source_monomials - target_monomials + 1) ** 2
        )
        result["complexity_field_multiplications"] = complexity
        result["log2_complexity"] = log2(complexity)
    return result


@dataclass
class ProfileResult:
    profile: str
    n: int
    o: int
    m1: int
    base_characteristic: int
    extension_degree: int
    core_field_size: int
    wedge_reconciliation: list[dict]
    wedge_intersection_core: list[dict]
    intersection_projection_probability_logq: int
    status: str


def analyze_profile(
    name: str, n: int, o: int, m1: int, p: int, extension_degree: int
) -> ProfileResult:
    reconciliations = []
    intersections = []
    for ell in range(1, extension_degree + 1):
        truncation = p**ell
        for reduced_oil in range(1, o + 1):
            reconciliations.append(
                wedge_complexity(n, reduced_oil, m1, truncation)
            )
        intersections.append(
            wedge_complexity(n - 1, 1, 3 * m1 - 2, truncation)
        )

    no_reconciliation = all(x["D"] is None for x in reconciliations)
    no_intersection = all(x["D"] is None for x in intersections)
    status = (
        "source_model_condition_fails"
        if no_reconciliation and no_intersection
        else "source_model_condition_meets"
    )
    return ProfileResult(
        profile=name,
        n=n,
        o=o,
        m1=m1,
        base_characteristic=p,
        extension_degree=extension_degree,
        core_field_size=p**extension_degree,
        wedge_reconciliation=reconciliations,
        wedge_intersection_core=intersections,
        intersection_projection_probability_logq=n - 3 * o + 1,
        status=status,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    results = [analyze_profile(*profile) for profile in PROFILES]
    payload = [asdict(result) for result in results]
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    for result in results:
        print(
            f"{result.profile}: n={result.n} o={result.o} m1={result.m1}; "
            f"core field F_{result.core_field_size}; {result.status}"
        )
        for group in (
            result.wedge_reconciliation,
            result.wedge_intersection_core,
        ):
            for item in group:
                print(
                    "  "
                    f"instance=({item['n']},{item['oil_dimension']},"
                    f"{item['equations']}) trunc={item['truncation']}: "
                    f"D={item['D']} after degrees "
                    f"2..{item['maximum_degree_checked']}"
                )


if __name__ == "__main__":
    main()
