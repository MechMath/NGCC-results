#!/usr/bin/env python3
"""Exact small-instance test of Phoenix TFORS forced-pruning conditioning.

The model is the uniform digest model from the Phoenix specification:
  * k distinct set indices are chosen without replacement from k' sets;
  * each selected set has one independently uniform intra-set position in [0,t);
  * acceptance is auth_count(leaves) <= auth_max.

The experiment reports:
  * acceptance probability;
  * exact fixed-key coverage after q accepted signing queries for an
    independently accepted target;
  * the same quantity for unconditioned signing and target digests;
  * the source's unconditioned ITSR upper bound.

Only small parameters are exact-enumerated.  This is a premise audit, not a
cryptanalytic attack.
"""

from __future__ import annotations

import argparse
import itertools
import json
from fractions import Fraction


def octopus_auth_count(leaves: tuple[int, ...], height: int) -> int:
    curr = sorted(leaves)
    count = 0
    for _ in range(height):
        parents = []
        i = 0
        while i < len(curr):
            node = curr[i]
            if i + 1 < len(curr) and curr[i + 1] == (node ^ 1):
                i += 2
            else:
                count += 1
                i += 1
            parents.append(node // 2)
        curr = sorted(set(parents))
    return count


def enumerate_digests(k_prime: int, k: int, t: int) -> list[tuple[tuple[tuple[int, int], ...], int]]:
    height = t.bit_length() - 1
    if (1 << height) != t:
        raise ValueError("t must be a power of two")
    if (k_prime & (k_prime - 1)) != 0:
        raise ValueError("k_prime must be a power of two")
    tree_height = height + (k_prime.bit_length() - 1)
    outcomes = []
    for sets in itertools.combinations(range(k_prime), k):
        for positions in itertools.product(range(t), repeat=k):
            leaves = tuple(sorted(pos * k_prime + j for j, pos in zip(sets, positions)))
            outcomes.append((tuple(zip(sets, positions)), octopus_auth_count(leaves, tree_height)))
    return outcomes


def covered(target: tuple[tuple[int, int], ...], queries: tuple[tuple[tuple[int, int], ...], ...]) -> bool:
    seen = set()
    for query in queries:
        seen.update(query)
    return all(leaf in seen for leaf in target)


def exact_coverage(
    outcomes: list[tuple[tuple[tuple[int, int], ...], int]],
    auth_max: int,
    q: int,
    condition: bool,
) -> Fraction:
    if condition:
        pool = [o for o in outcomes if o[1] <= auth_max]
    else:
        pool = outcomes
    if not pool:
        raise ValueError("acceptance event is empty")

    # Rewrite coverage via inclusion-exclusion over the k target leaves:
    # P(target covered) = sum_{S subset target} (-1)^|S| *
    # P(no leaf in S appeared among q signing digests).
    # This is much cheaper than enumerating q-tuples of digests.
    mass = Fraction(0, 1)
    for tgt, _ in pool:
        denom = len(pool)
        prob = Fraction(0, 1)
        for r in range(len(tgt) + 1):
            sign = -1 if r & 1 else 1
            for subset in itertools.combinations(tgt, r):
                forbidden = set(subset)
                allowed = sum(1 for sig, _ in pool if forbidden.isdisjoint(sig))
                prob += sign * Fraction(allowed, denom) ** q
        mass += prob / denom
    return mass


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--k-prime", type=int, default=4)
    ap.add_argument("--k", type=int, default=2)
    ap.add_argument("--t", type=int, default=4)
    ap.add_argument("--auth-max", type=int, default=4)
    ap.add_argument("--q-max", type=int, default=3)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    outcomes = enumerate_digests(args.k_prime, args.k, args.t)
    accepted = sum(1 for _, a in outcomes if a <= args.auth_max)
    hist: dict[int, int] = {}
    for _, a in outcomes:
        hist[a] = hist.get(a, 0) + 1

    comparisons = []
    source_factor = Fraction(args.k, args.k_prime * args.t)
    acceptance_probability = Fraction(accepted, len(outcomes))
    for q in range(1, args.q_max + 1):
        conditioned = exact_coverage(outcomes, args.auth_max, q, True)
        unconditioned = exact_coverage(outcomes, args.auth_max, q, False)
        source_bound = (1 - (1 - source_factor) ** q) ** args.k
        # A random final digest must both be accepted and be covered.  This is
        # the quantity bounded by the PORS+FP security sketch, not the ratio of
        # two *conditioned* target distributions alone.
        accepted_attack_probability = acceptance_probability * conditioned
        comparisons.append(
            {
                "q": q,
                "conditioned_exact": [conditioned.numerator, conditioned.denominator],
                "unconditioned_exact": [unconditioned.numerator, unconditioned.denominator],
                "source_unconditioned_bound": [source_bound.numerator, source_bound.denominator],
                "conditioned_over_unconditioned": [
                    (conditioned / unconditioned).numerator,
                    (conditioned / unconditioned).denominator,
                ],
                "accepted_attack_probability": [
                    accepted_attack_probability.numerator,
                    accepted_attack_probability.denominator,
                ],
                "accepted_attack_exceeds_source_bound": accepted_attack_probability > source_bound,
            }
        )

    report = {
        "schema": "phoenix.tfors-conditioning-exact/v1",
        "parameters": vars(args) | {"tree_height": (args.t.bit_length() - 1) + (args.k_prime.bit_length() - 1)},
        "digest_outcomes": len(outcomes),
        "auth_count_histogram": {str(k): v for k, v in sorted(hist.items())},
        "accepted_outcomes": accepted,
        "acceptance_probability": [accepted, len(outcomes)],
        "comparisons": comparisons,
        "interpretation": (
            "conditioned_exact is P(J covers all target leaves | accepted target), "
            "while accepted_attack_probability multiplies it by Pr(accepted target). "
            "The PORS+FP theorem must bound the latter and must also account for "
            "accepted-query histories. A large conditioning ratio alone is not an attack."
        ),
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)
        fh.write("\n")


if __name__ == "__main__":
    main()
