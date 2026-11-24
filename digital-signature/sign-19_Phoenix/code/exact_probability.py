#!/usr/bin/env python3
"""Exact occupancy law for 64 low-six-bit draws requiring 25 distinct values."""

from decimal import Decimal, getcontext
from math import comb, factorial

getcontext().prec = 100

bins = 64
draws = 64
needed = 25

# S(n, r): Stirling numbers of the second kind.
stirling = [[0] * (draws + 1) for _ in range(draws + 1)]
stirling[0][0] = 1
for n in range(1, draws + 1):
    for r in range(1, n + 1):
        stirling[n][r] = stirling[n - 1][r - 1] + r * stirling[n - 1][r]

# Number of length-64 sequences over 64 symbols using at most 24 distinct symbols.
failure_sequences = sum(
    comb(bins, r) * factorial(r) * stirling[draws][r]
    for r in range(needed)
)
probability = Decimal(failure_sequences) / Decimal(bins**draws)

print(f"failure_sequences={failure_sequences}")
print(f"total_sequences={bins**draws}")
print(f"failure_probability={probability}")
print(f"expected_failures_in_384_trials={probability * 384}")
print(f"zero_hit_probability_in_384_trials={(1 - probability) ** 384}")
