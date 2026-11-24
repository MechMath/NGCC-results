#!/usr/bin/env python3
"""Reproduce CROSS Security Details v2.2 Theorem 6 (COLL) on Qing Luan tuples."""

import json
import math


P = 127
Z = 7
LP = math.log2(P)
LZ = math.log2(Z)


def log2sum(xs):
    m = max(xs)
    return m + math.log2(sum(2.0 ** (x - m) for x in xs))


def coll_bits(n, k):
    rows = []
    for ell in range(n - k + 1):
        lo = (k + ell) // 2
        hi = k + ell - lo
        la = lo * LZ
        lb = hi * LZ
        memory = min(la, lb) + math.log2(min(lo, hi))
        ca = la + math.log2(lo * LZ + ell * LP)
        cb = lb + math.log2(hi * LZ + ell * LP)
        cc = la + lb - ell * LP + math.log2((k + ell) * LP)
        solutions = math.log2(1.0 + 2.0 ** (n * LZ + (k - n) * LP))
        total = log2sum([ca, cb, cc]) - solutions + math.log2(memory)
        rows.append(
            {
                "ell": ell,
                "log2_time": total,
                "log2_memory": memory,
                "log2_expected_solutions": solutions,
            }
        )
    return min(rows, key=lambda row: row["log2_time"])


def main():
    tuples = [(127, 76), (187, 111), (251, 150), (370, 221), (491, 293)]
    results = {f"{n},{k}": coll_bits(n, k) for n, k in tuples}
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
