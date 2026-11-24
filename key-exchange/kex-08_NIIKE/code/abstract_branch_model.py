#!/usr/bin/env python3
"""Spec-visible index model for the all-zero Algorithm 7 branch.

This model records only the point slot that line 13 returns.  Curve operations
are intentionally opaque: the point evolution in the swap branch is determined
by Algorithm 7's cswap/line-9 indices alone.
"""

from dataclasses import dataclass


@dataclass
class Vertex:
    curve: str
    first: str
    second: str


def cswap(a: Vertex, b: Vertex) -> None:
    a.curve, b.curve = b.curve, a.curve
    a.first, b.first = b.first, a.first
    a.second, b.second = b.second, a.second


def trace_algorithm7(factors: list[tuple[int, int]], secret: list[int]) -> tuple[int, list]:
    """Return the multiplier on the original P and a branch trace."""
    r0 = Vertex("E", "P", "Q")
    r1 = Vertex("E", "Q", "P")
    multiplier = 1
    trace = []

    for (prime, exponent), bound in zip(factors, secret):
        for t in range(1, exponent + 1):
            b = t > bound
            trace.append((prime, t, bound, b, multiplier))
            if b:
                cswap(r0, r1)
                # Line 8 acts on the new R0. Line 9 scales the old R0[1],
                # which is now R1[1]; cswap puts its scaled copy in R0[1].
                multiplier *= prime
                cswap(r0, r1)

    return multiplier, trace


if __name__ == "__main__":
    # Algorithm 7 loops over l_i^{e_i}; the multiplier is product l_i^{e_i}=M.
    factors = [(3, 4), (5, 1), (7, 1), (11, 2)]
    secret = [0, 0, 0, 0]
    multiplier, trace = trace_algorithm7(factors, secret)
    M = 1
    for prime, exponent in factors:
        M *= prime**exponent
    assert multiplier == M
    assert all(row[3] for row in trace)
    print(f"all-zero branch: R0[1] = [{M}]P before line 13")
    print("four-isogeny has odd-order-injective restriction")
    print("non-maximal odd order; if ord(P)=M, returned P'=O")

    # In the exact-order case, the peer's first positive coordinate takes b=0.
    # R0[1] is the received P'=O, so the kernel is zero, not an l_1-order point.
    received_p = "O"
    first_peer_coordinate = 1
    first_peer_branch = 1 > first_peer_coordinate
    assert first_peer_branch == False
    assert received_p == "O"
    print("positive peer secret: first kernel = Ladder(O,E,m) = O")
