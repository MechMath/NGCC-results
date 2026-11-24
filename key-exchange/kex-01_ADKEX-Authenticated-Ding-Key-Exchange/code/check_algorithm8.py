#!/usr/bin/env python3
"""Finite checks for the literal-domain analysis of ADKEX Algorithm 8.

This is a reproducible note, not a proof-graph evidence object.
"""

from collections import Counter
from itertools import product
from math import comb


PROFILES = ((3, 256), (2, 256), (3, 512))


def sum_indices(i: int, eta: int, second: bool) -> range:
    start = i * 2 * eta
    if second:
        # Printed upper limit is eta, inclusive.
        return range(start + eta, start + 2 * eta + 1)
    return range(start, start + eta)


def cbd_output(bits: tuple[int, ...], eta: int, n: int) -> tuple[int, ...]:
    """The intended blockwise CBD sampler with eta bits in each half."""
    out = []
    for i in range(n):
        first = bits[i * 2 * eta : i * 2 * eta + eta]
        second = bits[i * 2 * eta + eta : (i + 1) * 2 * eta]
        out.append(sum(first) - sum(second))
    return tuple(out)


def repaired_upper_read(bits: tuple[int, ...], eta: int, n: int) -> tuple[int, ...]:
    """Preserve the input, retain printed upper limit, and set b[L] = 0."""
    length = len(bits)
    out = []
    for i in range(n):
        first = sum(bits[j] for j in sum_indices(i, eta, False))
        second = sum(bits[j] if j < length else 0
                     for j in sum_indices(i, eta, True))
        out.append(first - second)
    return tuple(out)


def main() -> None:
    for eta, n in PROFILES:
        length = 2 * eta * n
        last = max(sum_indices(n - 1, eta, True))
        assert last == length
        assert length not in range(length)
        print(f"eta={eta} n={n}: declared length={length}, final read={last}")

    eta, n = 2, 1
    counts = Counter(
        cbd_output(bits, eta, n)
        for bits in product((0, 1), repeat=2 * eta * n)
    )
    expected = Counter({
        (d,): sum(
            comb(2, a) * comb(2, a - d)
            for a in range(3)
            if 0 <= a - d <= 2
        )
        for d in range(-2, 3)
    })
    assert counts == expected
    print("eta=2 n=1 exhaustive zero-extended distribution:", sorted(counts.items()))

    eta, n = 2, 256
    witness = tuple(1 if i == 4 else 0 for i in range(2 * eta * n))
    intended = cbd_output(witness, eta, n)
    repaired = repaired_upper_read(witness, eta, n)
    assert (intended[0], intended[1]) == (0, 1)
    assert (repaired[0], repaired[1]) == (-1, 1)
    print("eta=2 n=256 b[4]=1 witness: intended=(0,1), repaired=(-1,1)")

    for eta in (2, 3):
        atoms = {
            d: sum(comb(eta, a) * comb(eta + 1, a - d)
                   for a in range(eta + 1) if 0 <= a - d <= eta + 1)
            for d in range(-eta - 1, eta + 1)
        }
        assert sum(atoms.values()) == 2 ** (2 * eta + 1)
        assert sum(d * count for d, count in atoms.items()) / sum(atoms.values()) == -0.5
        print(f"eta={eta} repaired nonfinal atom counts:", atoms)


if __name__ == "__main__":
    main()
