#!/usr/bin/env python3
"""Exact finite check supporting the Duet cross-profile separator.

This checks word-level index arithmetic for every padding position in 192..767.
It is an independent audit, not a cryptographic hardness experiment.
"""

SIGMA12 = (8, 2, 11, 0, 5, 9, 3, 10, 1, 7, 4, 6)
SIGMA17 = (9, 2, 15, 0, 6, 12, 4, 16, 1, 10, 7, 14, 3, 11, 5, 13, 8)


def main() -> None:
    # Each tuple entry is None for a structural zero and an integer word index
    # for a copied padded word. Compare only the first 12 outputs.
    p12 = tuple(range(12))
    p17 = tuple(range(12)) + (None,) * 5
    left = tuple(p12[i] for i in SIGMA12)
    right = tuple(p17[i] for i in SIGMA17[:12])

    # Equality of the two tuples imposes every one of these word constraints.
    equalities = set()
    forced_zero = {word for word, other in zip(left, right) if other is None}
    for a, b in zip(left, right):
        if a is not None and b is not None and a != b:
            equalities.add(tuple(sorted((a, b))))

    changed = True
    while changed:
        changed = False
        for a, b in equalities:
            if a in forced_zero and b not in forced_zero:
                forced_zero.add(b)
                changed = True
            if b in forced_zero and a not in forced_zero:
                forced_zero.add(a)
                changed = True

    covered = set()
    for length in range(192, 768):
        pad_word = length // 64
        # For lengths 192..767, the padding one bit is in word 3..11.
        if pad_word in forced_zero:
            covered.add(pad_word)
        else:
            raise AssertionError(
                f"length {length}: padding word {pad_word} survives equality"
            )

    print("sigma_12 first block:", left)
    print("sigma_17 first 12:", right)
    print("forced equalities:", sorted(equalities))
    print("words forced zero after equality propagation:", sorted(forced_zero))
    print("padding words checked contradictory:", sorted(covered))
    print("all 576 padding positions in 192..767 contradict first-12 equality")


if __name__ == "__main__":
    main()
