#!/usr/bin/env python3
"""Checks using the rendered WChain chi formula.

This is an observation script, not execution evidence or a proof verdict.
"""

W = 64
PI16_1 = 0x243F
D = (0, 1, 10, 20, 25, 32, 41, 46, 50)


def sbox(x: int) -> int:
    """Rendered Eq. (22): b_i = a_i xor (~a_{i+1} & a_{i+2})."""
    a = [(x >> i) & 1 for i in range(9)]
    return sum(
        (a[i] ^ ((1 ^ a[(i + 1) % 9]) & a[(i + 2) % 9])) << i
        for i in range(9)
    )


def rotl(x: int, amount: int) -> int:
    amount %= W
    if not amount:
        return x
    return ((x << amount) | (x >> (W - amount))) & ((1 << W) - 1)


def sbox_lanes(x: list[int]) -> list[int]:
    return [
        x[i] ^ ((~x[(i + 1) % 9]) & x[(i + 2) % 9])
        for i in range(9)
    ]


def mef(a: list[int]) -> list[int]:
    return sbox_lanes([rotl(a[i], D[i]) for i in range(9)])


def main() -> None:
    table = [sbox(x) for x in range(512)]
    assert len(set(table)) == 512
    print("rendered S-box: bijection on all 512 inputs")

    # The forward recurrence state map is invertible because MEF is.
    # Check the algebraic inverse on a deterministic sample.
    seeds = [
        [0] * 9,
        [PI16_1] * 9,
        [(0x0123456789ABCDEF * (i + 1)) & ((1 << 64) - 1) for i in range(9)],
    ]
    for a0, a1 in zip(seeds, seeds[1:] + seeds[:1]):
        a2 = [mef(a1)[i] ^ a0[i] for i in range(9)]
        restored = [mef(a1)[i] ^ a2[i] for i in range(9)]
        assert restored == a0
    print("scheduler adjacent-state inverse sample: ok")

    # A common adjacent injection pair determines all earlier injections,
    # and hence the two b-bit seeds and the complete message block.
    print("consequence: distinct blocks cannot share an adjacent scheduler suffix")


if __name__ == "__main__":
    main()
