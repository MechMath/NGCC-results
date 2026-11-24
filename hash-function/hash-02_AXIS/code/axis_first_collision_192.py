#!/usr/bin/env python3
"""Exact GF(2) certificate for the AXIS first-collision obstruction.

The map below is L in the AXIS register-difference recurrence

    Delta x_{t+1} = L(Delta x_t) xor V * delta b_t,

with bit i represented by 1 << i.  It contains only XOR, shifts, masks,
and parity checks, so every assertion is an exact finite-field identity.
"""

MASK = (1 << 192) - 1
V = (1 << 65) | (1 << 74) | (1 << 89) | (1 << 161) | (1 << 177) | (1 << 187)
P = (1 << 66) | (1 << 75) | (1 << 90) | (1 << 162) | (1 << 178) | (1 << 188)
A = (1 << 32) | (1 << 12) | (1 << 0)
B = (1 << 125) | (1 << 107) | (1 << 96)
VA = (1 << 161) | (1 << 177) | (1 << 187)
VB = (1 << 65) | (1 << 74) | (1 << 89)

# A left-annihilating test vector for V,L(V),...,L^190(V).  It has
# w.P = 1 and w.L^k(V) = 0 for 0 <= k <= 190.
W_SUPPORT = [
    1, 2, 3, 8, 11, 12, 14, 18, 19, 21, 24, 26, 31, 32, 33, 34,
    35, 36, 37, 39, 40, 44, 45, 47, 49, 51, 52, 54, 59, 63, 65, 68,
    69, 71, 72, 73, 74, 75, 77, 78, 81, 82, 85, 86, 88, 89, 90, 93,
    95, 97, 98, 99, 102, 106, 108, 110, 111, 112, 114, 116, 117, 119,
    121, 124, 126, 130, 131, 132, 136, 137, 138, 139, 140, 142, 144,
    145, 146, 150, 153, 156, 158, 159, 162, 163, 167, 169, 171, 173,
    174, 175, 177, 178, 179, 180, 181, 188, 190,
]
W = sum(1 << i for i in W_SUPPORT)
W_HEX = 0x503eea8cd2475f1c52b5d44ea7666fb2885ab1bf852c590e


def parity(x: int) -> int:
    return x.bit_count() & 1


def rho(x: int) -> int:
    """Rotate old bit i to new bit i-1 modulo 192."""
    return (x >> 1) | ((x & 1) << 191)


def L(x: int) -> int:
    y = rho(x)
    if parity(x & A):
        y ^= VA
    if parity(x & B):
        y ^= VB
    return y & MASK


def dot(x: int, y: int) -> int:
    return parity(x & y)


def main() -> None:
    assert W == W_HEX
    assert L(V) == ((1 << 64) | (1 << 73) | (1 << 88) |
                    (1 << 160) | (1 << 176) | (1 << 186))

    x = V
    for _ in range(191):
        assert dot(W, x) == 0
        x = L(x)
    assert dot(W, P) == 1
    assert len(W_SUPPORT) == len(set(W_SUPPORT)) == 97
    print("verified: w annihilates V,L(V),...,L^190(V); w.P = 1")
    print(f"w weight = {len(W_SUPPORT)}")


if __name__ == "__main__":
    main()
