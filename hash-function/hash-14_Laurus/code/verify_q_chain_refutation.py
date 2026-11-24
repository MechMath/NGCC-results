#!/usr/bin/env python3
"""Reproduce the Laurus q-chain refutation from the allowlisted specification.

This is a source-level research script, not execution evidence.  It implements
Sections 2.1-2.3 of the specification with MSB-left state strings.
"""

MASK64 = (1 << 64) - 1
B = 1536

RC = (
    0xB7E151628AED2A6A,
    0xAF82A3CD15DAD4D7,
    0x9F4546922BB529AD,
    0xFECA8C2C576AD359,
    0x3DD51950AED526B1,
    0x7BAA32A15DAA4D62,
    0xF7546542BB549AC4,
    0x2EE8CB8D76A9B58B,
    0x5DD1971AED536B16,
    0xBBA32E35DAA6D62C,
    0xB7065D63B54D2C5B,
    0xAE4CBBCF6A9AD8B5,
    0x9CD97696D5353169,
    0xF9F2EC25AA6AE2D1,
    0x33A5D94354D545A1,
    0x674BB286A9AA8B42,
)

THETA = (
    (31, 1, 4, 21, 22),
    (19, 12, 15, 34, 13),
    (28, 35, 58, 9, 23),
    (55, 18, 5, 27, 44),
    (14, 43, 53, 20, 25),
)


def rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> ((64 - n) % 64))) & MASK64


def rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << ((64 - n) % 64))) & MASK64


def permutation(value: int) -> int:
    state = [
        [(value >> (1600 - 64 * (5 * i + j + 1))) & MASK64 for j in range(5)]
        for i in range(5)
    ]
    for rc in RC:
        state[0][0] ^= rc
        chi = [[0] * 5 for _ in range(5)]
        for j in range(5):
            a = [state[i][j] for i in range(5)]
            chi[0][j] = (
                (a[0] & a[2] & a[3])
                ^ (a[2] & a[3] & a[4])
                ^ (a[0] & a[4])
                ^ (a[3] & a[4])
                ^ a[1]
            )
            chi[1][j] = (a[1] & a[3] & a[4]) ^ (a[0] & a[1]) ^ a[2]
            chi[2][j] = (a[1] & a[2]) ^ a[3]
            chi[3][j] = (a[2] & a[3]) ^ a[4]
            chi[4][j] = (a[3] & a[4]) ^ a[0]
        theta = [[0] * 5 for _ in range(5)]
        for i in range(5):
            lanes = chi[i]
            e = 0
            f = 0
            for lane in lanes:
                e ^= lane
            for lane, shift in zip(lanes, THETA[i]):
                f ^= rotl(lane, shift)
            for j, (lane, shift) in enumerate(zip(lanes, THETA[i])):
                theta[i][j] = lane ^ rotr(e, shift) ^ f
        state = [
            [theta[(i + 2 * j) % 5][(3 * i + 3 * j) % 5] for j in range(5)]
            for i in range(5)
        ]
    out = 0
    for i in range(5):
        for j in range(5):
            out = (out << 64) | state[i][j]
    return out


def g0(message: int, state: int, capacity: int) -> int:
    rate = B - capacity
    x = (message << B) | state
    length = rate + B
    msb_b = x >> (length - B)
    lsb_r = x & ((1 << rate) - 1)
    msb_c = x >> (length - capacity)
    return (msb_b << B) | (lsb_r << capacity) | msb_c


def absorb(state: int, message: int, counter: int, capacity: int) -> int:
    packed = g0(message, state, capacity)
    perm_input = (counter << B) | (packed >> B)
    return (permutation(perm_input) & ((1 << B) - 1)) ^ (
        packed & ((1 << B) - 1)
    )


def main() -> None:
    capacity = 512
    state = 0
    changed = 1 << (B - 1)
    assert (state & ((1 << 1024) - 1)) == (
        changed & ((1 << 1024) - 1)
    )
    first = absorb(state, 0, 0, capacity)
    second = absorb(changed, 0, 0, capacity)
    first_q = first & ((1 << 1024) - 1)
    second_q = second & ((1 << 1024) - 1)
    assert first_q != second_q
    print(f"q(F(S,0))  = {first_q:0256x}")
    print(f"q(F(S',0)) = {second_q:0256x}")
    print("PASS")


if __name__ == "__main__":
    main()
