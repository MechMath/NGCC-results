#!/usr/bin/env python3
"""Local source-level probe for Laurus profile interactions.

This is a research probe, not execution evidence. It implements the public
permutation from the allowlisted specification to test algebraic predictions.
"""

from __future__ import annotations

MASK = (1 << 64) - 1
RC = [
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
]
TS = [
    [31, 1, 4, 21, 22],
    [19, 12, 15, 34, 13],
    [28, 35, 58, 9, 23],
    [55, 18, 5, 27, 44],
    [14, 43, 53, 20, 25],
]


def rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & MASK


def rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (64 - n))) & MASK


def permutation(bits: str) -> str:
    if len(bits) != 1600:
        raise ValueError(len(bits))
    state = [[0] * 5 for _ in range(5)]
    for plane in range(5):
        for lane in range(5):
            off = (plane * 5 + lane) * 64
            state[plane][lane] = int(bits[off : off + 64], 2)

    for rnd in range(16):
        state[0][0] ^= RC[rnd]
        chi = [[0] * 5 for _ in range(5)]
        for bit in range(64):
            for lane in range(5):
                a = [(state[plane][lane] >> (63 - bit)) & 1 for plane in range(5)]
                b = [
                    (a[0] & a[2] & a[3])
                    ^ (a[2] & a[3] & a[4])
                    ^ (a[0] & a[4])
                    ^ (a[3] & a[4])
                    ^ a[1],
                    (a[1] & a[3] & a[4]) ^ (a[0] & a[1]) ^ a[2],
                    (a[1] & a[2]) ^ a[3],
                    (a[2] & a[3]) ^ a[4],
                    (a[3] & a[4]) ^ a[0],
                ]
                for plane, value in enumerate(b):
                    chi[plane][lane] |= value << (63 - bit)
        state = chi

        theta = [[0] * 5 for _ in range(5)]
        for plane in range(5):
            xs = state[plane]
            e = 0
            f = 0
            for x in xs:
                e ^= x
            for lane, x in enumerate(xs):
                f ^= rotl(x, TS[plane][lane])
            for lane, x in enumerate(xs):
                theta[plane][lane] = x ^ rotr(e, TS[plane][lane]) ^ f

        state = [[0] * 5 for _ in range(5)]
        for i in range(5):
            for j in range(5):
                state[i][j] = theta[(i + 2 * j) % 5][(3 * i + 3 * j) % 5]

    return "".join(f"{state[i][j]:064b}" for i in range(5) for j in range(5))


def xor(a: str, b: str) -> str:
    return "".join("1" if x != y else "0" for x, y in zip(a, b))


def empty_chunk(c: int, fid: int) -> str:
    q = (1 << 63) * fid + c
    s0 = "0" * (1536 - 64) + f"{q:064b}"
    final = "1" + "0" * 511
    x = s0 + final
    u = x[-1536:]
    v = x[-1088:]
    selector = "1" + "0" + f"{0:062b}"
    return xor(permutation(selector + u)[-1088:], v)


if __name__ == "__main__":
    outputs = {
        "512": empty_chunk(512, 0),
        "768": empty_chunk(768, 0),
        "1024": empty_chunk(1024, 0),
        "XOF": empty_chunk(512, 1),
    }
    for name, digest in outputs.items():
        print(name, digest[:64], digest[-64:])
    print("P changes on last-64 delta:", permutation("0" * 1600) != permutation("0" * 1536 + f"{512:064b}"))
    print("hash512 == hash768:", outputs["512"] == outputs["768"])
    print("hash512 == hash1024:", outputs["512"] == outputs["1024"])
    print("hash512 == xof:", outputs["512"] == outputs["XOF"])
