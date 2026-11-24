#!/usr/bin/env python3
"""Audit the Laurus permutation and short-message squeeze equation.

This is a local audit note, not crypto_run evidence. It follows the
allowlisted hash-14 PDF's MSB-left conventions.
"""

MASK64 = (1 << 64) - 1
MASK1600 = (1 << 1600) - 1

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

SBOX = [
    0, 2, 4, 23, 8, 10, 14, 13, 16, 18, 20, 15, 28, 30, 26, 17,
    1, 19, 5, 6, 9, 27, 31, 12, 25, 11, 29, 22, 21, 7, 3, 24,
]

ROTS = [
    [31, 1, 4, 21, 22],
    [19, 12, 15, 34, 13],
    [28, 35, 58, 9, 23],
    [55, 18, 5, 27, 44],
    [14, 43, 53, 20, 25],
]


def rol(x, n):
    return ((x << n) | (x >> (64 - n))) & MASK64


def ror(x, n):
    return ((x >> n) | (x << (64 - n))) & MASK64


def theta_plane(words, rots):
    e = 0
    f = 0
    for x, rot in zip(words, rots):
        e ^= x
        f ^= ror(x, rot)
    return [x ^ rol(e, rot) ^ f for x, rot in zip(words, rots)]


def pi_forward(planes):
    # Representation planes[source_plane][source_lane].
    out = [[0] * 5 for _ in range(5)]
    for i in range(5):
        for j in range(5):
            out[i][j] = planes[(i + 2 * j) % 5][(3 * i + 3 * j) % 5]
    return out


def permute(x):
    assert x >> 1600 == 0
    planes = []
    for i in range(5):
        plane = []
        for j in range(5):
            shift = 1600 - 64 * (i * 5 + j + 1)
            plane.append((x >> shift) & MASK64)
        planes.append(plane)

    for rnd in range(16):
        planes[0][0] ^= RC[rnd]
        for j in range(5):
            vals = [planes[i][j] for i in range(5)]
            columns = []
            for bit in range(64):
                v = sum(((vals[i] >> bit) & 1) << i for i in range(5))
                w = SBOX[v]
                columns.append(w)
            for i in range(5):
                planes[i][j] = sum(((columns[bit] >> i) & 1) << bit
                                   for bit in range(64))
        planes = [theta_plane(plane, rots) for plane, rots in zip(planes, ROTS)]
        planes = pi_forward(planes)

    out = 0
    for i in range(5):
        for j in range(5):
            out = (out << 64) | planes[i][j]
    return out


def bits(x, n):
    return x & ((1 << n) - 1)


def short_message_chunk(c, fid, msg, outlen, m, selector=0):
    if m == 0 or (m - 512) % (1536 - c) != 0:
        zeros = (1536 - c) - 1 - ((m - 512) % (1536 - c))
        final = (msg << (1 + zeros)) | (1 << zeros)
    else:
        final = msg
    assert final.bit_length() <= 512
    assert 0 <= selector < 1 << 62

    n = (fid << 63) | c
    state = n
    u = bits((state << 512) | final, 1536)
    v = bits((state << 512) | final, 1088)
    d = 0 if m < 512 else 1
    tag = (1 << 63) | (d << 62) | selector
    chunk = bits(permute((tag << 1536) | u), 1088) ^ v
    return bits(chunk, outlen)


def main():
    msgs = {
        "empty": (0, 0),
        "one": (1, 1),
        "ones512": ((1 << 512) - 1, 512),
        "z": (1 << 511, 512),
    }
    for name, (msg, m) in msgs.items():
        print(name)
        for c in (512, 768, 1024):
            for fid in (0, 1):
                h = short_message_chunk(c, fid, msg, 1088, m)
                print(c, fid, f"{h:0272x}")


if __name__ == "__main__":
    main()
