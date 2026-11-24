#!/usr/bin/env python3
"""Small exact checks of byte-integral propagation in Wish-512.

This is a research note, not execution evidence for an attack claim.
"""


def gf_mul(a: int, b: int) -> int:
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return r


def gf_pow(a: int, n: int) -> int:
    r = 1
    while n:
        if n & 1:
            r = gf_mul(r, a)
        a = gf_mul(a, a)
        n >>= 1
    return r


def aes_sbox(x: int) -> int:
    y = 0 if x == 0 else gf_pow(x, 254)
    z = y
    for shift in range(1, 5):
        z ^= ((y << shift) | (y >> (8 - shift))) & 0xFF
    return z ^ 0x63


SBOX = [aes_sbox(x) for x in range(256)]


def sub_bytes(s):
    return [SBOX[x] for x in s]


def shift_rows(s):
    out = [0] * 16
    for row in range(4):
        for col in range(4):
            out[row + 4 * ((col + row) % 4)] = s[row + 4 * col]
    return out


def mix_columns(s):
    out = [0] * 16
    for col in range(4):
        a = s[4 * col : 4 * col + 4]
        out[4 * col : 4 * col + 4] = [
            gf_mul(2, a[0]) ^ gf_mul(3, a[1]) ^ a[2] ^ a[3],
            a[0] ^ gf_mul(2, a[1]) ^ gf_mul(3, a[2]) ^ a[3],
            a[0] ^ a[1] ^ gf_mul(2, a[2]) ^ gf_mul(3, a[3]),
            gf_mul(3, a[0]) ^ a[1] ^ a[2] ^ gf_mul(2, a[3]),
        ]
    return out


def aes_round(s):
    return mix_columns(shift_rows(sub_bytes(s)))


RCONS = [
    bytes.fromhex(x)
    for x in (
        "243f6a8885a308d313198a2e03707344 "
        "497fd5110b4610a72632155d06e1e788 "
        "92ffab22168c204e4d652aba0cc2ce11 "
        "25fe56452c19419c9acb557418859d22 "
        "4bfcac8a593282393597aae9300b3b45 "
        "96f85815b26505736b2f54d26116778a "
        "2df0b02a64cb0ae7d75fa8a5c32cef15 "
        "5be06055c99714ceafbe504a8759de2a"
    ).split()
]

MIX512_ROWS = [
    [0, 16, 32, 48, 1, 17, 33, 49, 64, 80, 96, 112, 65, 81, 97, 113],
    [8, 24, 40, 56, 9, 25, 41, 57, 72, 88, 104, 120, 73, 89, 105, 121],
    [4, 20, 36, 52, 5, 21, 37, 53, 68, 84, 100, 116, 69, 85, 101, 117],
    [12, 28, 44, 60, 13, 29, 45, 61, 76, 92, 108, 124, 77, 93, 109, 125],
    [2, 18, 34, 50, 3, 19, 35, 51, 66, 82, 98, 114, 67, 83, 99, 115],
    [10, 26, 42, 58, 11, 27, 43, 59, 74, 90, 106, 122, 75, 91, 107, 123],
    [6, 22, 38, 54, 7, 23, 39, 55, 70, 86, 102, 118, 71, 87, 103, 119],
    [14, 30, 46, 62, 15, 31, 47, 63, 78, 94, 110, 126, 79, 95, 111, 127],
]
MIX512 = [i for row in MIX512_ROWS for i in row]

MIX1024_ROWS = [
    [0, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240],
    [8, 24, 40, 56, 72, 88, 104, 120, 136, 152, 168, 184, 200, 216, 232, 248],
    [4, 20, 36, 52, 68, 84, 100, 116, 132, 148, 164, 180, 196, 212, 228, 244],
    [12, 28, 44, 60, 76, 92, 108, 124, 140, 156, 172, 188, 204, 220, 236, 252],
    [2, 18, 34, 50, 66, 82, 98, 114, 130, 146, 162, 178, 194, 210, 226, 242],
    [10, 26, 42, 58, 74, 90, 106, 122, 138, 154, 170, 186, 202, 218, 234, 250],
    [6, 22, 38, 54, 70, 86, 102, 118, 134, 150, 166, 182, 198, 214, 230, 246],
    [14, 30, 46, 62, 78, 94, 110, 126, 142, 158, 174, 190, 206, 222, 238, 254],
    [1, 17, 33, 49, 65, 81, 97, 113, 129, 145, 161, 177, 193, 209, 225, 241],
    [9, 25, 41, 57, 73, 89, 105, 121, 137, 153, 169, 185, 201, 217, 233, 249],
    [5, 21, 37, 53, 69, 85, 101, 117, 133, 149, 165, 181, 197, 213, 229, 245],
    [13, 29, 45, 61, 77, 93, 109, 125, 141, 157, 173, 189, 205, 221, 237, 253],
    [3, 19, 35, 51, 67, 83, 99, 115, 131, 147, 163, 179, 195, 211, 227, 243],
    [11, 27, 43, 59, 75, 91, 107, 123, 139, 155, 171, 187, 203, 219, 235, 251],
    [7, 23, 39, 55, 71, 87, 103, 119, 135, 151, 167, 183, 199, 215, 231, 247],
    [15, 31, 47, 63, 79, 95, 111, 127, 143, 159, 175, 191, 207, 223, 239, 255],
]
MIX1024 = [i for row in MIX1024_ROWS for i in row]


def xor_lane0(s, value):
    out = s[:]
    out[:16] = [a ^ b for a, b in zip(out[:16], value)]
    return out


def mix_lanes(s, rounds, lanes, mix):
    for r in range(rounds):
        s = sum((aes_round(s[16 * k : 16 * k + 16]) for k in range(lanes)), [])
        s = xor_lane0(s, RCONS[r])
        if r % 2:
            s = [s[mix[i]] for i in range(16 * lanes)]
    return s


def sums(rounds, pos, base, lanes=8, mix=MIX512):
    result = [0] * (16 * lanes)
    distributions = [[] for _ in range(16 * lanes)]
    for x in range(256):
        state = base[:]
        state[pos] = x
        value = mix_lanes(state, rounds, lanes, mix)
        result = [a ^ b for a, b in zip(result, value)]
        for i, y in enumerate(value):
            distributions[i].append(y)
    return result, distributions


if __name__ == "__main__":
    for lanes, mix in ((8, MIX512), (16, MIX1024)):
        base = [0] * (16 * lanes)
        base[-1] = 1
        for r in range(1, 6):
            total, dist = sums(r, 0, base, lanes, mix)
            print(
                lanes,
                r,
                "nonzero_xor_bytes",
                sum(bool(x) for x in total),
                "full_support_bytes",
                sum(len(set(d)) == 256 for d in dist),
            )
