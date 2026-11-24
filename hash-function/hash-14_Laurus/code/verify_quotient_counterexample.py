#!/usr/bin/env python3
"""Exact 16-round counterexample to the proposed q-state preservation lemma.

Bit strings are integers with the leftmost (most significant) bit in bit
position n-1, matching the specification.  Run this file to print PASS only
when q(S)=q(S') but q(F(S,M))=q(F(S',M)) is false.
"""

MASK64 = (1 << 64) - 1
B = 1536

RC = [
    0xB7E151628AED2A6A, 0xAF82A3CD15DAD4D7, 0x9F4546922BB529AD,
    0xFECA8C2C576AD359, 0x3DD51950AED526B1, 0x7BAA32A15DAA4D62,
    0xF7546542BB549AC4, 0x2EE8CB8D76A9B58B, 0x5DD1971AED536B16,
    0xBBA32E35DAA6D62C, 0xB7065D63B54D2C5B, 0xAE4CBBCF6A9AD8B5,
    0x9CD97696D5353169, 0xF9F2EC25AA6AE2D1, 0x33A5D94354D545A1,
    0x674BB286A9AA8B42,
]

THETA = [
    [31, 1, 4, 21, 22],
    [19, 12, 15, 34, 13],
    [28, 35, 58, 9, 23],
    [55, 18, 5, 27, 44],
    [14, 43, 53, 20, 25],
]


def bits(value, width):
    return [(value >> (width - 1 - i)) & 1 for i in range(width)]


def value(words):
    out = 0
    for bit in words:
        out = (out << 1) | bit
    return out


def rol64(value, amount):
    return ((value << amount) | (value >> (64 - amount))) & MASK64


def permutation(state):
    flat = bits(state, 1600)
    planes = [
        [[flat[(i * 5 + j) * 64 + k] for k in range(64)] for j in range(5)]
        for i in range(5)
    ]

    for round_constant in RC:
        planes[0][0] = bits(value(planes[0][0]) ^ round_constant, 64)

        after_chi = [[[0] * 64 for _ in range(5)] for _ in range(5)]
        for j in range(5):
            for k in range(64):
                x = [planes[i][j][k] for i in range(5)]
                y = [
                    x[0] & x[2] & x[3] ^ x[2] & x[3] & x[4]
                    ^ x[0] & x[4] ^ x[3] & x[4] ^ x[1],
                    x[1] & x[3] & x[4] ^ x[0] & x[1] ^ x[2],
                    x[1] & x[2] ^ x[3],
                    x[2] & x[3] ^ x[4],
                    x[3] & x[4] ^ x[0],
                ]
                for i in range(5):
                    after_chi[i][j][k] = y[i]

        after_theta = [[[0] * 64 for _ in range(5)] for _ in range(5)]
        for i in range(5):
            x = [value(after_chi[i][j]) for j in range(5)]
            e = x[0] ^ x[1] ^ x[2] ^ x[3] ^ x[4]
            f = 0
            for j in range(5):
                f ^= rol64(x[j], THETA[i][j])
            for j in range(5):
                right_rotated_e = (
                    rol64(e, 64 - THETA[i][j]) if THETA[i][j] else e
                )
                after_theta[i][j] = bits(
                    x[j] ^ right_rotated_e ^ f, 64
                )

        after_pi = [[[0] * 64 for _ in range(5)] for _ in range(5)]
        for i in range(5):
            for j in range(5):
                after_pi[i][j] = after_theta[(i + 2 * j) % 5][
                    (3 * i + 3 * j) % 5
                ]
        planes = after_pi

    flat_out = []
    for i in range(5):
        for j in range(5):
            flat_out += planes[i][j]
    return value(flat_out)


def g0(message, state, capacity):
    rate = B - capacity
    x = (message << B) | state
    msb_b = x >> rate
    lsb_r = x & ((1 << rate) - 1)
    msb_c = message >> (rate - capacity)
    return (msb_b << B) | (lsb_r << capacity) | msb_c


def absorb(state, message, counter, capacity):
    mixed = g0(message, state, capacity)
    perm_input = (counter << B) | (mixed >> B)
    return (permutation(perm_input) & ((1 << B) - 1)) ^ (mixed & ((1 << B) - 1))


S = int(
    "afbd67f9619699cfe1988ad9f06c144a025b413f8a9a021e648a7dd06839eb9"
    "05b6e6e307d4bedc51431193e6c3f3391a2b8f1ff1fd42a29755d4c13a902931"
    "cd447e35b8b6d8fe442e3d437204e52db2221a58008a05a6c4647159c324c9859"
    "b810e766ec9d28663ca828dd5f4b3b2e4b06ce60741c7a87ce42c8218072e8c35"
    "bf992dc9e9c616612e7696a6cecc1b78e510617311d8a3c2ce6f447ed4d57b1e2"
    "feb89414c343c1027c4d1c386bbc4cd613e30d8f16adf91b7584a2265b1f5",
    16,
)
M = int(
    "a11d459a2f978d8719999e3fa46d6753ec148cb48e73ca47ea90a8f0d66b829e"
    "6a8ac4ba05805975ed2f89d94a2f20aaf3c64af775a89294c2cd789a380208a9a"
    "d45f23d3b1a11df587fd2803bab6c398d88348a7eed8d14f06d3fef701966a0c3"
    "81e88f38c0c8fd8712b8bc076f3787b9d179e06c0fd4f5f8130c4237730edf",
    16,
)

# The only changed state bit is S[0], the first of the proposed discarded bits.
S2 = S ^ (1 << (B - 1))

F = absorb(S, M, 0, 512)
F2 = absorb(S2, M, 0, 512)

Q_MASK = (1 << 1024) - 1
print(f"S  = {S:0384x}")
print(f"S' = {S2:0384x}")
print(f"M  = {M:0256x}")
print(f"F  = {F:0384x}")
print(f"F' = {F2:0384x}")

assert S.bit_length() <= B and S2.bit_length() <= B and M.bit_length() <= 1024
assert (S ^ S2) == (1 << (B - 1))
assert (S & Q_MASK) == (S2 & Q_MASK)
assert (F & Q_MASK) != (F2 & Q_MASK)
print("PASS: hypotheses hold and the asserted preservation conclusion is false")
print(f"q(F) xor q(F') has Hamming weight {(F ^ F2 & Q_MASK).bit_count()}")
