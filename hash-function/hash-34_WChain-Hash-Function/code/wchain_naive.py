#!/usr/bin/env python3
"""Column-oriented cross-check of wchain.py.

The production model in wchain.py evaluates all 64 columns with word operations.
This model extracts and updates each nine-bit column explicitly, then deserializes
the state again.  It shares only the specification tables with wchain.py.
"""

from __future__ import annotations

from wchain import (
    LEFT_ROWS, MASK64, PERM, PI16, RIGHT_DELTA, bits_from_bytes,
    bits_to_bytes, pad_bits, rotl, words_to_bytes,
)

MEF_ROTATIONS = (0, 1, 10, 20, 25, 32, 41, 46, 50)
CROSS_PAIRS = ((0, 0), (1, 3), (3, 1), (4, 4), (6, 6))


def scalar_sbox(x):
    a = [(x >> i) & 1 for i in range(9)]
    b = [a[i] ^ ((1 ^ a[(i + 1) % 9]) & a[(i + 2) % 9])
         for i in range(9)]
    return sum(bit << i for i, bit in enumerate(b))


def columns_to_state(columns, words):
    state = [0] * words
    for z, column in enumerate(columns):
        for i in range(words):
            state[i] |= ((column >> i) & 1) << z
    return state


def state_to_columns(state):
    return [sum(((state[i] >> z) & 1) << i for i in range(len(state)))
            for z in range(64)]


def scalar_sbox_layer(state):
    return columns_to_state([scalar_sbox(x) for x in state_to_columns(state)],
                            len(state))


def apply_perm(state):
    out = [0] * 9
    for i, value in enumerate(state):
        out[PERM[i]] = value
    return out


def apply_mix(state, rows):
    out = []
    for row in rows:
        value = 0
        for j, a in row:
            value ^= rotl(state[j], a)
        out.append(value)
    return out


def scalar_round(version, state, j):
    constant = PI16[j - 1]
    if version == 1:
        a = [state[i] ^ rotl(constant, i) for i in range(9)]
        return apply_mix(apply_perm(scalar_sbox_layer(a)), LEFT_ROWS)
    left = [state[i] ^ rotl(constant, i) for i in range(9)]
    right = [state[9 + i] ^ rotl(constant, i + 9) for i in range(9)]
    left, right = apply_perm(scalar_sbox_layer(left)), apply_perm(scalar_sbox_layer(right))
    for li, ri in CROSS_PAIRS:
        left[li], right[ri] = right[ri], left[li]
    right_rows = [tuple((j, (a + RIGHT_DELTA[i]) & 63) for j, a in row)
                  for i, row in enumerate(LEFT_ROWS)]
    return apply_mix(left, LEFT_ROWS) + apply_mix(right, right_rows)


def scalar_mef(a):
    return scalar_sbox_layer([rotl(x, MEF_ROTATIONS[i]) for i, x in enumerate(a)])


def scalar_expansion(version, block):
    words = 9 if version == 1 else 18
    rounds = 18 if version == 1 else 24
    p2, p1 = block[:words], block[words:]
    out = [p2, p1]
    for _ in range(2, rounds + 1):
        if version == 1:
            cur = [a ^ b for a, b in zip(scalar_mef(p1), p2)]
        else:
            cur = ([a ^ b for a, b in zip(scalar_mef(p1[:9]), p2[:9])]
                   + [a ^ b for a, b in zip(scalar_mef(p1[9:]), p2[9:])])
        out.append(cur)
        p2, p1 = p1, cur
    return out


def scalar_compression(version, v, block):
    rounds = 18 if version == 1 else 24
    out = scalar_expansion(version, block)
    x = v
    for j in range(1, rounds + 1):
        x = scalar_round(version, [a ^ b for a, b in zip(x, out[j - 1])], j)
    return [a ^ b ^ c for a, b, c in zip(x, out[rounds], v)]


def scalar_hash_bits(version, bits):
    words = 9 if version == 1 else 18
    block_bits = 128 * words
    blocks = []
    for raw in pad_bits(bits, block_bits):
        blocks.append([
            sum(bit << (63 - z) for z, bit in enumerate(raw[w * 64:(w + 1) * 64]))
            for w in range(2 * words)
        ])
    checksum = [0] * (2 * words)
    for block in blocks:
        checksum = [a ^ b for a, b in zip(checksum, block)]
    hm1, h = [0] * words, [0] * words
    for block in blocks:
        h, hm1 = [a ^ b for a, b in zip(scalar_compression(version, h, block), hm1)], h
    final = scalar_compression(version, h, checksum)
    return bits_from_bytes(words_to_bytes(final))[:512 if version == 1 else 1024]


def scalar_hash_bytes(version, data):
    return bits_to_bytes(scalar_hash_bits(version, bits_from_bytes(data)))
