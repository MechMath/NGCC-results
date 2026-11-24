#!/usr/bin/env python3
"""Independent, source-literal check of XRH-1 state serialization.

This is a local deterministic audit, not crypto_run execution evidence.
Only the allowlisted original specification is used.
"""

import hashlib


S = [
    4, 14, 10, 5, 9, 24, 20, 0, 18, 28, 30, 21, 2, 23, 29, 13,
    22, 27, 15, 7, 26, 12, 16, 3, 8, 1, 19, 31, 25, 11, 17, 6,
]

# Rows are printed exactly as in the matrix equation on p. 10:
# [b3,b2,b1,b0]^T = M [a3,a2,a1,a0]^T.
M_PRINTED = [
    [3, 2, 1, 3],
    [3, 1, 4, 4],
    [1, 3, 6, 4],
    [2, 2, 3, 1],
]


def gf32_mul(a: int, b: int) -> int:
    """Multiply in F2[x]/(x^5+x^2+1)."""
    result = 0
    for bit in range(5):
        if (b >> bit) & 1:
            result ^= a << bit
    for bit in range(8, 4, -1):
        if (result >> bit) & 1:
            result ^= 0b100101 << (bit - 5)
    return result & 31


def xor_all(values) -> int:
    result = 0
    for value in values:
        result ^= value
    return result


def mds(values):
    """Apply the p. 10 equation literally to [a0,a1,a2,a3]."""
    descending = list(reversed(values))
    b_descending = [
        xor_all(gf32_mul(row[col], descending[col]) for col in range(4))
        for row in M_PRINTED
    ]
    return list(reversed(b_descending))


def shift_rows(source, kind: str, inverse: bool = False):
    result = [[0] * 64 for _ in range(20)]
    for row in range(20):
        group = row // 5
        if kind == "X":
            width, amount = 4, group
        elif kind == "Y":
            width, amount = 16, 4 * group
        else:
            width, amount = 64, 16 * group
        if inverse:
            amount = (-amount) % width
        for column in range(64):
            base = (column // width) * width
            destination = base + (column % width + amount) % width
            result[row][destination] = source[row][column]
    return result


def rnd(state, round_number: int, rc: int = 0):
    # Algorithm 3, lines 5-10: S, MDS, S on each 20-bit column.
    after_sbox = [[0] * 64 for _ in range(20)]
    for column in range(64):
        values = []
        for block in range(4):
            packed = 0
            for lane in range(5):
                # a_i = row 5i + 2 row(5i+1) + ... + 16 row(5i+4).
                packed |= state[5 * block + lane][column] << lane
            values.append(S[packed])
        mixed = [S[value] for value in mds(values)]
        for block in range(4):
            for lane in range(5):
                after_sbox[5 * block + lane][column] = (
                    mixed[block] >> lane
                ) & 1

    # Algorithm 3, lines 11-25: SR, column MDS, SR^{-1}.
    kind = "XYZ"[round_number % 3]
    shifted = shift_rows(after_sbox, kind)
    after_mds = [[0] * 64 for _ in range(20)]
    for column in range(64):
        values = []
        for block in range(4):
            packed = 0
            for lane in range(5):
                packed |= shifted[5 * block + lane][column] << lane
            values.append(packed)
        mixed = mds(values)
        for block in range(4):
            for lane in range(5):
                after_mds[5 * block + lane][column] = (
                    mixed[block] >> lane
                ) & 1
    result = shift_rows(after_mds, kind, inverse=True)

    # Algorithm 3, lines 27-28: row zero, column j receives bit j of RC_r.
    for column in range(64):
        result[0][column] ^= (rc >> column) & 1
    return result


def perm(state, begin: int = 0, end: int = 18):
    for round_number in range(begin, end):
        # The finite theorem fixes every round constant to zero.
        state = rnd(state, round_number, 0)
    return state


def from_bits(bits, order: str):
    state = [[0] * 64 for _ in range(20)]
    for index, bit in enumerate(bits):
        if order == "R":
            row, column = divmod(index, 64)
        else:
            column, row = divmod(index, 20)
        state[row][column] = bit
    return state


def to_bits(state, order: str):
    bits = []
    for index in range(1280):
        if order == "R":
            row, column = divmod(index, 64)
        else:
            column, row = divmod(index, 20)
        bits.append(state[row][column])
    return bits


def pad(message, rate: int):
    zeros = (-len(message) - 2) % rate
    return message + [1] + [0] * zeros + [1]


def absorb_block(state, message_block, capacity: int, order: str):
    """Algorithm 4, lines 6-9, including the EDM feed-forward."""
    x_bits = to_bits(state, order)
    for index, bit in enumerate(message_block):
        x_bits[index] ^= bit
    x = from_bits(x_bits, order)
    after_g = perm(x, 0, 9)
    capacity_bits = x_bits[:capacity]
    feed_bits = to_bits(after_g, order)
    for index, bit in enumerate(capacity_bits):
        feed_bits[index] ^= bit
    return perm(from_bits(feed_bits, order), 9, 18)


def digest(message, output_length: int, order: str):
    rate = 1280 - output_length - 64
    capacity = output_length + 64
    padded = pad(message, rate)
    state = [[0] * 64 for _ in range(20)]
    absorb_trace = []
    for offset in range(0, len(padded), rate):
        state = absorb_block(state, padded[offset:offset + rate], capacity, order)
        absorb_trace.append(hash_state(state, order))
    output = to_bits(state, order)[:rate]
    while len(output) < output_length:
        state = perm(state, 0, 18)
        output.extend(to_bits(state, order)[:rate])
    return output[:output_length], absorb_trace


def hash_state(state, order: str) -> str:
    return hashlib.sha256(bytes(pack_bits(to_bits(state, order)))).hexdigest()


def pack_bits(bits):
    packed = bytearray()
    for offset in range(0, len(bits), 8):
        value = 0
        for bit in bits[offset:offset + 8]:
            value = (value << 1) | bit
        packed.append(value)
    return bytes(packed)


def main():
    for output_length in (512, 768, 1024):
        for message in ([1], [0, 1], [1, 0, 1, 1]):
            row, row_trace = digest(message, output_length, "R")
            col, col_trace = digest(message, output_length, "C")
            differing = sum(a != b for a, b in zip(row, col))
            print(
                f"n={output_length} msg={''.join(map(str, message))} "
                f"equal={row == col} differing_bits={differing} "
                f"row_sha256={hashlib.sha256(pack_bits(row)).hexdigest()} "
                f"col_sha256={hashlib.sha256(pack_bits(col)).hexdigest()} "
                f"row_absorb={','.join(row_trace)} "
                f"col_absorb={','.join(col_trace)}"
            )


if __name__ == "__main__":
    main()
