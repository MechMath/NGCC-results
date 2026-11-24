#!/usr/bin/env python3
"""Test whether row-major and column-major matrix serializations differ.

Both implementations use the same 18 consecutive 64-bit windows of the binary
expansion of pi, so the test isolates the specification's missing
vector-to-matrix map.
"""

import hashlib

S = [
    4, 14, 10, 5, 9, 24, 20, 0, 18, 28, 30, 21, 2, 23, 29, 13,
    22, 27, 15, 7, 26, 12, 16, 3, 8, 1, 19, 31, 25, 11, 17, 6,
]
M = [
    [3, 2, 1, 3],
    [3, 1, 4, 4],
    [1, 3, 6, 4],
    [2, 2, 3, 1],
]

# floor(2^1152 * frac(pi)), split into eighteen consecutive 64-bit windows.
PI_RC = [
    0x243F6A8885A308D3, 0x13198A2E03707344,
    0xA4093822299F31D0, 0x082EFA98EC4E6C89,
    0x452821E638D01377, 0xBE5466CF34E90C6C,
    0xC0AC29B7C97C50DD, 0x3F84D5B5B5470917,
    0x9216D5D98979FB1B, 0xD1310BA698DFB5AC,
    0x2FFD72DBD01ADFB7, 0xB8E1AFED6A267E96,
    0xBA7C9045F12C7F99, 0x24A19947B3916CF7,
    0x0801F2E2858EFC16, 0x636920D871574E69,
    0xA458FEA3F4933D7E, 0x0D95748F728EB658,
]


def mul(a, b):
    """Multiply in F2[x]/(x^5+x^2+1)."""
    result = 0
    for bit in range(5):
        if (b >> bit) & 1:
            result ^= a << bit
    for bit in range(8, 4, -1):
        if (result >> bit) & 1:
            result ^= 0b100101 << (bit - 5)
    return result & 31


def xor_all(values):
    result = 0
    for value in values:
        result ^= value
    return result


def shift_rows(source, kind, inverse=False):
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
            result[row][base + (column % width + amount) % width] = source[row][column]
    return result


def rnd(state, round_number, rc=0):
    def mds(values):
        # Page 10 prints [b3,b2,b1,b0]^T = M [a3,a2,a1,a0]^T.
        # Convert the value list in a0..a3 order to that printed order and back.
        printed_inputs = list(reversed(values))
        printed_outputs = [
            xor_all(
                mul(M[row][col], printed_inputs[col])
                for col in range(4)
            )
            for row in range(4)
        ]
        return list(reversed(printed_outputs))

    after_sbox = [[0] * 64 for _ in range(20)]
    for column in range(64):
        values = []
        for block in range(4):
            packed = 0
            for lane in range(5):
                packed |= state[5 * block + lane][column] << lane
            values.append(S[packed])
        mixed = mds(values)
        mixed = [S[value] for value in mixed]
        for block in range(4):
            for lane in range(5):
                after_sbox[5 * block + lane][column] = (mixed[block] >> lane) & 1

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
                after_mds[5 * block + lane][column] = (mixed[block] >> lane) & 1

    result = shift_rows(after_mds, kind, inverse=True)
    for column in range(64):
        result[0][column] ^= (rc >> column) & 1
    return result


def rounds(state, start, stop):
    for round_number in range(start, stop):
        state = rnd(state, round_number, PI_RC[round_number])
    return state


def perm(state):
    return rounds(state, 0, 18)


def from_bits(bits, order):
    state = [[0] * 64 for _ in range(20)]
    for index, bit in enumerate(bits):
        if order == "row":
            row, column = divmod(index, 64)
        else:
            column, row = divmod(index, 20)
        state[row][column] = bit
    return state


def to_bits(state, order):
    bits = []
    for index in range(1280):
        if order == "row":
            row, column = divmod(index, 64)
        else:
            column, row = divmod(index, 20)
        bits.append(state[row][column])
    return bits


def pad(message, rate):
    zeros = (-len(message) - 2) % rate
    return message + [1] + [0] * zeros + [1]


def digest(message, output_length, order):
    rate = 1280 - output_length - 64
    padded = pad(message, rate)
    state = [[0] * 64 for _ in range(20)]
    for offset in range(0, len(padded), rate):
        vector = to_bits(state, order)
        for index, bit in enumerate(padded[offset:offset + rate]):
            vector[index] ^= bit
        # Algorithm 4: state' = injected state; state = g(state); then
        # state = h(state XOR capacity_projection(state')).
        injected = vector
        state = rounds(from_bits(vector, order), 0, 9)
        permuted = to_bits(state, order)
        # The printed floor-to-c-bits operator selects the first c vector
        # coordinates; this is distinct from the zero-padding above unless a
        # separate rate/capacity convention is supplied.
        for index in range(0, 1280 - rate):
            permuted[index] ^= injected[index]
        state = rounds(from_bits(permuted, order), 9, 18)
    output = to_bits(state, order)[:rate]
    while len(output) < output_length:
        state = perm(state)
        output.extend(to_bits(state, order)[:rate])
    return output[:output_length]


def pack_bits(bits):
    """Pack the tested output-bit sequence big-endian for compact printing."""
    packed = bytearray()
    for offset in range(0, len(bits), 8):
        value = 0
        for bit in bits[offset:offset + 8]:
            value = (value << 1) | bit
        packed.append(value)
    return bytes(packed)


for output_length in (512, 768, 1024):
    for message in ([1], [0, 1], [1, 0, 1, 1]):
        row = digest(message, output_length, "row")
        column = digest(message, output_length, "col")
        differing = sum(left != right for left, right in zip(row, column))
        row_hash = hashlib.sha256(pack_bits(row)).hexdigest()
        column_hash = hashlib.sha256(pack_bits(column)).hexdigest()
        print(
            f"n={output_length} msg={''.join(map(str, message))} "
            f"equal={row == column} differing_bits={differing} "
            f"row_bits={''.join(map(str, row[:32]))} "
            f"col_bits={''.join(map(str, column[:32]))} "
            f"row_sha256={row_hash} col_sha256={column_hash}"
        )
