#!/usr/bin/env python3
"""Exact branch separator for the MasterCube 2.0 specification.

The representation is state[y][x][z], with y=0 the bottom row as stated in
the specification.  All state pictures in the PDF are top-to-bottom, but the
text fixes y=0 at the bottom.  Cell and lane rotations are logical left/right
rotations, with the leftmost displayed bit first.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy


WIDTH = 16
MASK16 = (1 << WIDTH) - 1
RC_BASE = [
    0x243F,
    0x6A88,
    0x85A3,
    0x08D3,
    0x1319,
    0x8A2E,
    0x0370,
    0x7344,
]
MAND_RX_ROTATIONS = [
    (0, 1, 8),
    (14, 5, 0),
    (9, 12, 8),
    (14, 5, 0),
    (0, 1, 8),
    (8, 9, 0),
]

M_MIX_ROWS = [
    [1, 1, 0, 1],
    [1, 1, 1, 0],
    [0, 1, 1, 1],
    [1, 0, 1, 1],
]
M_CROSS_MIX = [
    [1, 1, 0, 0, 1, 0],
    [0, 1, 1, 0, 0, 1],
    [1, 0, 1, 1, 0, 0],
    [0, 1, 0, 1, 1, 0],
    [0, 0, 1, 0, 1, 1],
    [1, 0, 0, 1, 0, 1],
]
M_MIX_COLUMNS_1 = [
    [0, 1, 1],
    [1, 0, 1],
    [1, 1, 1],
]
M_MIX_COLUMNS_2 = [
    [1, 0, 1],
    [0, 1, 1],
    [1, 1, 1],
]


def new_state(fill: int = 0):
    return [[[fill, fill] for _x in range(8)] for _y in range(6)]


def clone(state):
    return deepcopy(state)


def rol16(value: int, amount: int) -> int:
    amount %= WIDTH
    return ((value << amount) | (value >> (WIDTH - amount))) & MASK16


def ror16(value: int, amount: int) -> int:
    return rol16(value, -amount)


def apply_matrix(vector, matrix):
    return [
        xor_words(vector[j] for j, coefficient in enumerate(row) if coefficient)
        for row in matrix
    ]


def xor_words(words) -> int:
    result = 0
    for word in words:
        result ^= word
    return result


def mandrx(state):
    for y in range(6):
        for x in range(8):
            left, right = state[y][x]
            for alpha, beta, gamma in MAND_RX_ROTATIONS:
                left, right = (
                    ror16(left, alpha) & ror16(left, beta)
                    ^ ror16(left, gamma)
                    ^ right,
                    left,
                )
            state[y][x] = [left, right]


def mandrx_inverse(state):
    for y in range(6):
        for x in range(8):
            old_left, old_right = state[y][x]
            # Undo the six rounds.  The state after round j is (L_j, R_j).
            left, right = old_left, old_right
            for alpha, beta, gamma in reversed(MAND_RX_ROTATIONS):
                # (L_j, R_j) = (F(L_{j-1}) xor R_{j-1}, L_{j-1}).
                previous_left = right
                previous_right = ror16(right, alpha) & ror16(
                    right, beta
                ) ^ ror16(right, gamma) ^ left
                left, right = previous_left, previous_right
            state[y][x] = [left, right]


def shift_rows(state):
    for z in range(2):
        for y in range(6):
            row = [state[y][x][z] for x in range(8)]
            # Figure 4 has sources at x=5-y for A^0 and x=2+y for A^1,
            # with arrows ending at x=0 and x=7 respectively.  Thus row y
            # moves by 5-y cells: A^0 left and A^1 right.
            shift = 5 - y
            amount = shift if z == 0 else -shift
            row = [row[(x + amount) % 8] for x in range(8)]
            for x, value in enumerate(row):
                state[y][x][z] = value


def shift_rows_inverse(state):
    for z in range(2):
        for y in range(6):
            row = [state[y][x][z] for x in range(8)]
            shift = 5 - y
            amount = -shift if z == 0 else shift
            row = [row[(x + amount) % 8] for x in range(8)]
            for x, value in enumerate(row):
                state[y][x][z] = value


def mix_rows(state):
    for z in range(2):
        for y in range(6):
            for parity in range(2):
                indices = list(range(parity, 8, 2))
                values = [state[y][x][z] for x in indices]
                mixed = apply_matrix(values, M_MIX_ROWS)
                for x, value in zip(indices, mixed):
                    state[y][x][z] = value


def swap_slices(state):
    for y in range(6):
        for x in range(8):
            state[y][x][0], state[y][x][1] = state[y][x][1], state[y][x][0]


def swap_rows(state):
    for x in range(8):
        for y in (0, 2, 4):
            state[y][x][1], state[y + 1][x][1] = (
                state[y + 1][x][1],
                state[y][x][1],
            )


def cross_mix(state):
    for x in range(8):
        for parity in range(2):
            coordinates = [
                (y, z)
                for z in range(2)
                for y in range(parity, 6, 2)
            ]
            values = [state[y][x][z] for y, z in coordinates]
            mixed = apply_matrix(values, M_CROSS_MIX)
            for (y, z), value in zip(coordinates, mixed):
                state[y][x][z] = value


def mix_columns(state, inverse: bool = False):
    for x in range(8):
        for z in range(2):
            matrix = M_MIX_COLUMNS_2 if (z == 1) ^ inverse else M_MIX_COLUMNS_1
            for parity in range(2):
                ys = list(range(parity, 6, 2))
                values = [state[y][x][z] for y in ys]
                mixed = apply_matrix(values, matrix)
                for y, value in zip(ys, mixed):
                    state[y][x][z] = value


def add_round_constant(state, round_index: int):
    for x, base in enumerate(RC_BASE):
        state[0][x][0] ^= base ^ round_index


def round_forward(state, round_index: int):
    cross_mix(state)
    swap_rows(state)
    mandrx(state)
    cross_mix(state)
    swap_rows(state)
    mix_columns(state)
    shift_rows(state)
    mix_rows(state)
    add_round_constant(state, round_index)


def round_inverse_exact(state, round_index: int):
    add_round_constant(state, round_index)
    mix_rows(state)
    shift_rows_inverse(state)
    mix_columns(state, inverse=True)
    swap_rows(state)
    cross_mix(state)
    mandrx_inverse(state)
    swap_rows(state)
    cross_mix(state)


def round_inverse_literal(state, round_index: int):
    """Algorithm 2 exactly as printed, with operations in the printed order."""
    add_round_constant(state, round_index)
    mix_rows(state)
    swap_slices(state)
    shift_rows(state)
    mix_columns(state)
    swap_slices(state)
    swap_rows(state)
    cross_mix(state)
    swap_slices(state)
    mandrx(state)
    swap_rows(state)
    cross_mix(state)


def forward_nine(state):
    for i in range(9):
        round_forward(state, i)


def inverse_literal_nine(state):
    for i in range(9):
        round_inverse_literal(state, i)


def inverse_exact_nine(state):
    for i in reversed(range(9)):
        round_inverse_exact(state, i)


def cube_f_literal(state):
    forward = clone(state)
    inverse = clone(state)
    forward_nine(forward)
    inverse_literal_nine(inverse)
    return combine(forward, inverse)


def cube_f_exact(state):
    forward = clone(state)
    inverse = clone(state)
    forward_nine(forward)
    inverse_exact_nine(inverse)
    return combine(forward, inverse)


def combine(left, right):
    out = new_state()
    for y in range(6):
        for x in range(8):
            for z in range(2):
                out[y][x][z] = left[y][x][z] ^ right[y][x][z]
    return out


def rate_cells(rate: int, fill=0):
    """Choose an ordered prefix of cells as the rate.

    The specification gives the rate sizes but no state-to-message
    serialization.  This frozen coordinate order only defines the displayed
    internal witness.  Any bijective serialization reaches the same state for
    a suitable first block.
    """
    out = new_state(fill)
    ordered = [(y, x, z) for y in range(6) for x in range(8) for z in range(2)]
    assert rate % 16 == 0
    used = [(y, x, z) for y, x, z in ordered[: rate // 16]]
    return out, used


def empty_message_padded_state(rate: int):
    """State A on input to Cube-f for the empty message.

    pad10*1 on an empty message is 1, then the minimum zeros, then 1.
    """
    state, used = rate_cells(rate)
    state[used[0][0]][used[0][1]][used[0][2]] |= 1 << 15
    state[used[-1][0]][used[-1][1]][used[-1][2]] |= 1
    return state, used


def serialize_cells(state):
    raw = bytearray()
    for y in range(6):
        for x in range(8):
            for z in range(2):
                raw.extend(state[y][x][z].to_bytes(2, "big"))
    return bytes(raw)


def digest_cells(state, digest_bits: int):
    raw = serialize_cells(state)
    return raw[: digest_bits // 8]


def state_sha256(state):
    return hashlib.sha256(serialize_cells(state)).hexdigest()


def xor_difference(left, right):
    diff = new_state()
    for y in range(6):
        for x in range(8):
            for z in range(2):
                diff[y][x][z] = left[y][x][z] ^ right[y][x][z]
    return diff


def nonzero_words(state):
    return sum(
        state[y][x][z] != 0
        for y in range(6)
        for x in range(8)
        for z in range(2)
    )


def nonzero_coordinates(state):
    return [
        [y, x, z, state[y][x][z]]
        for y in range(6)
        for x in range(8)
        for z in range(2)
        if state[y][x][z]
    ]


def make_witness(rate, digest_bits):
    input_state, rate_positions = empty_message_padded_state(rate)
    literal = cube_f_literal(input_state)
    exact = cube_f_exact(input_state)
    diff = xor_difference(literal, exact)

    # Continue the literal actual sponge construction to the digest.  Since
    # Cube-f is not a bit permutation and the output mapping is unspecified,
    # this continuation is explicitly fixed by serialize_cells().
    literal_digest = digest_cells(literal, digest_bits)
    exact_digest = digest_cells(exact, digest_bits)

    return {
        "rate": rate,
        "digest_bits": digest_bits,
        "input_state_nonzero": nonzero_coordinates(input_state),
        "rate_positions_used": rate_positions,
        "literal_state_sha256": state_sha256(literal),
        "exact_state_sha256": state_sha256(exact),
        "state_difference_nonzero_words": nonzero_words(diff),
        "state_difference_nonzero_coordinates": nonzero_coordinates(diff),
        "literal_digest_hex": literal_digest.hex(),
        "exact_digest_hex": exact_digest.hex(),
    }


def make_zero_witness(digest_bits):
    input_state = new_state()
    literal = cube_f_literal(input_state)
    exact = cube_f_exact(input_state)
    diff = xor_difference(literal, exact)
    return {
        "digest_bits": digest_bits,
        "literal_state_sha256": state_sha256(literal),
        "exact_state_sha256": state_sha256(exact),
        "state_difference_nonzero_words": nonzero_words(diff),
        "state_difference_nonzero_coordinates": nonzero_coordinates(diff),
        "literal_digest_hex": digest_cells(literal, digest_bits).hex(),
        "exact_digest_hex": digest_cells(exact, digest_bits).hex(),
    }


def self_test():
    state = new_state()
    mandrx(state)
    mandrx_inverse(state)
    assert nonzero_words(state) == 0

    # Verify the linear inverses pairwise on a deterministic nonzero state.
    state = new_state()
    for y in range(6):
        for x in range(8):
            for z in range(2):
                state[y][x][z] = (
                    (0x9E37 * (x + 1) + 0x79B9 * (y + 1) + 0x811C * (z + 1))
                    & MASK16
                )
    for forward, inverse in [
        (shift_rows, shift_rows_inverse),
        (mix_rows, mix_rows),
        (swap_slices, swap_slices),
        (swap_rows, swap_rows),
        (cross_mix, cross_mix),
    ]:
        work = clone(state)
        forward(work)
        inverse(work)
        assert work == state

    work = clone(state)
    mix_columns(work)
    mix_columns(work, inverse=True)
    assert work == state

    # Verify the exact round inverse for every round constant.
    for i in range(9):
        work = clone(state)
        round_forward(work, i)
        round_inverse_exact(work, i)
        assert work == state


def main():
    self_test()
    profiles = [(960, 512), (704, 768), (448, 1024)]
    print(
        json.dumps(
            {
                "empty_pad_witnesses": [
                    make_witness(*profile) for profile in profiles
                ],
                "zero_block_witnesses": [
                    make_zero_witness(digest_bits)
                    for _rate, digest_bits in profiles
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
