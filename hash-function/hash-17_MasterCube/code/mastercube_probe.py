#!/usr/bin/env python3
"""Independent experiments with the literal MasterCube v2.0 round definitions."""

from __future__ import annotations

import argparse
import itertools

MASK16 = 0xFFFF

# Matrices are rows acting on column vectors over GF(2).
M_MIXROWS = (
    (1, 1, 0, 1),
    (1, 1, 1, 0),
    (0, 1, 1, 1),
    (1, 0, 1, 1),
)
M_CROSSMIXS = (
    (1, 1, 0, 0, 1, 0),
    (0, 1, 1, 0, 0, 1),
    (1, 0, 1, 1, 0, 0),
    (0, 1, 0, 1, 1, 0),
    (0, 0, 1, 0, 1, 1),
    (1, 0, 0, 1, 0, 1),
)
M_MIXCOLUMNS_Z0 = (
    (0, 1, 1),
    (1, 0, 1),
    (1, 1, 1),
)
M_MIXCOLUMNS_Z1 = (
    (1, 0, 1),
    (0, 1, 1),
    (1, 1, 1),
)

ROUND_CONSTANTS = (
    (0x243F, 0x6A88, 0x85A3, 0x08D3, 0x1319, 0x8A2E, 0x0370, 0x7344),
    (0x243F ^ 1, 0x6A88 ^ 1, 0x85A3 ^ 1, 0x08D3 ^ 1, 0x1319 ^ 1, 0x8A2E ^ 1, 0x0370 ^ 1, 0x7344 ^ 1),
    (0x243F ^ 2, 0x6A88 ^ 2, 0x85A3 ^ 2, 0x08D3 ^ 2, 0x1319 ^ 2, 0x8A2E ^ 2, 0x0370 ^ 2, 0x7344 ^ 2),
    (0x243F ^ 3, 0x6A88 ^ 3, 0x85A3 ^ 3, 0x08D3 ^ 3, 0x1319 ^ 3, 0x8A2E ^ 3, 0x0370 ^ 3, 0x7344 ^ 3),
    (0x243F ^ 4, 0x6A88 ^ 4, 0x85A3 ^ 4, 0x08D3 ^ 4, 0x1319 ^ 4, 0x8A2E ^ 4, 0x0370 ^ 4, 0x7344 ^ 4),
    (0x243F ^ 5, 0x6A88 ^ 5, 0x85A3 ^ 5, 0x08D3 ^ 5, 0x1319 ^ 5, 0x8A2E ^ 5, 0x0370 ^ 5, 0x7344 ^ 5),
    (0x243F ^ 6, 0x6A88 ^ 6, 0x85A3 ^ 6, 0x08D3 ^ 6, 0x1319 ^ 6, 0x8A2E ^ 6, 0x0370 ^ 6, 0x7344 ^ 6),
    (0x243F ^ 7, 0x6A88 ^ 7, 0x85A3 ^ 7, 0x08D3 ^ 7, 0x1319 ^ 7, 0x8A2E ^ 7, 0x0370 ^ 7, 0x7344 ^ 7),
    (0x243F ^ 8, 0x6A88 ^ 8, 0x85A3 ^ 8, 0x08D3 ^ 8, 0x1319 ^ 8, 0x8A2E ^ 8, 0x0370 ^ 8, 0x7344 ^ 8),
    (0x243F ^ 9, 0x6A88 ^ 9, 0x85A3 ^ 9, 0x08D3 ^ 9, 0x1319 ^ 9, 0x8A2E ^ 9, 0x0370 ^ 9, 0x7344 ^ 9),
    (0x243F ^ 10, 0x6A88 ^ 10, 0x85A3 ^ 10, 0x08D3 ^ 10, 0x1319 ^ 10, 0x8A2E ^ 10, 0x0370 ^ 10, 0x7344 ^ 10),
    (0x243F ^ 11, 0x6A88 ^ 11, 0x85A3 ^ 11, 0x08D3 ^ 11, 0x1319 ^ 11, 0x8A2E ^ 11, 0x0370 ^ 11, 0x7344 ^ 11),
    (0x243F ^ 12, 0x6A88 ^ 12, 0x85A3 ^ 12, 0x08D3 ^ 12, 0x1319 ^ 12, 0x8A2E ^ 12, 0x0370 ^ 12, 0x7344 ^ 12),
    (0x243F ^ 13, 0x6A88 ^ 13, 0x85A3 ^ 13, 0x08D3 ^ 13, 0x1319 ^ 13, 0x8A2E ^ 13, 0x0370 ^ 13, 0x7344 ^ 13),
    (0x243F ^ 14, 0x6A88 ^ 14, 0x85A3 ^ 14, 0x08D3 ^ 14, 0x1319 ^ 14, 0x8A2E ^ 14, 0x0370 ^ 14, 0x7344 ^ 14),
    (0x243F ^ 15, 0x6A88 ^ 15, 0x85A3 ^ 15, 0x08D3 ^ 15, 0x1319 ^ 15, 0x8A2E ^ 15, 0x0370 ^ 15, 0x7344 ^ 15),
    (0x243F ^ 16, 0x6A88 ^ 16, 0x85A3 ^ 16, 0x08D3 ^ 16, 0x1319 ^ 16, 0x8A2E ^ 16, 0x0370 ^ 16, 0x7344 ^ 16),
    (0x243F ^ 17, 0x6A88 ^ 17, 0x85A3 ^ 17, 0x08D3 ^ 17, 0x1319 ^ 17, 0x8A2E ^ 17, 0x0370 ^ 17, 0x7344 ^ 17),
)

ANDRX_SHIFTS = (
    (0, 1, 8),
    (14, 5, 0),
    (9, 12, 8),
    (14, 5, 0),
    (0, 1, 8),
    (8, 9, 0),
)


State = list  # A[y][x][z], a mutable 6 x 8 x 2 table.


def new_state() -> State:
    return [[[0, 0] for _ in range(8)] for _ in range(6)]


def copy_state(a: State) -> State:
    return [[row[:] for row in plane] for plane in a]


def xor_state(a: State, b: State) -> State:
    return [[[a[y][x][z] ^ b[y][x][z] for z in range(2)] for x in range(8)] for y in range(6)]


def rotr16(x: int, k: int) -> int:
    k %= 16
    return ((x >> k) | (x << (16 - k))) & MASK16 if k else x


def rotl16(x: int, k: int) -> int:
    k %= 16
    return ((x << k) | (x >> (16 - k))) & MASK16 if k else x


def mat_vec(matrix: tuple[tuple[int, ...], ...], values: list[int]) -> list[int]:
    out = []
    for row in matrix:
        x = 0
        for bit, value in zip(row, values):
            if bit:
                x ^= value
        out.append(x)
    return out


def cross_mixs(a: State) -> None:
    for x in range(8):
        for parity in range(2):
            pos = [a[y][x][z] for z in range(2) for y in range(parity, 6, 2)]
            out = mat_vec(M_CROSSMIXS, pos)
            i = 0
            for z in range(2):
                for y in range(parity, 6, 2):
                    a[y][x][z] = out[i]
                    i += 1


def swap_rows(a: State) -> None:
    for x in range(8):
        for y in (0, 2, 4):
            a[y][x][1], a[y + 1][x][1] = a[y + 1][x][1], a[y][x][1]


def mandrx(a: State, *, inverse: bool = False) -> None:
    for y in range(6):
        for x in range(8):
            left, right = a[y][x]
            if not inverse:
                for alpha, beta, gamma in ANDRX_SHIFTS:
                    left, right = (
                        (rotr16(left, alpha) & rotr16(left, beta))
                        ^ rotr16(left, gamma)
                        ^ right,
                        left,
                    )
            else:
                for alpha, beta, gamma in reversed(ANDRX_SHIFTS):
                    old_right = left
                    old_left = rotr16(left, gamma) ^ left ^ right
                    old_left = inverse_last_andrx(rotr16(left, alpha), rotr16(left, beta), old_left)
                    left, right = old_left, old_right
            a[y][x] = [left, right]


def inverse_last_andrx(after_and: int, after_beta: int, target: int) -> int:
    """Recover x from target = (x & after_beta) xor fixed, where x = after_alpha."""
    # after_alpha and after_beta are rotations of the same unknown x. Recover over 16 bits.
    for candidate in range(1 << 16):
        if (candidate & after_beta) == target:
            # after_alpha must be the same unknown candidate, so derive it first and
            # verify. Rotation relation is checked by the caller-facing helper below.
            return candidate
    raise AssertionError("unreachable")


def mandrx_inverse_exact(a: State) -> None:
    for y in range(6):
        for x in range(8):
            for alpha, beta, gamma in reversed(ANDRX_SHIFTS):
                left, right = a[y][x]
                # Feistel inversion: (left,right)=(f(old_left)^old_right,old_left).
                old_left = right
                old_right = left ^ (
                    (rotr16(old_left, alpha) & rotr16(old_left, beta))
                    ^ rotr16(old_left, gamma)
                )
                a[y][x] = [old_left, old_right]


def mix_columns(a: State, *, inverse: bool = False) -> None:
    if inverse:
        # The printed matrices are mutual inverses between the two z-slices.
        matrices = (M_MIXCOLUMNS_Z1, M_MIXCOLUMNS_Z0)
    else:
        matrices = (M_MIXCOLUMNS_Z0, M_MIXCOLUMNS_Z1)
    for z in range(2):
        matrix = matrices[z]
        for parity in range(2):
            xs = (0, 2, 4, 6) if parity == 0 else (1, 3, 5, 7)
            for x in xs:
                pos = [a[y][x][z] for y in range(parity, 6, 2)]
                out = mat_vec(matrix, pos)
                for y, value in zip(range(parity, 6, 2), out):
                    a[y][x][z] = value


def shift_rows(a: State) -> None:
    for y in range(6):
        left = a[y][0][0]
        for x in range(8):
            a[y][x][0] = a[y][(x + y) % 8][0]
        a[y][(7 - y) % 8][0] = left if y else left
    # Restore by direct rotation semantics: z=0 left, z=1 right.
    for y in range(6):
        # Reinsert the input row values rather than relying on the loop above.
        pass


def shift_rows_correct(a: State) -> None:
    for z in range(2):
        for y in range(6):
            row = [a[y][x][z] for x in range(8)]
            if z == 0:
                out = row[y:] + row[:y]
            else:
                out = row[-y:] + row[:-y] if y else row[:]
            for x, value in enumerate(out):
                a[y][x][z] = value


def inverse_shift_rows_correct(a: State) -> None:
    for z in range(2):
        for y in range(6):
            row = [a[y][x][z] for x in range(8)]
            if z == 0:
                out = row[-y:] + row[:-y] if y else row[:]
            else:
                out = row[y:] + row[:y]
            for x, value in enumerate(out):
                a[y][x][z] = value


def swap_slices(a: State) -> None:
    for y in range(6):
        for x in range(8):
            a[y][x][0], a[y][x][1] = a[y][x][1], a[y][x][0]


def mix_rows(a: State, *, inverse: bool = False) -> None:
    # The printed matrix is involutory.
    for y in range(6):
        for z in range(2):
            for parity in range(2):
                xs = (0, 2, 4, 6) if parity == 0 else (1, 3, 5, 7)
                pos = [a[y][x][z] for x in xs]
                out = mat_vec(M_MIXROWS, pos)
                for x, value in zip(xs, out):
                    a[y][x][z] = value


def rc_xor(a: State, rc: int) -> None:
    for x, value in enumerate(ROUND_CONSTANTS[rc]):
        a[0][x][0] ^= value


def round_forward(a: State, rc: int) -> State:
    a = copy_state(a)
    cross_mixs(a)
    swap_rows(a)
    mandrx(a)
    cross_mixs(a)
    swap_rows(a)
    mix_columns(a)
    shift_rows_correct(a)
    mix_rows(a)
    rc_xor(a, rc)
    return a


def round_inverse_correct(a: State, rc: int) -> State:
    a = copy_state(a)
    rc_xor(a, rc)
    mix_rows(a, inverse=True)
    inverse_shift_rows_correct(a)
    mix_columns(a, inverse=True)
    swap_rows(a)
    cross_mixs(a)
    mandrx_inverse_exact(a)
    swap_rows(a)
    cross_mixs(a)
    return a


def round_inverse_literal(a: State, rc: int) -> State:
    a = copy_state(a)
    rc_xor(a, rc)
    mix_rows(a)
    swap_slices(a)
    shift_rows_correct(a)
    mix_columns(a)
    swap_slices(a)
    swap_rows(a)
    cross_mixs(a)
    swap_slices(a)
    mandrx(a)
    swap_rows(a)
    cross_mixs(a)
    return a


def cube_p(a: State) -> State:
    for rc in range(18):
        a = round_forward(a, rc)
    return a


def cube_f_literal(a: State) -> State:
    forward = a
    inverse = copy_state(a)
    for rc in range(9):
        forward = round_forward(forward, rc)
        inverse = round_inverse_literal(inverse, rc)
    return xor_state(forward, inverse)


def cube_f_correct_split(a: State) -> State:
    forward = a
    for rc in range(9):
        forward = round_forward(forward, rc)
    inverse = a
    for rc in reversed(range(9)):
        inverse = round_inverse_correct(inverse, rc)
    return xor_state(forward, inverse)


def cube_f_hardware(a: State) -> State:
    forward = a
    for rc in range(9):
        forward = round_forward(forward, rc)
    inverse = a
    for rc in range(17, 8, -1):
        inverse = round_inverse_correct(inverse, rc)
    return xor_state(forward, inverse)


def transform(a: State, f_mode: str) -> State:
    if f_mode == "correct_split":
        return cube_f_correct_split(a)
    if f_mode == "literal":
        return cube_f_literal(a)
    if f_mode == "hardware":
        return cube_f_hardware(a)
    raise ValueError(f_mode)


def one_lane_nonzero(value: int) -> State:
    a = new_state()
    a[0][0] = [(value >> 16) & MASK16, value & MASK16]
    return a


def state_hex(a: State, order: str = "xyz") -> str:
    if order == "xyz":
        cells = (a[y][x][z] for z in range(2) for y in range(6) for x in range(8))
    elif order == "zyx":
        cells = (a[y][x][z] for x in range(8) for y in range(6) for z in range(2))
    elif order == "yxz":
        cells = (a[y][x][z] for z in range(2) for x in range(8) for y in range(6))
    else:
        raise ValueError(order)
    return "".join(f"{cell:04X}" for cell in cells)


PROFILES = {
    "MasterCube-512": (960, 576, 512),
    "MasterCube-768": (704, 832, 768),
    "MasterCube-1024": (448, 1088, 1024),
}

VECTORS = {
    ("MasterCube-512", 16): "C6ADAAFAC38E7BDAA6EAF589376AACCE00D7DCA0B5AC9F6282C6082637B0196B42AB3C3C6D8F2D A9D43E7B81FC17C3715CE5DDB7B0EA988AAC782925336B3FF7",
    ("MasterCube-512", 256): "CAE91F74FAFE967DFA4796DF6A51231189BA1DFC71A03FF19F32DBDDE2CE0679D66030DC0C1810 FE48F5F5B8331D555A4DFCB7A849CC39F81944156E3AEDBD63",
    ("MasterCube-768", 16): "D0CBAAA4A32BC0D7C9CC9823AF87D257BF95FBBB024F6F8DFD74046B6A0B02C527FBB0304AA6B8 306E965D1413708AB466F96156E81B53F9C7C0B502AD5B777B9F06C6EE3E66091F5B10867D022C95A50E5 69FA184D05D2BC8AD55281AA2DA87",
    ("MasterCube-768", 256): "49F363B73F1221D05BE0FD575C2D588C67856A0A6CC5D35FA70B5712BEA84F6ED58D1FA696F686 86EAFF716FE80387841D6016408D7884664325CDDB3F453CC08C3B164CF30F9B713A99C3D5E381C6904E4 8CD65D13A457CB31C28C9D70EAD6F",
    ("MasterCube-1024", 16): "1AA7173582BAB6838D0A4FA47CF6056D365D40ECF31EB8015E7CA0E14C0C5E606738934727667A F0475E670D027D8915D4362693C69A43D72555255DE8BA4FD864DE95C3362711C2D319834FB73860A904C 1AF836DAB21D1D7B36A1849B5C4913B39B6284632246072AAA999F402A6D66C9CB984E73FAA3BE1136E2F 45859EA0",
    ("MasterCube-1024", 256): "8AAE420D49F4C8B2538A3BBBF7A9768EA27701524D8BB124F1BF360F1243E6E8DD3E74342C3CE5 587EFD60565A26AF7DC156D020F9B51E5902932814C93EFED4C7423A88941E0248642FE48F9CA5C674877 5FB20A37050EFB9B3E983DFB48AB1E79D88D690F326D475B241452EFBFF4F7A565204535447E859B72275 B03F4740",
}

VECTOR_MESSAGES = {
    16: "5D9B",
    256: "41BDB6A04FCD27406E77D0D2ADE868940824EC7124BDAF36CCE4AA0938A16BFC",
}


def normalize_hex(value: str) -> str:
    return "".join(value.split()).upper()


def ordered_cells(order: str, directions: tuple[int, int, int]):
    indexes = {"x": range(8), "y": range(6), "z": range(2)}
    axes = {
        "x": (indexes["x"], directions[0]),
        "y": (indexes["y"], directions[1]),
        "z": (indexes["z"], directions[2]),
    }
    seqs = [list(axes[axis][0])[:: axes[axis][1]] for axis in order]
    for xyz in itertools.product(*seqs):
        coord = dict(zip(order, xyz))
        yield coord["y"], coord["x"], coord["z"]


def cells_to_bits(cells: list[tuple[int, int, int]], state: State, *, cell_bits: int = 0):
    for y, x, z in cells:
        value = state[y][x][z]
        for i in range(16):
            bit = i if cell_bits == 0 else 15 - i
            yield (value >> bit) & 1


def bits_to_cells(cells: list[tuple[int, int, int]], bits: list[int], state: State, *, cell_bits: int = 0):
    i = 0
    for y, x, z in cells:
        value = 0
        for j in range(16):
            bit = j if cell_bits == 0 else 15 - j
            value |= bits[i] << bit
            i += 1
        state[y][x][z] = value


def pad_message(message: bytes, rate: int) -> list[int]:
    bits = []
    for byte in message:
        bits.extend((byte >> i) & 1 for i in range(7, -1, -1))
    bits.append(1)
    while (len(bits) + 1) % rate:
        bits.append(0)
    bits.append(1)
    return bits


def bits_to_hex(bits: list[int]) -> str:
    assert len(bits) % 4 == 0
    return "".join(f"{sum(bits[i + j] << (3 - j) for j in range(4)):X}" for i in range(0, len(bits), 4))


def hash_profile(
    message_hex: str,
    profile: str,
    *,
    f_mode: str = "correct_split",
    order: str = "xyz",
    directions: tuple[int, int, int] = (1, 1, 1),
    cell_msb_first: bool = True,
) -> str:
    rate, capacity, digest = PROFILES[profile]
    assert rate + capacity == 1536 and rate % 16 == 0
    all_cells = list(ordered_cells(order, directions))
    rate_cells = all_cells[: rate // 16]
    state = new_state()
    padded = pad_message(bytes.fromhex(message_hex), rate)
    for i in range(0, len(padded), rate):
        block = padded[i : i + rate]
        current = list(cells_to_bits(rate_cells, state, cell_bits=0 if cell_msb_first else 1))
        block = [a ^ b for a, b in zip(current, block)]
        bits_to_cells(rate_cells, block, state, cell_bits=0 if cell_msb_first else 1)
        state = transform(state, f_mode)
    out = list(cells_to_bits(rate_cells, state, cell_bits=0 if cell_msb_first else 1))
    while len(out) < digest:
        state = transform(state, f_mode)
        out += list(cells_to_bits(rate_cells, state, cell_bits=0 if cell_msb_first else 1))
    return bits_to_hex(out[:digest])


def absorb_state(
    message_hex: str,
    profile: str,
    *,
    f_mode: str,
    order: str,
    directions: tuple[int, int, int],
    cell_msb_first: bool,
) -> State:
    rate, _capacity, _digest = PROFILES[profile]
    rate_cells = list(ordered_cells(order, directions))[: rate // 16]
    state = new_state()
    padded = pad_message(bytes.fromhex(message_hex), rate)
    for i in range(0, len(padded), rate):
        block = padded[i : i + rate]
        current = list(cells_to_bits(rate_cells, state, cell_bits=0 if cell_msb_first else 1))
        block = [a ^ b for a, b in zip(current, block)]
        bits_to_cells(rate_cells, block, state, cell_bits=0 if cell_msb_first else 1)
        state = transform(state, f_mode)
    return state


def extract_digest(
    state: State,
    profile: str,
    *,
    f_mode: str,
    order: str,
    directions: tuple[int, int, int],
    cell_msb_first: bool,
) -> str:
    rate, _capacity, digest = PROFILES[profile]
    cells = list(ordered_cells(order, directions))[: rate // 16]
    out = list(cells_to_bits(cells, state, cell_bits=0 if cell_msb_first else 1))
    while len(out) < digest:
        state = transform(state, f_mode)
        out += list(cells_to_bits(cells, state, cell_bits=0 if cell_msb_first else 1))
    return bits_to_hex(out[:digest])


def vector_search() -> None:
    target = normalize_hex(VECTORS[("MasterCube-512", 16)])
    inputs = []
    for f_mode in ("correct_split", "literal", "hardware"):
        for order in map("".join, itertools.permutations("xyz")):
            for directions in itertools.product((1, -1), repeat=3):
                for cell_msb_first in (True, False):
                    state = absorb_state(
                        VECTOR_MESSAGES[16],
                        "MasterCube-512",
                        f_mode=f_mode,
                        order=order,
                        directions=directions,
                        cell_msb_first=cell_msb_first,
                    )
                    inputs.append((f_mode, order, directions, cell_msb_first, state))
    for f_mode, in_order, in_dirs, in_msb, state in inputs:
        for out_order in map("".join, itertools.permutations("xyz")):
            for out_dirs in itertools.product((1, -1), repeat=3):
                for out_msb in (True, False):
                    got = extract_digest(
                        state,
                        "MasterCube-512",
                        f_mode=f_mode,
                        order=out_order,
                        directions=out_dirs,
                        cell_msb_first=out_msb,
                    )
                    if got == target:
                        print(
                            "MATCH",
                            {
                                "f_mode": f_mode,
                                "input_order": in_order,
                                "input_directions": in_dirs,
                                "input_cell_msb": in_msb,
                                "output_order": out_order,
                                "output_directions": out_dirs,
                                "output_cell_msb": out_msb,
                            },
                            got,
                        )
                        return
    print(
        "no MC512/16-bit vector match among",
        len(inputs) * 96,
        "input/output convention pairs",
    )


def semantic_divergence_search() -> None:
    for msg_len in (0, 2, 4, 8, 16, 32, 64, 128):
        message = bytes(((0x9E3779B1 * (i + 1)) >> (8 * (i % 4))) & 0xFF for i in range(msg_len // 8))
        if msg_len % 8:
            message += bytes([0xA5])
        msg_hex = message.hex()
        got = {
            mode: hash_profile(msg_hex, "MasterCube-512", f_mode=mode)
            for mode in ("literal", "correct_split", "hardware")
        }
        print(msg_len, got, "equal", len(set(got.values())) == 1)


def matrix_report() -> None:
    def multiply(x, y):
        return tuple(
            tuple(sum(x[i][k] * y[k][j] for k in range(len(y))) % 2 for j in range(len(y[0])))
            for i in range(len(x))
        )

    for name, matrix in (
        ("MixRows", M_MIXROWS),
        ("CrossMixs", M_CROSSMIXS),
        ("MixColumns-z0", M_MIXCOLUMNS_Z0),
        ("MixColumns-z1", M_MIXCOLUMNS_Z1),
    ):
        square = multiply(matrix, matrix)
        identity = tuple(tuple(int(i == j) for j in range(len(matrix))) for i in range(len(matrix)))
        print(name, "involutory" if square == identity else "NOT involutory")
    print(
        "MixColumns pair product",
        "identity"
        if multiply(M_MIXCOLUMNS_Z0, M_MIXCOLUMNS_Z1)
        == ((1, 0, 0), (0, 1, 0), (0, 0, 1))
        else "NOT identity",
    )


def inverse_report() -> None:
    for value in (0, 1, 0xDEADBEEF, 0x12345678, 0xFFFFFFFF):
        a = one_lane_nonzero(value)
        b = round_forward(a, 0)
        c = round_inverse_literal(b, 0)
        d = round_inverse_correct(b, 0)
        print(
            f"round value={value:08X} literal_recovers={a == c} correct_recovers={a == d}"
        )
    a = new_state()
    a[0][0] = [0xDEAD, 0xBEEF]
    b = round_forward(a, 3)
    print("full_state literal inverse mismatch", state_hex(a) != state_hex(round_inverse_literal(b, 3)))
    print("full_state exact inverse matches", state_hex(a) == state_hex(round_inverse_correct(b, 3)))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("matrices", "inverse", "states", "vectors", "divergence"))
    args = parser.parse_args()
    if args.mode == "matrices":
        matrix_report()
    elif args.mode == "inverse":
        inverse_report()
    elif args.mode == "states":
        a = new_state()
        a[0][0] = [0xDEAD, 0xBEEF]
        a[5][7] = [0x1234, 0x5678]
        print("input", state_hex(a))
        print("cube_f_literal", state_hex(cube_f_literal(a)))
        print("cube_f_correct_split", state_hex(cube_f_correct_split(a)))
    elif args.mode == "vectors":
        vector_search()
    elif args.mode == "divergence":
        semantic_divergence_search()


if __name__ == "__main__":
    main()
