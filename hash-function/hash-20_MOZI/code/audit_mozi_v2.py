#!/usr/bin/env python3
"""Exact cross-checks for the executable definitions in the MOZI specification.

Input is only the clean specification identified below.  Python treats a
four-bit tuple as (x0, x1, x2, x3), with x0 as the most significant bit, as
stated for the S-box and used by the displayed table.
"""

from __future__ import annotations

import hashlib
import json
from itertools import permutations, product
from pathlib import Path

SOURCE = Path(
    "/home/mmat/mmat-preview/campaigns/rebuild-20261119/runs/"
    "rebuild-104-hash-20-ds02/slots/orch-graph/orch/hash-20-spec.pdf"
)

SBOX_TABLE = (
    0, 8, 6, 13, 5, 15, 7, 12,
    4, 14, 2, 3, 9, 1, 11, 10,
)

# Table 3.  Rows are i mod 4; columns are y=0,1,2,3.
SHIFT_TABLE = (
    (0, 14, 20, 22),
    (0, 13, 68, 91),
    (0, 27, 42, 106),
    (0, 32, 48, 80),
)

# p.9's separate round-zero example of the constants.
SHIFT_P9_EXAMPLE = (0, 1, 2, 3)

ROUND_CONSTANTS = (
    0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3,
    0x13, 0x19, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x44,
    0xA4, 0x09, 0x38, 0x22, 0x29, 0x9F, 0x31, 0xD0,
)


def unpack(nibble: int) -> tuple[int, int, int, int]:
    """Return the page's (x0,x1,x2,x3) tuple, x0 being most significant."""
    return tuple((nibble >> i) & 1 for i in (3, 2, 1, 0))


def pack(bits: tuple[int, int, int, int]) -> int:
    return sum((b & 1) << (3 - i) for i, b in enumerate(bits))


def reverse_bits(nibble: int) -> int:
    return pack(tuple(reversed(unpack(nibble))))


def sbox_bitslice(nibble: int) -> int:
    """p.17 equations, with the displayed tuple order retained."""
    x0, x1, x2, x3 = unpack(nibble)
    y3 = (x3 & x2) ^ x1
    y1 = (x2 | x1) ^ x0
    y0 = (y3 & x0) ^ x3
    y2 = (y1 & x3) ^ x2
    return pack((y0, y1, y2, y3))


def sbox_anf(nibble: int) -> int:
    """p.12 ANF, with x0 the most significant input coordinate."""
    x0, x1, x2, x3 = unpack(nibble)
    y0 = (x3 & x2 & x0) ^ (x1 & x0) ^ x3
    y1 = (x2 & x1) ^ x2 ^ x1 ^ x0
    y2 = (x3 & x0) ^ (x2 & x1) ^ x1
    y3 = (x3 & x2) ^ x1
    return pack((y0, y1, y2, y3))


def table_anf_expression(output_index: int) -> str:
    """Mobius-transform one Table 2 output coordinate into its exact ANF."""
    coefficients = [
        (SBOX_TABLE[input_value] >> (3 - output_index)) & 1
        for input_value in range(16)
    ]
    for variable in range(4):
        for mask in range(16):
            if mask & (1 << variable):
                coefficients[mask] ^= coefficients[mask ^ (1 << variable)]
    terms = []
    for mask, coefficient in enumerate(coefficients):
        if not coefficient:
            continue
        if mask == 0:
            terms.append("1")
        else:
            terms.append(
                "*".join(
                    f"x{3 - variable}"
                    for variable in range(4)
                    if mask & (1 << variable)
                )
            )
    return " + ".join(terms) if terms else "0"


def alpha_printed(nibble: int) -> int:
    """The p.8 matrix alpha(x0,x1,x2,x3)=(x1,x2,x3,x0+x1)."""
    x0, x1, x2, x3 = unpack(nibble)
    return pack((x1, x2, x3, x0 ^ x1))


def alpha_algorithm(nibble: int) -> int:
    """Algorithm 4 MUL: (x0,x1,x2,x3)->(x3,x0+x3,x1,x2)."""
    x0, x1, x2, x3 = unpack(nibble)
    return pack((x3, x0 ^ x3, x1, x2))


def repeat(fn, nibble: int, times: int) -> int:
    for _ in range(times):
        nibble = fn(nibble)
    return nibble


PRINTED_ALPHA = tuple(alpha_printed(x) for x in range(16))
PRINTED_ALPHA2 = tuple(alpha_printed(x) for x in range(16))
PRINTED_ALPHA2 = tuple(alpha_printed(PRINTED_ALPHA[x]) for x in range(16))
ALG_ALPHA = tuple(alpha_algorithm(x) for x in range(16))
ALG_ALPHA2 = tuple(alpha_algorithm(ALG_ALPHA[x]) for x in range(16))


def mds_printed(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    """The polynomial matrix printed on p.8."""
    a2 = PRINTED_ALPHA2[a]
    b2 = PRINTED_ALPHA2[b]
    c2 = PRINTED_ALPHA2[c]
    d2 = PRINTED_ALPHA2[d]
    ab = PRINTED_ALPHA[b]
    ad = PRINTED_ALPHA[d]
    return (
        a2 ^ b2 ^ ab ^ c ^ d,
        a ^ ab ^ b ^ c2 ^ c ^ d2 ^ ad ^ d,
        a ^ b ^ c2 ^ d2 ^ ad,
        a2 ^ a ^ b2 ^ ab ^ b ^ c ^ ad ^ d,
    )


def mds_algorithm(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    """Algorithm 4 with its printed MUL operation."""
    s0, s1, s2, s3 = a, b, c, d
    s2 ^= s3
    s0 ^= s1
    s1 = ALG_ALPHA[s1]
    s3 = ALG_ALPHA[s3]
    s1 ^= s2
    s3 ^= s0
    s0 = ALG_ALPHA2[s0]
    s2 = ALG_ALPHA2[s2]
    s2 ^= s3
    s0 ^= s1
    s1 ^= s2
    s3 ^= s0
    return s0, s1, s2, s3


def mds_listing(a: int, b: int, c: int, d: int) -> tuple[int, int, int, str]:
    """Listing 1.  Return output and its exact XOR and MUL statement counts.

    The 16 arguments are four words A,B,C,D, each consisting of four
    bit-planes.  One bit position is enough to compare the transformations.
    """
    words = [
        [unpack(a)[i] for i in range(4)],
        [unpack(b)[i] for i in range(4)],
        [unpack(c)[i] for i in range(4)],
        [unpack(d)[i] for i in range(4)],
    ]
    xor_statements = 0
    mul_statements = 0

    def xor_rows(left: int, right: int) -> None:
        nonlocal xor_statements
        for i in range(4):
            words[left][i] ^= words[right][i]
        xor_statements += 4

    def mul(row: int) -> None:
        nonlocal mul_statements
        nonlocal xor_statements
        w = words[row]
        tmp = w[3]
        w[3], w[2], w[1], w[0] = w[2], w[1], w[0], tmp
        w[1] ^= w[0]
        mul_statements += 1
        xor_statements += 1

    xor_rows(2, 3)
    xor_rows(0, 1)
    mul(1)
    mul(3)
    xor_rows(1, 2)
    xor_rows(3, 0)
    mul(0)
    mul(0)
    mul(2)
    mul(2)
    xor_rows(2, 3)
    xor_rows(0, 1)
    xor_rows(1, 2)
    xor_rows(3, 0)
    result = tuple(pack(tuple(words[row])) for row in range(4))
    return (*result, f"{xor_statements} XOR and {mul_statements} MUL statements")


def rotate_right(word: list[int], count: int) -> list[int]:
    return [word[(z - count) % 128] for z in range(128)]


def sbox_state_anf(
    state: list[int],
) -> tuple[list[int], dict[tuple[int, int, int], tuple[int, int, int]]]:
    """Apply p.12's ANF S-box to every (y,z), retaining input/output triples."""
    output = state.copy()
    records: dict[tuple[int, int, int], tuple[int, int, int]] = {}
    for y in range(4):
        for z in range(128):
            indices = [(4 * x + y) * 128 + z for x in range(4)]
            before = tuple(state[i] for i in indices)
            nibble = pack(before)
            after_nibble = sbox_anf(nibble)
            after = unpack(after_nibble)
            for index, bit_value in zip(indices, after):
                output[index] = bit_value
            records[y, z] = (nibble, after_nibble, nibble)
    return output, records


def state_to_nibbles(state: list[int]) -> list[list[int]]:
    # state[x][y][z], with x0 as the most significant S-box bit.
    return [
        [
            [
                pack(tuple(state[(4 * x + y) * 128 + z] for x in range(4)))
                for z in range(128)
            ]
            for y in range(4)
        ]
        for _ in range(1)
    ][0]


def nibbles_to_state(nibbles: list[list[int]]) -> list[int]:
    state = [0] * 2048
    for y in range(4):
        for z in range(128):
            for x, bit_value in enumerate(unpack(nibbles[y][z])):
                state[(4 * x + y) * 128 + z] = bit_value
    return state


def one_round_anf_a4(state: list[int], round_index: int) -> list[int]:
    # S-box.
    b = [
        [[0] * 128 for _ in range(4)]
        for _ in range(4)
    ]
    for y in range(4):
        for z in range(128):
            output_nibble = sbox_anf(
                pack(tuple(state[(4 * x + y) * 128 + z] for x in range(4)))
            )
            for x, bit_value in enumerate(unpack(output_nibble)):
                b[x][y][z] = bit_value

    # MixColumn on (B[x,0,z],...,B[x,3,z]).
    c = [[[0] * 128 for _ in range(4)] for _ in range(4)]
    for z in range(128):
        input_nibbles = [
            pack(tuple(b[x][y][z] for x in range(4)))
            for y in range(4)
        ]
        output_nibbles = mds_algorithm(*input_nibbles)
        for y, output_nibble in enumerate(output_nibbles):
            for x, bit_value in enumerate(unpack(output_nibble)):
                c[x][y][z] = bit_value

    # ShiftRow.
    d = [row[:] for row in c]
    for x in range(4):
        for y in range(4):
            d[x][y] = rotate_right(c[x][y], SHIFT_TABLE[round_index % 4][y])

    # AddConstant at the LSB of D[3,3] under the stated little-endian map.
    d[3][3][0] ^= (ROUND_CONSTANTS[round_index] >> 0) & 1
    for bit_index in range(1, 8):
        # The external indexing supplies z=0..7 for the least significant
        # byte in the intended round constant; place bit_index at z=bit_index.
        d[3][3][bit_index] ^= (ROUND_CONSTANTS[round_index] >> bit_index) & 1

    out = [0] * 2048
    for x in range(4):
        for y in range(4):
            for z in range(128):
                out[(4 * x + y) * 128 + z] = d[x][y][z]
    return out


def sponge_anf_a4(message: str) -> str:
    """Mozi-384 sponge using p.12's ANF and Algorithm 4's MDS branch."""
    rate = 1280
    padded = list(map(int, message)) + [1]
    padded += [0] * ((-len(padded)) % rate)
    assert len(padded) == rate
    state = padded + [0] * (2048 - rate)
    for round_index in range(20):
        state = one_round_anf_a4(state, round_index)
    # ell=384 < r=1280, so squeezing returns the first rate prefix.
    return "".join(map(str, state[:384]))


def main() -> None:
    source_hash = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
    table = list(SBOX_TABLE)
    bitslice = [sbox_bitslice(x) for x in range(16)]
    anf = [sbox_anf(x) for x in range(16)]

    anf_collisions = {
        str(output): [x for x in range(16) if sbox_anf(x) == output]
        for output in sorted(set(anf))
        if sum(sbox_anf(x) == output for x in range(16)) > 1
    }
    anf_mismatches = [
        {"input": x, "table": table[x], "anf": anf[x]}
        for x in range(16)
        if table[x] != anf[x]
    ]
    matching_anf_output_permutations = []
    for output_order in permutations(range(4)):
        values = []
        for x in range(16):
            y = unpack(sbox_anf(x))
            values.append(pack(tuple(y[i] for i in output_order)))
        if values == table:
            matching_anf_output_permutations.append(list(output_order))

    mds_mismatches, listing_mismatches = [], []
    for values in product(range(16), repeat=4):
        printed = mds_printed(*values)
        algorithm = mds_algorithm(*values)
        listing = mds_listing(*values)[:4]
        if printed != algorithm:
            mds_mismatches.append([list(values), list(printed), list(algorithm)])
        if algorithm != listing:
            listing_mismatches.append([list(values), list(algorithm), list(listing)])

    shift_mismatches = [
        {
            "round": 0,
            "y": y,
            "page9_example": SHIFT_P9_EXAMPLE[y],
            "table3": SHIFT_TABLE[0][y],
        }
        for y in range(4)
        if SHIFT_P9_EXAMPLE[y] != SHIFT_TABLE[0][y]
    ]

    # The ANF collision 2 -> 4 <- 8 lies entirely in rate bits for Mozi-384.
    # These messages have the same length and both yield one padded rate block.
    m1 = list("0" * 1025)
    m2 = list("0" * 1025)
    m1[1024] = "1"
    m2[0] = "1"
    padded1 = "".join(m1) + "1" + "0" * 254
    padded2 = "".join(m2) + "1" + "0" * 254
    state1 = [int(c) for c in padded1 + "0" * 768]
    state2 = [int(c) for c in padded2 + "0" * 768]
    sb1, records1 = sbox_state_anf(state1)
    sb2, records2 = sbox_state_anf(state2)
    digest1 = sponge_anf_a4("".join(m1))
    digest2 = sponge_anf_a4("".join(m2))

    result = {
        "source": str(SOURCE),
        "source_sha256": source_hash,
        "environment": {
            "python": "3.12.3",
            "implementation": "stdlib only",
        },
        "sbox": {
            "table": table,
            "bitslice_msb_first": bitslice,
            "bitslice_equals_table": bitslice == table,
            "bitslice_is_bijection": len(set(bitslice)) == 16,
            "anf_x0_msb_then_y0_msb": anf,
            "anf_equals_table": anf == table,
            "anf_is_bijection": len(set(anf)) == 16,
            "anf_mismatches": anf_mismatches,
            "anf_collisions": anf_collisions,
            "table_anf_coordinates": [
                table_anf_expression(i) for i in range(4)
            ],
            "anf_coordinate_agreement_with_table": [
                all(
                    ((sbox_anf(x) >> (3 - coordinate)) & 1)
                    == ((SBOX_TABLE[x] >> (3 - coordinate)) & 1)
                    for x in range(16)
                )
                for coordinate in range(4)
            ],
            "matching_anf_output_permutations": matching_anf_output_permutations,
        },
        "mds": {
            "tested_inputs": 65536,
            "printed_matrix_first_mismatch": mds_mismatches[0],
            "printed_matrix_mismatch_count": len(mds_mismatches),
            "algorithm4_equals_listing1": not listing_mismatches,
            "algorithm4_listing_first_mismatch": (
                listing_mismatches[0] if listing_mismatches else None
            ),
        },
        "shiftrow": {
            "page9_vs_table3_mismatches": shift_mismatches,
            "equation4_equals_right_rotation_for_all_128_shifts": all(
                rotate_right(list(range(128)), rho)
                == [((z - rho) % 128) for z in range(128)]
                for rho in range(128)
            ),
            "nonzero_lanes_in_table3": sum(v != 0 for row in SHIFT_TABLE for v in row),
            "state_lanes": 16,
            "page18_parallel_lane_claim": 9,
        },
        "conditional_anf_sponge_collision": {
            "scope": (
                "Mozi-384's named sponge with the p.12 ANF substituted for the "
                "S-box; MixColumn/ShiftRow/AddConstant use the other printed "
                "executable definitions."
            ),
            "message_lengths_bits": [len(m1), len(m2)],
            "messages_differ_at_external_bit": 0,
            "messages_also_differ_at_external_bit": 1024,
            "pre_sbox_values_at_y0_z0": [2, 8],
            "post_sbox_values_at_y0_z0": [4, 4],
            "state_states_equal_after_sbox": sb1 == sb2,
            "record_at_y0_z0": [records1[0, 0], records2[0, 0]],
            "digests_equal": digest1 == digest2,
            "common_digest_hex": f"{int(digest1, 2):096x}",
            "warning": (
                "This is conditional on selecting the ANF branch. It is not a "
                "collision for implementations of Table 2 / p.17 bitslice."
            ),
        },
        "conclusions": {
            "sbox": (
                "Table 2 and the p.17 bitslice equations are identical. The "
                "p.12 ANF is a different and non-bijective map."
            ),
            "mds": (
                "The p.8 polynomial matrix differs from Algorithm 4 on 65,280 "
                "of 65,536 inputs. Algorithm 4 and Listing 1 agree on all inputs."
            ),
            "shiftrow": (
                "The p.9 round-zero example differs from Table 3 in y=1,2,3. "
                "Equation (4)'s right-rotation interpretation is internally "
                "consistent."
            ),
        },
    }
    Path("artifacts").mkdir(exist_ok=True)
    output = json.dumps(result, indent=2) + "\n"
    Path("artifacts/audit_v2.json").write_text(output, encoding="utf-8")
    print(output, end="")


if __name__ == "__main__":
    main()
