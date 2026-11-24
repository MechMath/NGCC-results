#!/usr/bin/env python3
"""Independent executable semantics for the MasterCube v2.0 specification.

The implementation is deliberately scalar and explicit.  State holds cells
A[x][y][z], with x in 0..7 (left to right), y in 0..5 (bottom to top), and
z in 0..1 (left and right 16-bit lane halves).

Three Cube-f branch interpretations from the specification are implemented:

  algo4      Algorithm 4 verbatim: forward r(0)..r(8), then literal
             Algorithm 2 ir(0)..ir(8), then XOR.
  hw17       Section 5.2: forward r(0)..r(8), inverse branch ir(17)..ir(9).
  exactzip   ZIP as a mathematical split: forward r(0)..r(8), and the exact
             inverse ir(8)..ir(0), where ir uses inverses of the printed
             matrices and an inverse MAndRX.

The message/state serialization is not printed explicitly.  The test command
enumerates a finite space of plausible axis orders, axis directions, and cell
bit orders and reports every match to all vectors, not merely the first one.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator

MASK16 = (1 << 16) - 1
MASK32 = (1 << 32) - 1

SHIFTS = (
    (0, 1, 8),
    (14, 5, 0),
    (9, 12, 8),
    (14, 5, 0),
    (0, 1, 8),
    (8, 9, 0),
)
RC_BASE = (0x243F, 0x6A88, 0x85A3, 0x08D3, 0x1319, 0x8A2E, 0x0370, 0x7344)

M_MIX_ROWS = (
    (1, 1, 0, 1),
    (1, 1, 1, 0),
    (0, 1, 1, 1),
    (1, 0, 1, 1),
)
M_CROSS = (
    (1, 1, 0, 0, 1, 0),
    (0, 1, 1, 0, 0, 1),
    (1, 0, 1, 1, 0, 0),
    (0, 1, 0, 1, 1, 0),
    (0, 0, 1, 0, 1, 1),
    (1, 0, 0, 1, 0, 1),
)
M_MIX_COL_1 = (
    (0, 1, 1),
    (1, 0, 1),
    (1, 1, 1),
)
M_MIX_COL_2 = (
    (1, 0, 1),
    (0, 1, 1),
    (1, 1, 1),
)


def mat_vec_mul(matrix: tuple[tuple[int, ...], ...], vector: Iterable[int]) -> tuple[int, ...]:
    # The entries are 16-bit cells and the arithmetic is bitwise XOR.
    result = []
    for row in matrix:
        value = 0
        for coefficient, cell in zip(row, vector):
            if coefficient:
                value ^= cell
        result.append(value & MASK16)
    return tuple(result)


def gf2_inv(matrix: tuple[tuple[int, ...], ...]) -> tuple[tuple[int, ...], ...]:
    n = len(matrix)
    aug = [list(row) + [int(i == j) for j in range(n)] for i, row in enumerate(matrix)]
    for col in range(n):
        pivot = next((r for r in range(col, n) if aug[r][col]), None)
        if pivot is None:
            raise ValueError("singular matrix")
        aug[col], aug[pivot] = aug[pivot], aug[col]
        for r in range(n):
            if r != col and aug[r][col]:
                aug[r] = [a ^ b for a, b in zip(aug[r], aug[col])]
    return tuple(tuple(row[n:]) for row in aug)


M_MIX_COL_1_INV = gf2_inv(M_MIX_COL_1)
M_MIX_COL_2_INV = gf2_inv(M_MIX_COL_2)


def empty_state() -> list[list[list[int]]]:
    return [[[0, 0] for _ in range(6)] for _ in range(8)]


def clone_state(A: list[list[list[int]]]) -> list[list[list[int]]]:
    return [[cell[:] for cell in column] for column in A]


def rotr16(x: int, n: int) -> int:
    n &= 15
    return ((x >> n) | (x << (16 - n))) & MASK16


def round_constants(i: int) -> tuple[int, ...]:
    return tuple(c ^ i for c in RC_BASE)


def xor_round_constant(A: list[list[list[int]]], rc: tuple[int, ...]) -> None:
    # "first row of A^0": y=0, z=0, with the eight 16-bit words at x=0..7.
    for x in range(8):
        A[x][0][0] ^= rc[x]


def cross_mixs(A: list[list[list[int]]]) -> None:
    # The sheet notation v_0,...,v_11 in Figure 5 is:
    #   v_y       = A[x,y,0]       (0 <= y < 6)
    #   v_(6+y)   = A[x,y,1].
    # Thus the matrix inputs are the interleaved vectors
    #   [v0,v2,v4,v6,v8,v10] = [z0:y0,y2,y4; z1:y0,y2,y4]
    # and similarly with odd indices.  It is not two independent operations
    # on the two z slices.
    for x in range(8):
        for parity in range(2):
            coords = (
                (0, 0), (0, 2), (0, 4),
                (1, 0), (1, 2), (1, 4),
            ) if parity == 0 else (
                (0, 1), (0, 3), (0, 5),
                (1, 1), (1, 3), (1, 5),
            )
            v = tuple(A[x][y][z] for z, y in coords)
            for (z, y), value in zip(coords, mat_vec_mul(M_CROSS, v)):
                A[x][y][z] = value


def swap_rows(A: list[list[list[int]]]) -> None:
    # Figure 5(a): v_(6+y)=A[x,y,1] and the printed row swaps are
    # (v6,v7), (v8,v9), (v10,v11), i.e. adjacent y rows in z=1.
    for x in range(8):
        for y in (0, 2, 4):
            A[x][y][1], A[x][y + 1][1] = A[x][y + 1][1], A[x][y][1]


def mix_columns(
    A: list[list[list[int]]],
    m1: tuple[tuple[int, ...], ...] = M_MIX_COL_1,
    m2: tuple[tuple[int, ...], ...] = M_MIX_COL_2,
) -> None:
    # M1 acts on [v0,v2,v4] and [v1,v3,v5], and M2 acts on
    # [v6,v8,v10] and [v7,v9,v11].  In A[x,y,z] coordinates these
    # are the even-y and odd-y triples in each z slice.
    for x in range(8):
        for z in range(2):
            v0 = tuple(A[x][y][z] for y in (0, 2, 4))
            v1 = tuple(A[x][y][z] for y in (1, 3, 5))
            for y, value in zip((0, 2, 4), mat_vec_mul(m1, v0)):
                A[x][y][z] = value
            for y, value in zip((1, 3, 5), mat_vec_mul(m2, v1)):
                A[x][y][z] = value


def shift_rows(A: list[list[list[int]]], inverse_slices: bool = False) -> None:
    out = [[[0, 0] for _ in range(6)] for _ in range(8)]
    for z in range(2):
        for x in range(8):
            for y in range(6):
                # Slice 0 shifts left, slice 1 right.  Swapping slices before
                # the forward operation obtains the inverse of either one.
                target_z = z
                # This is the direct inverse of the two directional row shifts
                # (the pseudocode expresses it equivalently by exchanging the
                # slices before and after the forward ShiftRows).
                source_z = z
                delta_z = 1 - target_z if inverse_slices else target_z
                delta = -y if delta_z == 0 else y
                out[(x + delta) & 7][y][target_z] = A[x][y][source_z]
    for x in range(8):
        for y in range(6):
            for z in range(2):
                A[x][y][z] = out[x][y][z]


def mix_rows(A: list[list[list[int]]]) -> None:
    # The printed matrix is involutory.
    for y in range(6):
        for z in range(2):
            v0 = tuple(A[x][y][z] for x in (0, 2, 4, 6))
            v1 = tuple(A[x][y][z] for x in (1, 3, 5, 7))
            for x, value in zip((0, 2, 4, 6), mat_vec_mul(M_MIX_ROWS, v0)):
                A[x][y][z] = value
            for x, value in zip((1, 3, 5, 7), mat_vec_mul(M_MIX_ROWS, v1)):
                A[x][y][z] = value


def mandrx_forward(A: list[list[list[int]]]) -> None:
    for x in range(8):
        for y in range(6):
            left, right = A[x][y]
            for alpha, beta, gamma in SHIFTS:
                new_left = (
                    (rotr16(left, alpha) & rotr16(left, beta))
                    ^ rotr16(left, gamma)
                    ^ right
                )
                left, right = new_left, left
            A[x][y][0], A[x][y][1] = left, right


def mandrx_inverse(A: list[list[list[int]]]) -> None:
    for x in range(8):
        for y in range(6):
            left_next, right_next = A[x][y]
            for alpha, beta, gamma in reversed(SHIFTS):
                left_prev = right_next
                f = (
                    (rotr16(left_prev, alpha) & rotr16(left_prev, beta))
                    ^ rotr16(left_prev, gamma)
                )
                right_prev = left_next ^ f
                left_next, right_next = left_prev, right_prev
            A[x][y][0], A[x][y][1] = left_next, right_next


def round_forward(A: list[list[list[int]]], i: int) -> None:
    cross_mixs(A)
    swap_rows(A)
    mandrx_forward(A)
    cross_mixs(A)
    swap_rows(A)
    mix_columns(A)
    shift_rows(A)
    mix_rows(A)
    xor_round_constant(A, round_constants(i))


def round_inverse_literal(A: list[list[list[int]]], i: int) -> None:
    """Algorithm 2 exactly as printed, including forward MixColumns/MAndRX."""
    xor_round_constant(A, round_constants(i))
    mix_rows(A)
    for x in range(8):
        for y in range(6):
            A[x][y][0], A[x][y][1] = A[x][y][1], A[x][y][0]
    shift_rows(A)
    mix_columns(A)
    for x in range(8):
        for y in range(6):
            A[x][y][0], A[x][y][1] = A[x][y][1], A[x][y][0]
    swap_rows(A)
    cross_mixs(A)
    for x in range(8):
        for y in range(6):
            A[x][y][0], A[x][y][1] = A[x][y][1], A[x][y][0]
    mandrx_forward(A)
    swap_rows(A)
    cross_mixs(A)


def round_inverse_exact(A: list[list[list[int]]], i: int) -> None:
    """Inverse of round_forward, using inverses of the printed matrices."""
    xor_round_constant(A, round_constants(i))
    mix_rows(A)
    shift_rows(A, inverse_slices=True)
    mix_columns(A, M_MIX_COL_1_INV, M_MIX_COL_2_INV)
    swap_rows(A)
    cross_mixs(A)
    mandrx_inverse(A)
    swap_rows(A)
    cross_mixs(A)


def cube_p(A: list[list[list[int]]]) -> None:
    for i in range(18):
        round_forward(A, i)


def cube_f(A: list[list[list[int]]], branch: str) -> None:
    forward = clone_state(A)
    inverse = clone_state(A)
    for i in range(9):
        round_forward(forward, i)
    if branch == "algo4":
        for i in range(9):
            round_inverse_literal(inverse, i)
    elif branch == "hw17":
        for i in range(17, 8, -1):
            round_inverse_exact(inverse, i)
    elif branch == "exactzip":
        for i in range(8, -1, -1):
            round_inverse_exact(inverse, i)
    else:
        raise ValueError(f"unknown branch {branch}")
    for x in range(8):
        for y in range(6):
            for z in range(2):
                A[x][y][z] = forward[x][y][z] ^ inverse[x][y][z]


@dataclass(frozen=True)
class Serialization:
    axes: str
    dirs: str
    cell_bit: str

    def coordinates(self) -> list[tuple[int, int, int, int]]:
        axis_ranges = {"x": range(8), "y": range(6), "z": range(2)}
        reverse = {"+": False, "-": True}
        out: list[tuple[int, int, int, int]] = []
        for values in itertools.product(*(axis_ranges[a] for a in self.axes)):
            coord: dict[str, int] = dict(zip(self.axes, values))
            if any(reverse[d] for d in self.dirs):
                coord = {
                    axis_name: (axis_ranges[axis_name][-1] - value if reverse[dir_flag] else value)
                    for axis_name, value, dir_flag in zip(self.axes, values, self.dirs)
                }
            bits = range(15, -1, -1) if self.cell_bit == "msb" else range(16)
            for bit in bits:
                out.append((coord["x"], coord["y"], coord["z"], bit))
        return out


def bytes_to_bits(data: bytes) -> list[int]:
    return [(byte >> bit) & 1 for byte in data for bit in range(7, -1, -1)]


def bits_to_bytes(bits: Iterable[int]) -> bytes:
    values = list(bits)
    if len(values) % 8:
        raise ValueError("bit count is not byte aligned")
    return bytes(
        sum(values[i + j] << (7 - j) for j in range(8))
        for i in range(0, len(values), 8)
    )


def pad10_star_1(bits: list[int], rate: int) -> list[int]:
    padded = bits[:] + [1]
    padded.extend([0] * ((-len(padded) - 1) % rate))
    padded.append(1)
    if len(padded) % rate:
        raise AssertionError("padding failed")
    return padded


def xor_block(
    A: list[list[list[int]]],
    block: list[int],
    serialization: Serialization,
) -> None:
    for bit, (x, y, z, cell_bit) in zip(block, serialization.coordinates()):
        A[x][y][z] ^= bit << cell_bit


def squeeze(
    A: list[list[list[int]]],
    length: int,
    serialization: Serialization,
    branch: str,
) -> bytes:
    coords = serialization.coordinates()
    rate = RATE_BY_BITS[STATE_BITS - 64 - length if length in HASH_TO_CAPACITY else None]
    output: list[int] = []
    while len(output) < length:
        for x, y, z, cell_bit in coords[: int(rate)]:
            output.append((A[x][y][z] >> cell_bit) & 1)
            if len(output) == length:
                break
        if len(output) < length:
            cube_f(A, branch)
    return bits_to_bytes(output)


STATE_BITS = 1536
HASH_TO_CAPACITY = {512: 576, 768: 832, 1024: 1088}
RATE_BY_BITS = {STATE_BITS - capacity: capacity for capacity in HASH_TO_CAPACITY.values()}


def mastercube(
    message: bytes,
    hash_bits: int,
    branch: str,
    serialization: Serialization,
    absorb_rate_side: str = "front",
    squeeze_rate_side: str = "front",
) -> bytes:
    if hash_bits not in HASH_TO_CAPACITY:
        raise ValueError("unsupported hash size")
    if absorb_rate_side not in ("front", "back") or squeeze_rate_side not in ("front", "back"):
        raise ValueError("rate side must be front or back")
    rate = STATE_BITS - HASH_TO_CAPACITY[hash_bits]
    capacity = STATE_BITS - rate
    A = empty_state()
    padded = pad10_star_1(bytes_to_bits(message), rate)
    coords = serialization.coordinates()
    absorb_coords = coords[:rate] if absorb_rate_side == "front" else coords[capacity:]
    squeeze_coords = coords[:rate] if squeeze_rate_side == "front" else coords[capacity:]
    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate]
        for bit, (x, y, z, cell_bit) in zip(block, absorb_coords):
            A[x][y][z] ^= bit << cell_bit
        cube_f(A, branch)

    output: list[int] = []
    while len(output) < hash_bits:
        for x, y, z, cell_bit in squeeze_coords:
            output.append((A[x][y][z] >> cell_bit) & 1)
            if len(output) == hash_bits:
                break
        if len(output) < hash_bits:
            cube_f(A, branch)
    return bits_to_bytes(output)


def self_tests() -> dict[str, object]:
    rng_state = 0xC001D00D
    A = empty_state()
    for x in range(8):
        for y in range(6):
            for z in range(2):
                rng_state = (1103515245 * rng_state + 12345) & 0x7FFFFFFF
                A[x][y][z] = rng_state & MASK16

    m = clone_state(A)
    mandrx_forward(m)
    mandrx_inverse(m)
    mandrx_ok = m == A

    r = clone_state(A)
    round_forward(r, 7)
    round_inverse_exact(r, 7)
    round_inverse_ok = r == A

    literal = clone_state(A)
    round_forward(literal, 7)
    round_inverse_literal(literal, 7)
    literal_ok = literal == A

    return {
        "mandrx_forward_then_inverse_identity": mandrx_ok,
        "round_forward_then_exact_inverse_identity": round_inverse_ok,
        "round_forward_then_literal_algorithm2_identity": literal_ok,
        "mix_columns_1_inverse": M_MIX_COL_1_INV,
        "mix_columns_2_inverse": M_MIX_COL_2_INV,
    }


def load_vectors(path: str) -> list[dict[str, object]]:
    return json.loads(Path(path).read_text(encoding="utf-8"))["vectors"]


def enumerate_matches(vectors_path: str) -> dict[str, object]:
    vectors = load_vectors(vectors_path)
    branches = ("algo4", "hw17", "exactzip")
    serializations = [
        Serialization("".join(axes), "".join(dirs), cell_bit)
        for axes in itertools.permutations("xyz")
        for dirs in itertools.product("+-", repeat=3)
        for cell_bit in ("msb", "lsb")
    ]
    results: list[dict[str, object]] = []
    canonical: list[dict[str, object]] = []
    tested_runs = 0
    rate_sides = ("front", "back")
    for branch in branches:
        for absorb_side in rate_sides:
            for squeeze_side in rate_sides:
                for ser in serializations:
                    matches: list[str] = []
                    mismatches: list[dict[str, str]] = []
                    for vector in vectors:
                        label = str(vector["label"])
                        got = mastercube(
                            bytes.fromhex(str(vector["message"])),
                            int(vector["hash_bits"]),
                            branch,
                            ser,
                            absorb_side,
                            squeeze_side,
                        ).hex().upper()
                        expected = str(vector["digest"]).upper()
                        tested_runs += 1
                        first = next(
                            (i for i, (a, b) in enumerate(zip(got, expected)) if a != b),
                            None,
                        )
                        if got == expected:
                            matches.append(label)
                        else:
                            mismatches.append(
                                {
                                    "label": label,
                                    "got": got,
                                    "first_hex_nibble": str(first),
                                }
                            )
                        if (
                            absorb_side == "front"
                            and squeeze_side == "front"
                            and ser == Serialization("xyz", "+++", "msb")
                        ):
                            canonical.append(
                                {
                                    "branch": branch,
                                    "label": label,
                                    "expected_sha256_hex": hashlib.sha256(bytes.fromhex(expected)).hexdigest(),
                                    "got_sha256_hex": hashlib.sha256(bytes.fromhex(got)).hexdigest(),
                                    "got": got,
                                    "expected": expected,
                                    "full_match": got == expected,
                                    "first_hex_nibble_0based": first,
                                }
                            )
                    if matches:
                        results.append(
                            {
                                "branch": branch,
                                "absorb_rate_side": absorb_side,
                                "squeeze_rate_side": squeeze_side,
                                "serialization": asdict(ser),
                                "matches": matches,
                                "all": len(matches) == len(vectors),
                                "mismatches": mismatches,
                            }
                        )
    return {
        "vector_file": vectors_path,
        "vector_file_sha256": hashlib.sha256(Path(vectors_path).read_bytes()).hexdigest(),
        "branches": list(branches),
        "serialization_count_per_branch": len(serializations),
        "rate_window_pair_count": len(rate_sides) ** 2,
        "vector_count": len(vectors),
        "tested_branch_serialization_vector_runs": tested_runs,
        "full_match_count": sum(
            int(m["full_match"]) for m in canonical
        ) + sum(len(m["matches"]) for m in results if not (
            m["serialization"] == asdict(Serialization("xyz", "+++", "msb"))
        )),
        "self_tests": self_tests(),
        "matches": results,
        "canonical_serialization": asdict(Serialization("xyz", "+++", "msb")),
        "canonical_vector_results": canonical,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    one = sub.add_parser("hash")
    one.add_argument("--message-hex", required=True)
    one.add_argument("--hash-bits", type=int, choices=sorted(HASH_TO_CAPACITY), required=True)
    one.add_argument("--branch", choices=("algo4", "hw17", "exactzip"), required=True)
    one.add_argument("--axes", default="xyz")
    one.add_argument("--dirs", default="+++")
    one.add_argument("--cell-bit", choices=("msb", "lsb"), default="msb")
    enum = sub.add_parser("enumerate")
    enum.add_argument("--vectors", default="vectors.json")
    sub.add_parser("self-test")
    args = parser.parse_args()

    if args.command == "hash":
        ser = Serialization(args.axes, args.dirs, args.cell_bit)
        print(mastercube(bytes.fromhex(args.message_hex), args.hash_bits, args.branch, ser).hex().upper())
    elif args.command == "enumerate":
        print(json.dumps(enumerate_matches(args.vectors), indent=2))
    elif args.command == "self-test":
        print(json.dumps(self_tests(), indent=2))


if __name__ == "__main__":
    main()
