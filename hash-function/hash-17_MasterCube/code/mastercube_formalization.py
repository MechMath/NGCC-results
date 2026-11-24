#!/usr/bin/env python3
"""Exact finite formalization of the MasterCube v2.0 round and its inverse.

Coordinates follow the clean specification: A[x][y][z], with x=0..7,
y=0..5, and the two z-slices z=0,1. Each cell is a 16-bit value over F_2.
Matrix orientation is rows acting on column vectors.
"""

from __future__ import annotations

import copy
import hashlib
import itertools
import json

MASK = 0xFFFF
SOURCE_URL = (
    "https://cdn.jsdelivr.net/gh/ngcc-dev/ngcc-harness@"
    "dc66c6cb3c06e75bdea0048e21fa4e13c63f00af/hash-17/hash-17-spec.pdf"
)
SOURCE_SHA256 = "cc5b51b21af90a1331f83ebc03ac1a0452c60dd5f7e5661b84266beb7c9c21e9"

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
M_MIXCOLUMNS_LEFT = (
    (0, 1, 1),
    (1, 0, 1),
    (1, 1, 1),
)
M_MIXCOLUMNS_RIGHT = (
    (1, 0, 1),
    (0, 1, 1),
    (1, 1, 1),
)

ANDRX_SHIFTS = (
    (0, 1, 8),
    (14, 5, 0),
    (9, 12, 8),
    (14, 5, 0),
    (0, 1, 8),
    (8, 9, 0),
)

RC_BASE = (0x243F, 0x6A88, 0x85A3, 0x08D3,
           0x1319, 0x8A2E, 0x0370, 0x7344)


def rotr16(x: int, k: int) -> int:
    k %= 16
    return ((x >> k) | (x << (16 - k))) & MASK if k else x


def new_state():
    return [[[0, 0] for _ in range(6)] for _ in range(8)]


def matvec(matrix, vector):
    result = []
    for row in matrix:
        value = 0
        for coefficient, entry in zip(row, vector):
            if coefficient:
                value ^= entry
        result.append(value)
    return tuple(result)


def matmul(a, b):
    return tuple(
        tuple(sum(a[i][k] * b[k][j] for k in range(len(b))) & 1
              for j in range(len(b[0])))
        for i in range(len(a))
    )


def identity(n):
    return tuple(tuple(int(i == j) for j in range(n)) for i in range(n))


def andrx(l, r, alpha, beta, gamma):
    return ((rotr16(l, alpha) & rotr16(l, beta)) ^
            rotr16(l, gamma) ^ r) & MASK, l


def andrx_inv(lp, rp, alpha, beta, gamma):
    l = rp
    r = lp ^ ((rotr16(l, alpha) & rotr16(l, beta)) ^ rotr16(l, gamma))
    return l & MASK, r & MASK


def mandrx_halves(l, r):
    trace = []
    for alpha, beta, gamma in ANDRX_SHIFTS:
        l, r = andrx(l, r, alpha, beta, gamma)
        trace.append((l, r))
    return (l, r), trace


def mandrx_halves_inv(l, r):
    trace = []
    for alpha, beta, gamma in reversed(ANDRX_SHIFTS):
        l, r = andrx_inv(l, r, alpha, beta, gamma)
        trace.append((l, r))
    return (l, r), trace


def mandrx(a, inverse=False):
    b = copy.deepcopy(a)
    for x in range(8):
        for y in range(6):
            if inverse:
                b[x][y] = list(mandrx_halves_inv(*b[x][y])[0])
            else:
                b[x][y] = list(mandrx_halves(*b[x][y])[0])
    return b


def slices_swap(a):
    b = copy.deepcopy(a)
    for x in range(8):
        for y in range(6):
            b[x][y] = [a[x][y][1], a[x][y][0]]
    return b


def swap_rows(a):
    b = copy.deepcopy(a)
    for x in range(8):
        for y in (0, 2, 4):
            b[x][y][1], b[x][y + 1][1] = a[x][y + 1][1], a[x][y][1]
    return b


def cross_mixs(a):
    b = copy.deepcopy(a)
    for x in range(8):
        for z in range(2):
            out = matvec(M_CROSSMIXS, [a[x][y][z] for y in range(6)])
            for y, value in enumerate(out):
                b[x][y][z] = value
    return b


def mix_rows(a):
    b = copy.deepcopy(a)
    for x in range(8):
        for y in range(6):
            for z in range(2):
                for parity in range(2):
                    xs = tuple(range(parity, 8, 2))
                    pos = [a[i][y][z] for i in xs]
                    out = matvec(M_MIXROWS, pos)
                    for i, value in zip(xs, out):
                        b[i][y][z] = value
    return b


def mix_columns(a, inverse=False):
    b = copy.deepcopy(a)
    for x in range(8):
        for parity in range(2):
            ys = tuple(range(parity, 6, 2))
            for z in range(2):
                if inverse:
                    matrix = M_MIXCOLUMNS_RIGHT if z == 0 else M_MIXCOLUMNS_LEFT
                else:
                    matrix = M_MIXCOLUMNS_LEFT if z == 0 else M_MIXCOLUMNS_RIGHT
                out = matvec(matrix, [a[x][y][z] for y in ys])
                for y, value in zip(ys, out):
                    b[x][y][z] = value
    return b


def shift_rows(a):
    b = copy.deepcopy(a)
    for x in range(8):
        for y in range(6):
            for z in range(2):
                destination = (x - y) % 8 if z == 0 else (x + y) % 8
                b[destination][y][z] = a[x][y][z]
    return b


def inverse_shift_rows(a):
    b = copy.deepcopy(a)
    for x in range(8):
        for y in range(6):
            for z in range(2):
                destination = (x + y) % 8 if z == 0 else (x - y) % 8
                b[destination][y][z] = a[x][y][z]
    return b


def xor_rc(a, i):
    b = copy.deepcopy(a)
    for x in range(8):
        b[x][0][0] ^= RC_BASE[x] ^ i
    return b


def round_forward(a, i):
    return xor_rc(
        mix_rows(shift_rows(mix_columns(swap_rows(cross_mixs(
            mandrx(swap_rows(cross_mixs(a)))))))),
        i,
    )


def round_inverse_exact(a, i):
    return cross_mixs(swap_rows(mandrx(
        cross_mixs(swap_rows(mix_columns(
            inverse_shift_rows(mix_rows(xor_rc(a, i))), inverse=True))),
        inverse=True)))


def round_inverse_literal(a, i):
    """Algorithm 2 literally: forward ShiftRows/SwapRows and forward MAndRX."""
    b = xor_rc(a, i)
    b = mix_rows(b)
    b = slices_swap(b)
    b = shift_rows(b)
    b = mix_columns(b, inverse=False)
    b = slices_swap(b)
    b = swap_rows(b)
    b = cross_mixs(b)
    b = slices_swap(b)
    b = mandrx(b, inverse=False)
    b = swap_rows(b)
    b = cross_mixs(b)
    return b


def round_inverse_algorithm2_fixed_mandrx(a, i):
    """Exact correction: delete line 10 and invert MAndRX at line 11."""
    b = xor_rc(a, i)
    b = mix_rows(b)
    b = slices_swap(b)
    b = shift_rows(b)
    b = mix_columns(b, inverse=False)
    b = slices_swap(b)
    b = swap_rows(b)
    b = cross_mixs(b)
    b = mandrx(b, inverse=True)
    b = swap_rows(b)
    b = cross_mixs(b)
    return b


def serialize(a):
    return "".join(f"{a[x][y][z]:04X}" for x in range(8)
                   for y in range(6) for z in range(2))


def digest(a):
    return hashlib.sha256(bytes.fromhex(serialize(a))).hexdigest()


def q_inverse(b):
    return cross_mixs(swap_rows(b))


def xor_states(a, b):
    return [copy.deepcopy(a), copy.deepcopy(b)]


def state_xor(a, b):
    c = new_state()
    for x in range(8):
        for y in range(6):
            for z in range(2):
                c[x][y][z] = a[x][y][z] ^ b[x][y][z]
    return c


def cube_f(a, branch="literal"):
    forward = copy.deepcopy(a)
    inverse = copy.deepcopy(a)
    for i in range(9):
        forward = round_forward(forward, i)
        if branch == "literal":
            inverse = round_inverse_literal(inverse, i)
        elif branch == "exact_same_index":
            inverse = round_inverse_exact(inverse, i)
        elif branch == "exact_reverse_index":
            pass
        else:
            raise ValueError(branch)
    if branch == "exact_reverse_index":
        for i in reversed(range(9)):
            inverse = round_inverse_exact(inverse, i)
    return state_xor(forward, inverse)


def cube_f_fixed(a):
    """ZIP with exact Cube-p-ir, indexed 0..8 as in Algorithm 4."""
    forward = copy.deepcopy(a)
    inverse = copy.deepcopy(a)
    for i in range(9):
        forward = round_forward(forward, i)
        inverse = round_inverse_algorithm2_fixed_mandrx(inverse, i)
    return state_xor(forward, inverse)


def full_differences(a, b):
    return [[x, y, z, a[x][y][z], b[x][y][z]]
            for x in range(8) for y in range(6) for z in range(2)
            if a[x][y][z] != b[x][y][z]]


def check_linear_layers():
    assert matmul(M_MIXROWS, M_MIXROWS) == identity(4)
    assert matmul(M_CROSSMIXS, M_CROSSMIXS) == identity(6)
    assert matmul(M_MIXCOLUMNS_LEFT, M_MIXCOLUMNS_RIGHT) == identity(3)
    assert matmul(M_MIXCOLUMNS_RIGHT, M_MIXCOLUMNS_LEFT) == identity(3)
    for v in itertools.product((0, 1), repeat=4):
        assert matvec(M_MIXROWS, matvec(M_MIXROWS, v)) == v
    for v in itertools.product((0, 1), repeat=6):
        assert matvec(M_CROSSMIXS, matvec(M_CROSSMIXS, v)) == v
    for v in itertools.product((0, 1), repeat=3):
        assert matvec(M_MIXCOLUMNS_RIGHT, matvec(M_MIXCOLUMNS_LEFT, v)) == v
        assert matvec(M_MIXCOLUMNS_LEFT, matvec(M_MIXCOLUMNS_RIGHT, v)) == v

    # F2-linear equalities are proved for all 1536-bit states by checking
    # every one-bit tensor basis vector.  This includes the exact meaning of
    # Algorithm 2's slice-swap-surrounded forward ShiftRows/MixColumns.
    for x in range(8):
        for y in range(6):
            for z in range(2):
                for value in (1, 2, 0x8000):
                    a = new_state()
                    a[x][y][z] = value
                    assert swap_rows(swap_rows(a)) == a
                    assert cross_mixs(cross_mixs(a)) == a
                    assert mix_rows(mix_rows(a)) == a
                    assert mix_columns(mix_columns(a, True)) == a
                    assert inverse_shift_rows(shift_rows(a)) == a
                    assert slices_swap(shift_rows(slices_swap(a))) == inverse_shift_rows(a)
                    assert slices_swap(mix_columns(slices_swap(a))) == mix_columns(
                        a, inverse=True)
                    assert (
                        slices_swap(mix_columns(
                            shift_rows(slices_swap(a))))
                        == mix_columns(inverse_shift_rows(a), inverse=True)
                    )
                    assert round_inverse_exact(round_forward(a, 0), 0) == a
                    assert round_forward(round_inverse_exact(a, 0), 0) == a
                    assert (
                        round_inverse_algorithm2_fixed_mandrx(
                            round_forward(a, 0), 0)
                        == a
                    )
                    assert (
                        round_forward(
                            round_inverse_algorithm2_fixed_mandrx(a, 0), 0)
                        == a
                    )
    return {
        "MixRows": "M^2=I_4 for all 16 vectors",
        "CrossMixs": "M^2=I_6 for all 64 vectors",
        "MixColumns": "M_left*M_right=I_3 in both orders for all 8 vectors",
        "ShiftRows": "S*ShiftRows*S=ShiftRows^-1 on all 1536 basis bits",
        "Algorithm2_linear_inverse": (
            "S*MixColumns*ShiftRows*S = MixColumns^-1*ShiftRows^-1 "
            "on all 1536 basis bits"
        ),
        "SwapRows": "involution on all 1536 basis bits",
        "statewide": "all listed linear inverse identities hold on every basis bit",
    }


def check_mandrx_with_z3():
    """Symbolically prove the six-round Feistel inverse over all 2^32 lanes."""
    from z3 import BitVec, BitVecVal, Or, Solver, sat, unsat

    width = 16
    l, r = BitVec("l", width), BitVec("r", width)

    def rot(x, k):
        return BitVecVal(0, width) if k == 0 else (
            (x >> k) | (x << (width - k)))

    def step(l, r, alpha, beta, gamma):
        return (rot(l, alpha) & rot(l, beta)) ^ rot(l, gamma) ^ r, l

    def inv_step(lp, rp, alpha, beta, gamma):
        return rp, lp ^ ((rot(rp, alpha) & rot(rp, beta)) ^ rot(rp, gamma))

    fl, fr = l, r
    for shifts in ANDRX_SHIFTS:
        fl, fr = step(fl, fr, *shifts)
    bl, br = fl, fr
    for shifts in reversed(ANDRX_SHIFTS):
        bl, br = inv_step(bl, br, *shifts)

    solver = Solver()
    solver.add(Or(bl != l, br != r))
    result = solver.check()
    assert result == unsat, result

    # Independently show the six-round map is not an involution.
    il, ir = fl, fr
    for shifts in ANDRX_SHIFTS:
        il, ir = step(il, ir, *shifts)
    solver = Solver()
    solver.add(Or(il != l, ir != r))
    assert solver.check() == sat
    return {
        "inverse_quantifier": "forall 16-bit L,R",
        "inverse_smt_result": "unsat of negation (proved)",
        "involution_quantifier": "exists 16-bit L,R",
        "involution_smt_result": "sat of negation (not an involution)",
    }


def evidence():
    linear = check_linear_layers()
    mandrx_smt = check_mandrx_with_z3()
    for alpha, beta, gamma in ANDRX_SHIFTS:
        for l in range(65536):
            for r in (0, MASK, l ^ 0xA5A5):
                assert andrx_inv(*andrx(l, r, alpha, beta, gamma),
                                 alpha, beta, gamma) == (l, r)

    original = 0x9E9230B8
    image, trace1 = mandrx_halves(original >> 16, original & MASK)
    image32 = (image[0] << 16) | image[1]
    image2, trace2 = mandrx_halves(*image)
    image232 = (image2[0] << 16) | image2[1]
    assert image32 == 0x12341234 and image232 != original
    assert mandrx_halves_inv(*image2)[0] == image

    b = new_state()
    b[0][0] = [original >> 16, original & MASK]
    a = q_inverse(b)
    fwd = round_forward(a, 0)
    literal_back = round_inverse_literal(fwd, 0)
    exact_back = round_inverse_exact(fwd, 0)
    assert exact_back == a and literal_back != a
    fixed_back = round_inverse_algorithm2_fixed_mandrx(fwd, 0)
    assert fixed_back == a

    # Isolate the second Algorithm 2 defect: delete/invert MAndRX but retain
    # the slice swap at line 10.
    swap_input = new_state()
    swap_input[0][0][0] = 1
    swap_fwd = round_forward(swap_input, 0)
    swap_only_b = xor_rc(swap_fwd, 0)
    swap_only_b = mix_rows(swap_only_b)
    swap_only_b = slices_swap(swap_only_b)
    swap_only_b = shift_rows(swap_only_b)
    swap_only_b = mix_columns(swap_only_b)
    swap_only_b = slices_swap(swap_only_b)
    swap_only_b = swap_rows(swap_only_b)
    swap_only_b = cross_mixs(swap_only_b)
    swap_only_b = slices_swap(swap_only_b)
    swap_only_b = mandrx(swap_only_b, inverse=True)
    swap_only_b = swap_rows(swap_only_b)
    swap_only_b = cross_mixs(swap_only_b)
    assert swap_only_b != swap_input

    # Isolate the third defect: line 11 uses forward MAndRX (line 10 removed).
    forward_m_b = round_inverse_algorithm2_fixed_mandrx(fwd, 0)
    assert forward_m_b == a
    no_swap_input = new_state()
    no_swap_input[0][0][0] = 3
    no_swap_fwd = round_forward(no_swap_input, 0)
    no_swap_b = xor_rc(no_swap_fwd, 0)
    no_swap_b = mix_rows(no_swap_b)
    no_swap_b = slices_swap(no_swap_b)
    no_swap_b = shift_rows(no_swap_b)
    no_swap_b = mix_columns(no_swap_b)
    no_swap_b = slices_swap(no_swap_b)
    no_swap_b = swap_rows(no_swap_b)
    no_swap_b = cross_mixs(no_swap_b)
    no_swap_b = mandrx(no_swap_b, inverse=False)
    no_swap_b = swap_rows(no_swap_b)
    no_swap_b = cross_mixs(no_swap_b)
    assert no_swap_b != no_swap_input

    zero = new_state()
    cf_literal = cube_f(zero, "literal")
    cf_same_index = cube_f(zero, "exact_same_index")
    cf_reverse_index = cube_f(zero, "exact_reverse_index")
    assert cf_same_index != cf_reverse_index
    assert cf_literal != cf_same_index
    assert cube_f_fixed(zero) == cf_same_index

    return {
        "source": {
            "url": SOURCE_URL,
            "sha256": SOURCE_SHA256,
            "document_version": "2.0, June 2026",
            "coordinate_convention": (
                "A[x][y][z], x=0..7 left-to-right, y=0..5, z=0..1; "
                "A[x,y,0] is the left 16-bit Feistel half"
            ),
        },
        "linear_layer_checks": linear,
        "MAndRX": {
            "definition": "six Feistel rounds with the listed shift triples",
            "exact_inverse": "old L=R', old R=L' xor f(R')",
            "smt": mandrx_smt,
            "witness_input": f"{original:08X}",
            "forward_trace": [[f"{l:04X}", f"{r:04X}"] for l, r in trace1],
            "M_input": f"{image32:08X}",
            "M_squared": f"{image232:08X}",
            "not_involution": True,
        },
        "Algorithm2_full_round": {
            "B_input_to_first_C_S_pair": f"{original:08X} at A[0,0]",
            "A_digest": digest(a),
            "forward_image_digest": digest(fwd),
            "literal_inverse_digest": digest(literal_back),
            "exact_inverse_recovers": True,
            "literal_mismatch_count": len(full_differences(a, literal_back)),
            "first_mismatch": full_differences(a, literal_back)[0],
            "final_mismatch": full_differences(a, literal_back)[-1],
            "fixed_line11_recovers": fixed_back == a,
            "literal_nonzero_before_inverse": [
                [x, y, z, f"{a[x][y][z]:04X}"]
                for x in range(8) for y in range(6) for z in range(2)
                if a[x][y][z]
            ],
            "literal_nonzero_after_inverse": [
                [x, y, z, f"{literal_back[x][y][z]:04X}"]
                for x in range(8) for y in range(6) for z in range(2)
                if literal_back[x][y][z]
            ],
            "line10_extra_swap_counterexample": {
                "A_input": [0, 0, 0, 1],
                "forward_image_digest": digest(swap_fwd),
                "recovered_digest": digest(swap_only_b),
                "with_line10_and_inverse_mandrx_recovers": False,
                "first_mismatch": full_differences(
                    swap_input, swap_only_b)[0],
                "final_mismatch": full_differences(
                    swap_input, swap_only_b)[-1],
            },
            "line11_forward_mandrx_counterexample": {
                "A_input": [0, 0, 0, 3],
                "forward_image_digest": digest(no_swap_fwd),
                "recovered_digest": digest(no_swap_b),
                "first_mismatch": full_differences(
                    no_swap_input, no_swap_b)[0],
                "final_mismatch": full_differences(
                    no_swap_input, no_swap_b)[-1],
            },
        },
        "Algorithm4_round_order": {
            "same_index_0_to_8_is_correct_for_P^-9": True,
            "reason": (
                "If P^9=R8*...*R0, then P^-9=R0^-1*...*R8^-1; "
                "Algorithm 4 therefore applies Cube-p-ir with i=0..8."
            ),
            "zero_literal_digest": digest(cf_literal),
            "zero_exact_same_index_digest": digest(cf_same_index),
            "zero_exact_reverse_index_digest": digest(cf_reverse_index),
            "zero_fixed_algorithm4_digest": digest(cf_same_index),
            "same_index_mismatch_count": len(
                full_differences(cf_same_index, cf_reverse_index)),
            "first_same_index_mismatch": full_differences(
                cf_same_index, cf_reverse_index)[0],
            "literal_vs_fixed_mismatch_count": len(
                full_differences(cf_same_index, cf_literal)),
            "first_literal_vs_fixed_mismatch": full_differences(
                cf_same_index, cf_literal)[0],
        },
    }


if __name__ == "__main__":
    print(json.dumps(evidence(), indent=2))
