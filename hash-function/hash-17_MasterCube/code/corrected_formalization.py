#!/usr/bin/env python3
"""Corrected MasterCube v2.0 round formalization.

Figure 5 on p. 7 orders the six-bit CrossMixs operands as

    [z=0,y=0, z=0,y=2, z=0,y=4, z=1,y=0, z=1,y=2, z=1,y=4]

for even y, and analogously for odd y.  Thus CrossMixs does not act
independently on each z-slice.
"""

from __future__ import annotations

import copy
import hashlib
import itertools
import json
import random

MASK = 0xFFFF
SHIFTS = ((0, 1, 8), (14, 5, 0), (9, 12, 8),
          (14, 5, 0), (0, 1, 8), (8, 9, 0))
RC_BASE = (0x243F, 0x6A88, 0x85A3, 0x08D3,
           0x1319, 0x8A2E, 0x0370, 0x7344)

MIXROWS = ((1, 1, 0, 1), (1, 1, 1, 0),
           (0, 1, 1, 1), (1, 0, 1, 1))
CROSSMIXS = ((1, 1, 0, 0, 1, 0), (0, 1, 1, 0, 0, 1),
             (1, 0, 1, 1, 0, 0), (0, 1, 0, 1, 1, 0),
             (0, 0, 1, 0, 1, 1), (1, 0, 0, 1, 0, 1))
MIXCOLUMNS_0 = ((0, 1, 1), (1, 0, 1), (1, 1, 1))
MIXCOLUMNS_1 = ((1, 0, 1), (0, 1, 1), (1, 1, 1))


def state():
    return [[[0, 0] for _ in range(6)] for _ in range(8)]


def clone(a):
    return copy.deepcopy(a)


def mv(mat, vec):
    out = []
    for row in mat:
        value = 0
        for coefficient, entry in zip(row, vec):
            if coefficient:
                value ^= entry
        out.append(value)
    return tuple(out)


def mm(a, b):
    return tuple(
        tuple(sum(a[i][k] * b[k][j] for k in range(len(b))) & 1
              for j in range(len(b[0])))
        for i in range(len(a))
    )


def eye(n):
    return tuple(tuple(int(i == j) for j in range(n))
                 for i in range(n))


def rotr(x, k):
    return x if k == 0 else ((x >> k) | (x << (16 - k))) & MASK


def f_step(l, r, shift):
    a, b, c = shift
    f = (rotr(l, a) & rotr(l, b)) ^ rotr(l, c)
    return (f ^ r) & MASK, l


def f_step_inv(lp, rp, shift):
    a, b, c = shift
    f = (rotr(rp, a) & rotr(rp, b)) ^ rotr(rp, c)
    return rp, (lp ^ f) & MASK


def mandrx(a, inverse=False):
    b = clone(a)
    shifts = reversed(SHIFTS) if inverse else SHIFTS
    op = f_step_inv if inverse else f_step
    shifts = tuple(shifts)
    for x in range(8):
        for y in range(6):
            l, r = b[x][y]
            for shift in shifts:
                l, r = op(l, r, shift)
            b[x][y] = [l, r]
    return b


def cross_mixs(a):
    """Apply MCrossMixs to each parity class across both z-slices."""
    b = clone(a)
    for x in range(8):
        for parity in range(2):
            ys = tuple(range(parity, 6, 2))
            # Printed vectors v[2y], v[2y+2], ...: all z=0 entries,
            # then all z=1 entries.
            vec = tuple(a[x][y][z] for z in range(2) for y in ys)
            out = mv(CROSSMIXS, vec)
            for index, y in enumerate(ys):
                b[x][y][0] = out[index]
                b[x][y][1] = out[index + 3]
    return b


def swap_rows(a):
    b = clone(a)
    for x in range(8):
        for y in (0, 2, 4):
            b[x][y][1], b[x][y + 1][1] = (
                a[x][y + 1][1], a[x][y][1])
    return b


def mix_columns(a, inverse=False):
    b = clone(a)
    for x in range(8):
        for parity in range(2):
            ys = tuple(range(parity, 6, 2))
            mats = ((MIXCOLUMNS_1, MIXCOLUMNS_0) if inverse
                    else (MIXCOLUMNS_0, MIXCOLUMNS_1))
            for z, mat in enumerate(mats):
                out = mv(mat, tuple(a[x][y][z] for y in ys))
                for y, value in zip(ys, out):
                    b[x][y][z] = value
    return b


def shift_rows(a):
    b = clone(a)
    for x in range(8):
        for y in range(6):
            for z in range(2):
                dest = (x - y) % 8 if z == 0 else (x + y) % 8
                b[dest][y][z] = a[x][y][z]
    return b


def shift_rows_inv(a):
    b = clone(a)
    for x in range(8):
        for y in range(6):
            for z in range(2):
                dest = (x + y) % 8 if z == 0 else (x - y) % 8
                b[dest][y][z] = a[x][y][z]
    return b


def mix_rows(a):
    b = clone(a)
    for x in range(8):
        for y in range(6):
            for z in range(2):
                for parity in range(2):
                    xs = tuple(range(parity, 8, 2))
                    out = mv(MIXROWS, tuple(a[i][y][z] for i in xs))
                    for i, value in zip(xs, out):
                        b[i][y][z] = value
    return b


def slice_swap(a):
    b = clone(a)
    for x in range(8):
        for y in range(6):
            b[x][y] = [a[x][y][1], a[x][y][0]]
    return b


def rc_xor(a, i):
    b = clone(a)
    for x in range(8):
        b[x][0][0] ^= RC_BASE[x] ^ i
    return b


def forward(a, i):
    return rc_xor(
        mix_rows(shift_rows(mix_columns(swap_rows(cross_mixs(
            mandrx(swap_rows(cross_mixs(a)))))))),
        i,
    )


def inverse_exact(a, i):
    b = rc_xor(a, i)
    b = mix_rows(b)
    b = shift_rows_inv(b)
    b = mix_columns(b, inverse=True)
    b = swap_rows(b)
    b = cross_mixs(b)
    b = mandrx(b, inverse=True)
    b = swap_rows(b)
    return cross_mixs(b)


def inverse_literal(a, i):
    b = rc_xor(a, i)
    b = mix_rows(b)
    b = slice_swap(b)
    b = shift_rows(b)
    b = mix_columns(b)
    b = slice_swap(b)
    b = swap_rows(b)
    b = cross_mixs(b)
    b = slice_swap(b)              # line 10
    b = mandrx(b)                  # line 11, forward
    b = swap_rows(b)
    b = cross_mixs(b)
    return b


def inverse_delete_line10_only(a, i):
    """Single edit: delete line 10, leave line 11 forward."""
    b = rc_xor(a, i)
    b = mix_rows(b)
    b = slice_swap(b)
    b = shift_rows(b)
    b = mix_columns(b)
    b = slice_swap(b)
    b = swap_rows(b)
    b = cross_mixs(b)
    b = mandrx(b)
    b = swap_rows(b)
    b = cross_mixs(b)
    return b


def inverse_invert_line11_only(a, i):
    """Single edit: keep line 10, invert line 11."""
    b = rc_xor(a, i)
    b = mix_rows(b)
    b = slice_swap(b)
    b = shift_rows(b)
    b = mix_columns(b)
    b = slice_swap(b)
    b = swap_rows(b)
    b = cross_mixs(b)
    b = slice_swap(b)
    b = mandrx(b, inverse=True)
    b = swap_rows(b)
    b = cross_mixs(b)
    return b


def inverse_two_edits(a, i):
    """Delete line 10 and invert line-11 MAndRX."""
    b = rc_xor(a, i)
    b = mix_rows(b)
    b = slice_swap(b)
    b = shift_rows(b)
    b = mix_columns(b)
    b = slice_swap(b)
    b = swap_rows(b)
    b = cross_mixs(b)
    b = mandrx(b, inverse=True)
    b = swap_rows(b)
    b = cross_mixs(b)
    return b


def xor(a, b):
    c = state()
    for x in range(8):
        for y in range(6):
            for z in range(2):
                c[x][y][z] = a[x][y][z] ^ b[x][y][z]
    return c


def cube_f(a, inverse_fn=inverse_exact, descending=False):
    p = clone(a)
    q = clone(a)
    for i in range(9):
        p = forward(p, i)
    indices = reversed(range(9)) if descending else range(9)
    for i in indices:
        q = inverse_fn(q, i)
    return xor(p, q)


def digest(a):
    raw = bytes.fromhex("".join(
        f"{a[x][y][z]:04X}"
        for x in range(8) for y in range(6) for z in range(2)))
    return hashlib.sha256(raw).hexdigest()


def diffs(a, b):
    return [[x, y, z, a[x][y][z], b[x][y][z]]
            for x in range(8) for y in range(6) for z in range(2)
            if a[x][y][z] != b[x][y][z]]


def basis_states():
    for x in range(8):
        for y in range(6):
            for z in range(2):
                for value in (1, 2, 0x8000):
                    a = state()
                    a[x][y][z] = value
                    yield a


def check_linear_and_round():
    assert mm(MIXROWS, MIXROWS) == eye(4)
    assert mm(CROSSMIXS, CROSSMIXS) == eye(6)
    assert mm(MIXCOLUMNS_0, MIXCOLUMNS_1) == eye(3)
    assert mm(MIXCOLUMNS_1, MIXCOLUMNS_0) == eye(3)

    counts = 0
    for a in basis_states():
        assert cross_mixs(cross_mixs(a)) == a
        assert swap_rows(swap_rows(a)) == a
        assert mix_rows(mix_rows(a)) == a
        assert mix_columns(mix_columns(a), inverse=True) == a
        assert mix_columns(mix_columns(a, inverse=True)) == a
        assert shift_rows_inv(shift_rows(a)) == a
        assert shift_rows(shift_rows_inv(a)) == a
        assert slice_swap(shift_rows(slice_swap(a))) == shift_rows_inv(a)
        assert (
            slice_swap(mix_columns(slice_swap(a), inverse=True))
            == mix_columns(a)
        )
        assert (
            slice_swap(mix_columns(shift_rows(slice_swap(a))))
            == mix_columns(shift_rows_inv(a), inverse=True)
        )
        for i in range(18):
            b = forward(a, i)
            assert inverse_exact(b, i) == a
            assert forward(inverse_exact(a, i), i) == a
            assert inverse_two_edits(b, i) == a
            assert forward(inverse_two_edits(a, i), i) == a
        counts += 1
    return counts


def check_mandrx_symbolic():
    import z3
    l = z3.BitVec("l", 16)
    r = z3.BitVec("r", 16)

    def rot(x, k):
        return x if k == 0 else z3.RotateRight(x, k)

    def step(x, y, shift):
        a, b, c = shift
        return (rot(x, a) & rot(x, b)) ^ rot(x, c) ^ y, x

    def inv(x, y, shift):
        a, b, c = shift
        return y, x ^ ((rot(y, a) & rot(y, b)) ^ rot(y, c))

    fl, fr = l, r
    for shift in SHIFTS:
        fl, fr = step(fl, fr, shift)
    bl, br = fl, fr
    for shift in reversed(SHIFTS):
        bl, br = inv(bl, br, shift)
    s = z3.Solver()
    s.add(z3.Or(bl != l, br != r))
    assert s.check() == z3.unsat
    return "z3.unsat(forall 16-bit lane inputs)"


def check_single_edit_insufficiency():
    a10 = state()
    a10[0][0][0] = 1
    a10[0][0][1] = 2
    b10 = inverse_delete_line10_only(forward(a10, 0), 0)
    assert b10 != a10

    a11 = state()
    a11[0][0][0] = 1
    a11[0][0][1] = 2
    b11 = inverse_invert_line11_only(forward(a11, 0), 0)
    assert b11 != a11

    alit = state()
    alit[0][0][0] = 1
    alit[0][1][1] = 0x8001
    blit = inverse_literal(forward(alit, 0), 0)
    assert blit != alit
    return {
        "delete_line10_only": {
            "nonzero_input": [[0, 0, 0, 1], [0, 0, 1, 2]],
            "recovered": [b10[0][0][0], b10[0][1][1]],
            "first_mismatch": diffs(a10, b10)[0],
        },
        "invert_line11_only": {
            "nonzero_input": [[0, 0, 0, 1], [0, 0, 1, 2]],
            "recovered": [b11[0][0][0], b11[0][1][1]],
            "first_mismatch": diffs(a11, b11)[0],
        },
        "literal": {
            "nonzero_input_cells": [[0, 0, 0, 1], [0, 1, 1, 0x8001]],
            "mismatch_count": len(diffs(alit, blit)),
            "first_mismatch": diffs(alit, blit)[0],
        },
    }


def random_states(count=24, seed=0x4D435F434D):
    rng = random.Random(seed)
    for _ in range(count):
        a = state()
        for x in range(8):
            for y in range(6):
                a[x][y][0] = rng.getrandbits(16)
                a[x][y][1] = rng.getrandbits(16)
        yield a


def structured_states():
    zeros = state()
    ones = state()
    digest_round = state()
    for x in range(8):
        for y in range(6):
            for z in range(2):
                ones[x][y][z] = MASK
                digest_round[x][y][z] = ((x * 97 + y * 31 + z * 17) ^ 0xA5C3)
    return (zeros, ones, digest_round)


def check_cube_f():
    reports = []
    for label, a in (
        *(("structured", a) for a in structured_states()),
        *(("random", a) for a in random_states()),
    ):
        exact = cube_f(a, inverse_exact, descending=True)
        same_index_exact = cube_f(a, inverse_exact)
        literal = cube_f(a, inverse_literal)
        both = cube_f(a, inverse_two_edits, descending=True)
        both_same_index = cube_f(a, inverse_two_edits)
        del10 = cube_f(a, inverse_delete_line10_only, descending=True)
        inv11 = cube_f(a, inverse_invert_line11_only, descending=True)
        assert both == exact
        reports.append({
            "kind": label,
            "input_digest": digest(a),
            "exact_f_digest": digest(exact),
            "same_index_exact_round_differs": same_index_exact != exact,
            "literal_differs": literal != exact,
            "two_edits_same_index_differs": both_same_index != exact,
            "delete10_differs": del10 != exact,
            "invert11_differs": inv11 != exact,
        })
    return reports


def evidence():
    basis = check_linear_and_round()
    singles = check_single_edit_insufficiency()
    cube = check_cube_f()
    return {
        "source": {
            "url": "https://cdn.jsdelivr.net/gh/ngcc-dev/ngcc-harness@dc66c6cb3c06e75bdea0048e21fa4e13c63f00af/hash-17/hash-17-spec.pdf",
            "sha256": "cc5b51b21af90a1331f83ebc03ac1a0452c60dd5f7e5661b84266beb7c9c21e9",
            "figure": "p.7 Figure 5 and equations",
            "algorithms": "p.8 Algorithms 1 and 2",
        },
        "crossmix_convention": {
            "mapping": "v[6*z+y] = A[x,y,z]",
            "vector_order": "[v0,v2,v4,v6,v8,v10] or [v1,v3,v5,v7,v9,v11]",
            "slices_mixed_together": True,
        },
        "linear_basis_states_checked": basis,
        "mandrx_quantified_check": check_mandrx_symbolic(),
        "one_round_equations": {
            "P_i": "K_i Y Q C W X M W X",
            "R_i": "X W M^-1 X W C^-1 Q^-1 Y K_i",
            "literal_G_i": "X W M S X W S C Q S Y K_i",
            "two_edits_exact_for_all_basis_inputs": True,
        },
        "single_edit_counterexamples": singles,
        "cube_f_checks": {
            "correct_inverse_order": "execute R_8, R_7, ..., R_0",
            "incorrect_same_index_order": "0,1,...,8",
            "cases": cube,
        },
        "scope": (
            "One corrected Cube-p round and the literal Algorithm 4 "
            "Cube-f structure with inverse traversal 8,...,0. "
            "No digest collision or unrelated "
            "hardware-schedule interpretation is claimed."
        ),
    }


if __name__ == "__main__":
    print(json.dumps(evidence(), indent=2, sort_keys=True))
