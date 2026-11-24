#!/usr/bin/env python3
"""Check the lane-uniform subspace against psi and L for pinned Thunder-p."""

from thunder_fixedspace import RC, TAU, linear, psi, pos


def rank(vectors):
    basis = {}
    for row in vectors:
        while row:
            p = row.bit_length() - 1
            if p in basis:
                row ^= basis[p]
            else:
                basis[p] = row
                break
    return len(basis)


def in_v(x):
    return all(
        len({(x >> pos(a, b, z)) & 1 for a in range(5) for b in range(5)}) == 1
        for z in range(64)
    )


def v_word(x):
    return sum(((x >> pos(0, 0, z)) & 1) << z for z in range(64))


def main():
    v_basis = []
    for z in range(64):
        x = 0
        for a in range(5):
            for b in range(5):
                x |= 1 << pos(a, b, z)
        v_basis.append(x)
    assert rank(v_basis) == 64
    assert all(in_v(psi(x)) for x in v_basis)
    assert all(psi(psi(x)) == x for x in v_basis)

    image = [linear(x) for x in v_basis]
    assert rank(image) == 64

    # Express V in its pivot basis. Each image vector is reduced together with
    # the V-coordinate combination that produced it. The number of images that
    # do not reduce to zero is dim((L(V)+V)/V), hence intersection rank is
    # 64 minus that number.
    piv = {}
    for j, row in enumerate(v_basis):
        combo = 1 << j
        while row:
            p = row.bit_length() - 1
            if p in piv:
                row ^= piv[p][0]
                combo ^= piv[p][1]
            else:
                piv[p] = (row, combo)
                break
    independent_mod_v = 0
    intersection_equations = []
    for j, row in enumerate(image):
        combo = 1 << j
        while row:
            p = row.bit_length() - 1
            if p in piv:
                row ^= piv[p][0]
                combo ^= piv[p][1]
            else:
                piv[p] = (row, combo)
                independent_mod_v += 1
                intersection_equations.append(combo)
                break
    inter_dim = 64 - independent_mod_v
    print("dim V =", rank(v_basis))
    print("psi(V)=V =", all(in_v(psi(x)) for x in v_basis))
    print("dim L(V) =", rank(image))
    print("dim((L(V)+V)/V) =", independent_mod_v)
    print("dim(L(V) intersect V) =", inter_dim)

    # Find a vector in the intersection by solving the 63 linear equations
    # against the 64 V coordinates. Gaussian elimination on those equations
    # leaves one free V-coordinate, from which the unique nonzero vector is
    # reconstructed.
    row_basis = {}
    for row in intersection_equations:
        while row:
            p = row.bit_length() - 1
            if p in row_basis:
                row ^= row_basis[p]
            else:
                row_basis[p] = row
                break
    assert len(row_basis) == 63
    free = next(z for z in range(64) if z not in row_basis)
    vcomb = 1 << free
    for p in sorted(row_basis):
        if (row_basis[p] & vcomb).bit_count() & 1:
            vcomb |= 1 << p
    assert all((row & vcomb).bit_count() & 1 == 0 for row in intersection_equations)
    xint = 0
    for z in range(64):
        if (vcomb >> z) & 1:
            for a in range(5):
                for b in range(5):
                    xint ^= 1 << pos(a, b, z)
    assert in_v(xint)
    assert in_v(linear(xint))
    print("nonzero intersection V-word =", f"{v_word(xint):016x}")
    print("word period-1 =", v_word(xint) == (1 << 64) - 1)
    print("integer hex =", f"{xint:x}")
    sum_basis = v_basis + image
    print("dim(V+LV) =", rank(sum_basis))
    for i, rc in enumerate(RC):
        lrc = linear(rc)
        print(
            "round",
            i,
            "L(RC) in V+LV",
            rank(sum_basis + [lrc]) == rank(sum_basis),
        )


if __name__ == "__main__":
    main()
