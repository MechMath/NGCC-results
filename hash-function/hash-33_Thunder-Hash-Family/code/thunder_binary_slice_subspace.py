#!/usr/bin/env python3
"""Check the 320-dimensional 0/31 S-box slice subspace under Thunder-p."""

from thunder_fixedspace import RC, linear, psi, pos


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


def intersection_dim(a, b):
    assert rank(a) == len(a)
    assert rank(b) == len(b)
    piv = {}
    for j, row in enumerate(a):
        combo = 1 << j
        while row:
            p = row.bit_length() - 1
            if p in piv:
                row ^= piv[p][0]
                combo ^= piv[p][1]
            else:
                piv[p] = (row, combo)
                break
    independent_mod_a = 0
    for row in b:
        while row:
            p = row.bit_length() - 1
            if p in piv:
                row ^= piv[p][0]
            else:
                independent_mod_a += 1
                piv[p] = (row, 0)
                break
    return len(b) - independent_mod_a, rank(a + b)


def main():
    u_basis = []
    for x in range(5):
        for z in range(64):
            state = 0
            for y in range(5):
                state |= 1 << pos(x, y, z)
            u_basis.append(state)
    assert rank(u_basis) == 320
    assert all(span_membership_for_basis(psi(x), u_basis) for x in u_basis)
    image = [linear(x) for x in u_basis]
    inter, union_rank = intersection_dim(u_basis, image)
    print("dim U", rank(u_basis))
    print("dim L(U)", rank(image))
    print("dim(U intersect L(U))", inter)
    print("dim(U+L(U))", union_rank)
    for i, rc in enumerate(RC):
        # R_i(U) intersects U iff L(RC_i) lies in U+L(U), because psi(U)=U.
        print("round", i, "L(RC) in U+LU", rank(u_basis + image + [linear(rc)]) == union_rank)


def span_membership_for_basis(v, basis):
    # Membership is tested by reducing once against the pivot basis.
    piv = {}
    for row in basis:
        while row:
            p = row.bit_length() - 1
            if p in piv:
                row ^= piv[p]
            else:
                piv[p] = row
                break
    while v:
        p = v.bit_length() - 1
        if p not in piv:
            return False
        v ^= piv[p]
    return True


if __name__ == "__main__":
    main()
