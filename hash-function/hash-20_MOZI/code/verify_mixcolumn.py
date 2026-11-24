#!/usr/bin/env python3
"""Independent checks for the MOZI p.8-p.9 MixColumn definitions.

All vectors are ordered tuples (x0, x1, x2, x3), exactly as printed.  The
script does not identify x0 with either the numeric MSB or LSB; both numeric
display conventions induce the same tuple equality question.
"""

from itertools import permutations, product


NIBBLES = tuple(product((0, 1), repeat=4))
ALL_INPUTS = tuple(product(NIBBLES, repeat=4))
ZERO = (0, 0, 0, 0)


def xor(*values):
    return tuple(sum(v[i] for v in values) % 2 for i in range(4))


def alpha(x):
    """The p.8 displayed matrix times (x0,x1,x2,x3)^T."""
    return (x[1], x[2], x[3], x[0] ^ x[1])


def mul(x):
    """Algorithm 4, line 2, interpreted with simultaneous right-hand sides."""
    return (x[3], x[0] ^ x[3], x[1], x[2])


def formal(matrix_element):
    """The four p.8 RHS formulas with alpha replaced by matrix_element."""

    def map4(v):
        a, b, c, d = v
        aa = matrix_element(matrix_element(a))
        bb = matrix_element(matrix_element(b))
        cc = matrix_element(matrix_element(c))
        dd = matrix_element(matrix_element(d))
        return (
            xor(aa, bb, matrix_element(b), c, d),
            xor(a, matrix_element(b), b, cc, c, dd, matrix_element(d), d),
            xor(a, b, cc, dd, matrix_element(d)),
            xor(aa, a, bb, matrix_element(b), b, c, matrix_element(d), d),
        )

    return map4


def algorithm(v):
    s0, s1, s2, s3 = v
    s2 = xor(s2, s3)
    s0 = xor(s0, s1)
    s1 = mul(s1)
    s3 = mul(s3)
    s1 = xor(s1, s2)
    s3 = xor(s3, s0)
    s0 = mul(s0)
    s2 = mul(s2)
    s0 = mul(s0)
    s2 = mul(s2)
    s2 = xor(s2, s3)
    s0 = xor(s0, s1)
    s1 = xor(s1, s2)
    s3 = xor(s3, s0)
    return s0, s1, s2, s3


def bit_swap_1_3(x):
    return (x[0], x[3], x[2], x[1])


def field_multiply(left, right):
    """GF(16) product for tuples (alpha^3,alpha^2,alpha,1)."""
    result = ZERO
    term = right
    for coefficient in reversed(left):
        if coefficient:
            result = xor(result, term)
        term = alpha(term)
    return result


def formal_from_displayed_matrix(v):
    """Multiply the displayed GF(16) coefficient matrix by v."""
    one = (0, 0, 0, 1)
    a = (0, 0, 1, 0)
    a2 = alpha(a)
    matrix = (
        (a2, xor(a2, a), one, one),
        (one, xor(a, one), xor(a2, one), xor(a2, a, one)),
        (one, one, a2, xor(a2, a)),
        (xor(a2, one), xor(a2, a, one), one, xor(a, one)),
    )
    output = []
    for row in matrix:
        value = ZERO
        for coefficient, nibble in zip(row, v):
            value = xor(value, field_multiply(coefficient, nibble))
        output.append(value)
    return tuple(output)


def permute_nibbles(v, p):
    return tuple(v[p[i]] for i in range(4))


def permute_bits(v, p):
    return tuple(bit_swap_1_3(x) if p == (0, 3, 2, 1) else
                 tuple(x[p[i]] for i in range(4)) for x in v)


def bits(n):
    return tuple((n >> (3 - i)) & 1 for i in range(4))


def bits_string(v):
    return "|".join("".join(str(bit) for bit in nibble) for nibble in v)


def main():
    f = formal(alpha)
    assert all(formal_from_displayed_matrix(v) == f(v) for v in ALL_INPUTS)
    assert all(algorithm(v) == formal(mul)(v) for v in ALL_INPUTS)

    different = []
    p_conjugation_failures = []
    for values in product(range(16), repeat=4):
        v = tuple(bits(value) for value in values)
        if f(v) != algorithm(v):
            different.append(values)
        expected = tuple(bit_swap_1_3(x) for x in f(
            tuple(bit_swap_1_3(x) for x in v)))
        if algorithm(v) != expected:
            p_conjugation_failures.append(values)

    assert different
    assert not p_conjugation_failures

    witness = (0, 0, 0, 1)
    witness_tuple = tuple(bits(value) for value in witness)
    assert formal(alpha)(witness_tuple) == tuple(map(bits, (1, 7, 6, 3)))
    assert algorithm(witness_tuple) == tuple(map(bits, (1, 11, 10, 13)))

    # Without a within-nibble bit permutation, no nibble-index permutation
    # makes the maps equal.
    successful_nibble_perms = []
    for p in permutations(range(4)):
        if all(algorithm(v) == permute_nibbles(f(permute_nibbles(v, p)), p)
               for v in ALL_INPUTS):
            successful_nibble_perms.append(p)
    assert successful_nibble_perms == []

    # A complete independent search over all pairs of within-nibble bit
    # permutations: only (x1,x3) works (with either of the nibble swaps).
    bit_perms = list(permutations(range(4)))
    successful_bit_pairs = []
    basis = []
    for index in range(16):
        v = [ZERO] * 4
        nibble = [0] * 4
        nibble[index % 4] = 1
        v[index // 4] = tuple(nibble)
        basis.append(tuple(v))
    for p in bit_perms:
        for q in bit_perms:
            if all(
                algorithm(v) == permute_bits(f(permute_bits(v, p)), q)
                for v in basis
            ):
                successful_bit_pairs.append((p, q))
    assert successful_bit_pairs == [((0, 3, 2, 1), (0, 3, 2, 1))]

    # If simultaneous nibble-coordinate relabellings are also allowed, exactly
    # two remain: the identity and (a,c)(b,d), in both cases with the x1,x3
    # within-nibble swap.
    p = (0, 3, 2, 1)
    combined_successes = []
    for nibble_perm in permutations(range(4)):
        if all(
            algorithm(v) == permute_nibbles(
                permute_bits(f(permute_bits(
                    permute_nibbles(v, nibble_perm), p)), p),
                nibble_perm,
            )
            for v in ALL_INPUTS
        ):
            combined_successes.append(nibble_perm)
    assert combined_successes == [(0, 1, 2, 3), (2, 3, 0, 1)]

    # Complete search over within-nibble and nibble-index relabellings.  It is
    # enough to check a GF(2) basis because all maps are linear.
    full_relabelling_successes = []
    for p_in in bit_perms:
        for p_out in bit_perms:
            for n_in in permutations(range(4)):
                for n_out in permutations(range(4)):
                    if all(
                        algorithm(v) == permute_nibbles(
                            permute_bits(f(permute_bits(
                                permute_nibbles(v, n_in), p_in)), p_out),
                            n_out,
                        )
                        for v in basis
                    ):
                        full_relabelling_successes.append(
                            (p_in, p_out, n_in, n_out)
                        )
    assert full_relabelling_successes == [
        ((0, 3, 2, 1), (0, 3, 2, 1), (0, 1, 2, 3), (0, 1, 2, 3)),
        ((0, 3, 2, 1), (0, 3, 2, 1), (2, 3, 0, 1), (2, 3, 0, 1)),
    ]

    # P is not an S-box symmetry.  Interpret tuple x0x1x2x3 as binary x0 MSB,
    # as p.12 explicitly identifies x0 as the S-box input's MSB.
    sbox = (0, 8, 6, 13, 5, 15, 7, 12, 4, 14, 2, 3, 9, 1, 11, 10)

    def p_num(n):
        x0, x1, x2, x3 = bits(n)
        return (x0 << 3) | (x3 << 2) | (x2 << 1) | x1

    sbox_commutation_failures = [
        n for n in range(16) if sbox[p_num(n)] != p_num(sbox[n])
    ]
    assert sbox_commutation_failures == [1, 2, 3, 4, 6, 7, 8, 9, 11, 12, 13, 14]

    print("Mismatches under literal ordered-tuple convention:", len(different))
    print("Witness inputs (a,b,c,d):", witness)
    print("Formal outputs (0001,0111,0110,0011):", bits_string(f(witness_tuple)))
    print("Algorithm outputs (0001,1011,1010,1101):", bits_string(algorithm(witness_tuple)))
    print("Exact bit conjugacy G = P F P, P(x0,x1,x2,x3)=(x0,x3,x2,x1): PASS")
    print("Nibble permutations preserving equivalence:", successful_nibble_perms)
    print("Within-nibble bit-permutation conjugators:", successful_bit_pairs)
    print("Combined nibble relabellings (with x1<->x3):", combined_successes)
    print("All bit/nibble relabelling conjugators:", full_relabelling_successes)
    print("S-box commutation failures under P:", sbox_commutation_failures)


if __name__ == "__main__":
    main()
