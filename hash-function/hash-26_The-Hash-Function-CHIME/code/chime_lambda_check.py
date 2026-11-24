#!/usr/bin/env python3
"""Exact checks for the printed CHIME lambda map.

Array coordinates are big-endian: index 0 is the leftmost/high bit of a
256-bit array.  Both rotations and logical shifts operate independently
on each 64-bit word.  Within a word, numeric left rotation by n maps old
coordinate i to (i-n) mod 64, left shift 7 maps i to i-7 (dropping local
i<7), and right shift 5 maps i to i+5 (dropping local i>58).
"""

NAMES = ("A0", "A1", "B0", "B1", "C0", "C1")
N = 256


def from_support(*supports):
    state = [[0] * N for _ in NAMES]
    for name, support in supports:
        a = NAMES.index(name)
        for i in support:
            state[a][i] = 1
    return state


def xor(a, b):
    return [x ^ y for x, y in zip(a, b)]


def permute_chunks(a, width, order):
    """Permute high-to-low chunks; order[k]=j means output chunk k gets input j."""
    if 256 % width:
        raise ValueError(width)
    count = 256 // width
    if sorted(order) != list(range(count)):
        raise ValueError(order)
    out = [0] * N
    for ok, ik in enumerate(order):
        for t in range(width):
            out[ok * width + t] = a[ik * width + t]
    return out


def p32(a):
    # a1||b1||c1||d1||a0||b0||c0||d0
    # -> d1||a1||b1||c1||d0||a0||b0||c0
    return permute_chunks(a, 32, (3, 0, 1, 2, 7, 4, 5, 6))


def p32_inv(a):
    return permute_chunks(a, 32, (1, 2, 3, 0, 5, 6, 7, 4))


def p64(a):
    return permute_chunks(a, 64, (1, 2, 3, 0))


def p64_inv(a):
    return permute_chunks(a, 64, (3, 0, 1, 2))


def p64_swap(a):
    return permute_chunks(a, 64, (1, 0, 3, 2))


def p128(a):
    return permute_chunks(a, 128, (1, 0))


def p128_inv(a):
    return p128(a)


def rol_word(a, n):
    out = [0] * N
    for i, bit in enumerate(a):
        if bit:
            out[(i - n) % 64 + 64 * (i // 64)] = 1
    return out


def shl_word(a, n):
    out = [0] * N
    for i, bit in enumerate(a):
        local = i % 64
        base = i - local
        if bit and local >= n:
            out[base + local - n] = 1
    return out


def shr_word(a, n):
    out = [0] * N
    for i, bit in enumerate(a):
        local = i % 64
        base = i - local
        if bit and local + n < 64:
            out[base + local + n] = 1
    return out


def lam(s):
    a0, a1, b0, b1, c0, c1 = [x[:] for x in s]

    b1 = xor(b1, p32(c1))
    b0 = xor(b0, a1)
    c0 = xor(c0, rol_word(a0, 29))
    b1 = xor(b1, rol_word(a1, 31))
    c1 = xor(c1, rol_word(a0, 13))
    c0 = xor(c0, b1)
    a0 = p64(a0)
    c1 = xor(c1, p32(b1))
    a1 = p128(a1)
    a0 = xor(a0, p64_swap(c0))
    a1 = xor(a1, p32(b0))
    b1 = xor(b1, shl_word(a0, 7))
    c1 = xor(c1, shr_word(a1, 5))
    return [a0, a1, b0, b1, c0, c1]


def lam_inv(y):
    ya0, ya1, yb0, yb1, yc0, yc1 = [x[:] for x in y]

    # Reverse the operations in the exact order stated in Section 1.6.1.
    a1_p = xor(ya1, p32(yb0))
    xa1 = p128_inv(a1_p)
    a0_p = xor(ya0, p64_swap(yc0))
    xa0 = p64_inv(a0_p)
    b1_after = xor(yb1, shl_word(ya0, 7))
    xb0 = xor(yb0, xa1)
    xc0 = xor(xor(yc0, b1_after), rol_word(xa0, 29))
    xc1 = xor(
        xor(xor(yc1, shr_word(ya1, 5)), p32(b1_after)),
        rol_word(xa0, 13),
    )
    xb1 = xor(xor(b1_after, rol_word(xa1, 31)), p32(xc1))
    return [xa0, xa1, xb0, xb1, xc0, xc1]


def support(s):
    return {
        name: [i for i, bit in enumerate(s[k]) if bit]
        for k, name in enumerate(NAMES)
        if any(s[k])
    }


def matrix_basis_image(column):
    s = [[0] * N for _ in NAMES]
    a, bit = divmod(column, N)
    s[a][bit] = 1
    y = lam(s)
    result = 0
    for outa, row in enumerate(y):
        for outbit, value in enumerate(row):
            if value:
                result |= 1 << (outa * N + outbit)
    return result


def rank_and_kernel(columns):
    """Incremental RREF.  Rows are output-coordinate masks of input columns."""
    rows = [0] * (len(NAMES) * N)
    for column, image in enumerate(columns):
        v = image
        while v:
            pivot = v.bit_length() - 1
            if rows[pivot]:
                v ^= rows[pivot]
            else:
                rows[pivot] = v
                break
    rank = sum(bool(r) for r in rows)
    return rank, rows


def rank_from_matrix_rows():
    """Second rank representation: output rows, each an input-coordinate mask."""
    rows = [0] * (len(NAMES) * N)
    for i in range(len(rows)):
        s = [[0] * N for _ in NAMES]
        out, bit = divmod(i, N)
        s[out][bit] = 1
        x = lam_inv(s)  # For a linear map, output row = inverse images of basis
        mask = 0
        for a, row in enumerate(x):
            for j, value in enumerate(row):
                if value:
                    mask |= 1 << (a * N + j)
        rows[i] = mask
    rank, _ = rref(rows)
    return rank


def rref(rows):
    rows = rows[:]
    pivots = []
    rr = 0
    for col in range(len(NAMES) * N - 1, -1, -1):
        p = next((k for k in range(rr, len(rows)) if (rows[k] >> col) & 1), None)
        if p is None:
            continue
        rows[rr], rows[p] = rows[p], rows[rr]
        for k in range(len(rows)):
            if k != rr and ((rows[k] >> col) & 1):
                rows[k] ^= rows[rr]
        pivots.append(col)
        rr += 1
    return rr, rows


def main():
    # Inverse certificate over all 1536 standard basis vectors.
    columns = [matrix_basis_image(j) for j in range(len(NAMES) * N)]
    inv_ok = True
    for col in range(len(columns)):
        s = [[0] * N for _ in NAMES]
        a, bit = divmod(col, N)
        s[a][bit] = 1
        inv_ok &= lam_inv(lam(s)) == s

    rank, _ = rank_and_kernel(columns)
    rank_rows = rank_from_matrix_rows()

    d_support = {31 + 4 * j for j in range(8)} | {159 + 4 * j for j in range(8)}
    d = [[1 if i in d_support else 0 for i in range(N)]]
    b1 = [1 if i in {0, 128} else 0 for i in range(N)]
    zero = [0] * N
    K = [zero, d[0], zero, b1, zero, zero]
    image = lam(K)

    print("rotation 31 image of proposed D:")
    print({i: (i - 31) % 64 + 64 * (i // 64) for i in (31 + 4*j for j in range(8))})
    print("rotation 31 image of proposed D (159+4j):")
    print({i: (i - 31) % 64 + 64 * (i // 64) for i in (159 + 4*j for j in range(8))})
    print("inverse_on_standard_basis", inv_ok)
    print("rank_columns", rank, "rank_rows", rank_rows)
    print("kernel_dimension", len(NAMES) * N - rank)
    print("input_K_support", support(K))
    print("lambda_K_support", support(image))
    print("lambda_K_weight", sum(map(sum, image)))

    expected = {
        "A0": [68 + 4*j for j in range(7)] + [196 + 4*j for j in range(7)],
        "A1": (
            [31 + 4*j for j in range(8)]
            + [63 + 4*j for j in range(8)]
            + [159 + 4*j for j in range(8)]
            + [191 + 4*j for j in range(8)]
        ),
        "B0": [31 + 4*j for j in range(8)] + [159 + 4*j for j in range(8)],
        "B1": (
            [4*j for j in range(1, 8)]
            + [65 + 4*j for j in range(6)]
            + [132 + 4*j for j in range(7)]
            + [193 + 4*j for j in range(6)]
        ),
        "C0": [4*j for j in range(1, 8)] + [132 + 4*j for j in range(7)],
        "C1": [72 + 4*j for j in range(7)] + [200 + 4*j for j in range(7)],
    }
    assert inv_ok and rank == rank_rows == 1536
    assert support(image) == expected and sum(map(sum, image)) == 116


if __name__ == "__main__":
    main()
