#!/usr/bin/env python3
"""Exact checks for LLH's period-three / all-slices-equal affine sector."""

from itertools import product

MASK6 = (1 << 6) - 1
MASK24 = (1 << 24) - 1
A = (0x00, 0x09, 0x12, 0x1B, 0x24, 0x2D, 0x36, 0x3F)
DERANGEMENT = (
    4, 9, 18, 23, 8, 1, 22, 15, 12, 17, 6, 3,
    20, 5, 10, 19, 0, 21, 14, 11, 16, 13, 2, 7,
)
SHIFTS = {
    32: (3, 16, 13, 26, 8, 29, 2, 23, 21, 18, 31, 28,
         10, 15, 4, 9, 7, 20, 17, 30, 12, 1, 6, 27),
    64: (2, 25, 20, 51, 15, 40, 37, 6, 36, 63, 62, 33,
         1, 30, 31, 4, 38, 5, 8, 47, 19, 52, 57, 34),
    96: (2, 11, 28, 53, 19, 34, 57, 88, 52, 73, 6, 43,
         5, 32, 67, 14, 70, 7, 48, 1, 55, 94, 45, 4),
    128: (1, 16, 55, 118, 10, 29, 72, 11, 35, 58, 105, 48,
          76, 103, 26, 101, 5, 36, 91, 42, 78, 113, 44, 127),
}
RC = {
    32: (0xB7E15162, 0x8AED2A6A, 0xBF715880, 0x9CF4F3C7,
         0x62E7160F, 0x38B4DA56, 0xA784D904, 0x5190CFEF,
         0x324E7738, 0x926CFBE5, 0xF4BF8D8D, 0x8C31D763,
         0xDA06C80A, 0xBB1185EB, 0x4F7C7B57, 0x57F59584),
    64: (0xB7E151628AED2A6A, 0xBF7158809CF4F3C7,
         0x62E7160F38B4DA56, 0xA784D9045190CFEF,
         0x324E7738926CFBE5, 0xF4BF8D8D8C31D763,
         0xDA06C80ABB1185EB, 0x4F7C7B5757F59584,
         0x90CFD47D7C19BB42, 0x158D9554F7B46BCE,
         0xD55C4D79FD5F24D6, 0x613C31C3839A2DDF,
         0x8A9A276BCFBFA1C8, 0x77C56284DAB79CD4,
         0xC2B3293D20E9E5EA, 0xF02AC60ACC93ED87,
         0x4422A52ECB238FEE, 0xE5AB6ADD835FD1A0,
         0x753D0A8F78E537D2, 0xB95BB79D8DCAEC64,
         0x2C1E9F23B829B5C2, 0x780BF38737DF8BB3,
         0x00D01334A0D0BD86, 0x45CBFA73A6160FFE),
    96: (0xB7E151628AED2A6ABF715880,
         0x9CF4F3C762E7160F38B4DA56,
         0xA784D9045190CFEF324E7738,
         0x926CFBE5F4BF8D8D8C31D763,
         0xDA06C80ABB1185EB4F7C7B57,
         0x57F5958490CFD47D7C19BB42,
         0x158D9554F7B46BCED55C4D79,
         0xFD5F24D6613C31C3839A2DDF,
         0x8A9A276BCFBFA1C877C56284,
         0xDAB79CD4C2B3293D20E9E5EA,
         0xF02AC60ACC93ED874422A52E,
         0xCB238FEEE5AB6ADD835FD1A0,
         0x753D0A8F78E537D2B95BB79D,
         0x8DCAEC642C1E9F23B829B5C2,
         0x780BF38737DF8BB300D01334,
         0xA0D0BD8645CBFA73A6160FFE,
         0x393C48CBBBCA060F0FF8EC6D,
         0x31BEB5CCEED7F2F0BB088017,
         0x163BC60DF45A0ECB1BCD289B,
         0x06CBBFEA21AD08E1847F3F73,
         0x78D56CED94640D6EF0D3D37B,
         0xE67008E186D1BF275B9B241D,
         0xEB64749A47DFDFB96632C3EB,
         0x061B6472BBF84C26144E49C2,
         0xD04C324EF10DE513D3F5114B,
         0x8B5D374D93CB8879C7D52FFD,
         0x72BA0AAE7277DA7BA1B4AF14,
         0x88D8E836AF14865E6C37AB68,
         0x76FE690B571121382AF341AF,
         0xE94F77BCF06C83B8FF5675F0,
         0x979074AD9A787BC5B9BD4B0C,
         0x5937D3EDE4C3A79396215EDA),
    128: (0xB7E151628AED2A6ABF7158809CF4F3C7,
          0x62E7160F38B4DA56A784D9045190CFEF,
          0x324E7738926CFBE5F4BF8D8D8C31D763,
          0xDA06C80ABB1185EB4F7C7B5757F59584,
          0x90CFD47D7C19BB42158D9554F7B46BCE,
          0xD55C4D79FD5F24D6613C31C3839A2DDF,
          0x8A9A276BCFBFA1C877C56284DAB79CD4,
          0xC2B3293D20E9E5EAF02AC60ACC93ED87,
          0x4422A52ECB238FEEE5AB6ADD835FD1A0,
          0x753D0A8F78E537D2B95BB79D8DCAEC64,
          0x2C1E9F23B829B5C2780BF38737DF8BB3,
          0x00D01334A0D0BD8645CBFA73A6160FFE,
          0x393C48CBBBCA060F0FF8EC6D31BEB5CC,
          0xEED7F2F0BB088017163BC60DF45A0ECB,
          0x1BCD289B06CBBFEA21AD08E1847F3F73,
          0x78D56CED94640D6EF0D3D37BE67008E1,
          0x86D1BF275B9B241DEB64749A47DFDFB9,
          0x6632C3EB061B6472BBF84C26144E49C2,
          0xD04C324EF10DE513D3F5114B8B5D374D,
          0x93CB8879C7D52FFD72BA0AAE7277DA7B,
          0xA1B4AF1488D8E836AF14865E6C37AB68,
          0x76FE690B571121382AF341AFE94F77BC,
          0xF06C83B8FF5675F0979074AD9A787BC5,
          0xB9BD4B0C5937D3EDE4C3A79396215EDA,
          0xB1F57D0B5A7DB461DD8F3C75540D0012,
          0x1FD56E95F8C731E9C4D7221BBED0C62B,
          0xB5A87804B679A0CAA41D802A4604C311,
          0xB71DE3E5C6B400E024A6668CCF2E2DE8,
          0x6876E4F5C50000F0A93B3AA7E6342B30,
          0x2A0A47373B25F73E3B26D569FE2291AD,
          0x36D6A147D1060B871A2801F978376408,
          0x2FF592D9140DB1E9399DF4B0E14CA8E8,
          0x8EE9110B2BD4FA98EED150CA6DD89322,
          0x45EF7592C703F532CE3A30CD31C070EB,
          0x36B4195FF33FB1C66C7D70F93918107C,
          0xE2051FED33F6D1DE9491C7DEA6A5A442,
          0xE154C8BB6D8D0362803BC248D414478C,
          0x2AFB07FFE78E89B9FECA7E3060C08F0D,
          0x61F8E36801DF66D1D8F9392E52CAEF06,
          0x53199479DF2BE64BBAAB008CA8A06FDA),
}


def ror6(x: int, r: int) -> int:
    return ((x >> r) | (x << (6 - r))) & MASK6


def s6(x: int) -> int:
    return x ^ ror6(x, 2) ^ (ror6(x, 1) & ror6(x, 3)) ^ 0x1B


def columns(x: int) -> tuple[int, ...]:
    return tuple(
        sum(((x >> (4 * r + c)) & 1) << r for r in range(6))
        for c in range(4)
    )


def from_columns(xs: tuple[int, ...]) -> int:
    return sum(
        ((x >> r) & 1) << (4 * r + c)
        for c, x in enumerate(xs)
        for r in range(6)
    )


def s24(x: int) -> int:
    z = from_columns(tuple(s6(v) for v in columns(x)))
    # A label moves from its left-table position to its right-table position:
    # output[i] = input[position of label i].
    d = sum(((z >> DERANGEMENT.index(i)) & 1) << i for i in range(24))
    y = 0
    for r in range(6):
        row = (d >> (4 * r)) & 0xF
        for c in range(4):
            bit = sum((row >> j) & 1 for j in range(4) if j != c) & 1
            y |= bit << (4 * r + c)
    return y


def subcolumn(state: int, w: int) -> int:
    out = 0
    for j in range(w):
        out |= s24((state >> (24 * j)) & MASK24) << (24 * j)
    return out


def shiftrows(state: int, w: int) -> int:
    out = 0
    mask = (1 << w) - 1
    for i, sigma in enumerate(SHIFTS[w]):
        word = (state >> (w * i)) & mask
        word = ((word << sigma) | (word >> (w - sigma))) & mask
        out |= word << (w * i)
    return out


def roundfun(state: int, w: int, t: int) -> int:
    state = shiftrows(subcolumn(state, w), w)
    return state ^ (RC[w][t] << (23 * w))


def period3_vectors() -> tuple[int, ...]:
    out = []
    for a, b, c in product(range(2), repeat=3):
        x = sum(bit << i for i, bit in enumerate((a, b, c) * 8))
        out.append(x)
    return tuple(sorted(out))


def all_slices_equal_state(u: int, w: int) -> int:
    return sum(u << (24 * j) for j in range(w))


def bit_rank(words: tuple[int, ...]) -> int:
    basis = {}
    for x in words:
        while x:
            p = x.bit_length() - 1
            if p in basis:
                x ^= basis[p]
            else:
                basis[p] = x
                break
    return len(basis)


def affine_hull(words: tuple[int, ...]) -> tuple[int, int]:
    origin = words[0]
    return origin, bit_rank(tuple(x ^ origin for x in words))


def is_affine(words: tuple[int, ...]) -> bool:
    origin, rank = affine_hull(words)
    return len(set(words)) == (1 << rank)


def main() -> None:
    P3 = period3_vectors()
    print("period-three collision counts:", [
        sum(P3[i] ^ P3[j] == 0x09 for j in range(8)) for i in range(8)
    ][:1])

    a4 = tuple(from_columns(xs) for xs in product(A, repeat=4))
    b = tuple(sorted({s24(x) for x in a4}))
    print("|A^4|", len(a4), "|S24(A^4)|", len(b))
    print("S24(A^4) affine?", is_affine(b), "rank", affine_hull(b)[1])

    b2 = tuple(sorted({s24(x) for x in b}))
    print("|S24^2(A^4)|", len(b2))
    print("S24^2(A^4) affine?", is_affine(b2), "rank", affine_hull(b2)[1])

    for w in (32, 64, 96, 128):
        E = tuple(all_slices_equal_state(u, w) for u in a4)
        first = tuple(roundfun(x, w, 0) for x in E)
        E_set = set(E)
        print(f"w={w}: |Round_0(E)|={len(set(first))}, "
              f"subset E={all(x in E_set for x in first)}")
    z8 = all_slices_equal_state(0, 32)
    y1 = roundfun(z8, 32, 0)
    y2 = roundfun(y1, 32, 1)
    print("w=32 zero orbit after 1:", hex(y1))
    print("w=32 zero orbit after 2:", hex(y2))


if __name__ == "__main__":
    main()
