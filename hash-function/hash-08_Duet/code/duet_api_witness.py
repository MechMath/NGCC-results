#!/usr/bin/env python3
"""Reference-semantics witness for the Duet API length ambiguity.

This is an independent transcription of the pinned Duet specification.  It is
used only to compare the distinct algorithm objects Duet_h(M, nu) for one
message; no security claim rests on the implementation.
"""

from __future__ import annotations

MASK64 = (1 << 64) - 1

SBOX = (
    0x1A, 0x09, 0x10, 0x17, 0x07, 0x08, 0x15, 0x0E,
    0x19, 0x1F, 0x1E, 0x0C, 0x1B, 0x01, 0x04, 0x0A,
    0x05, 0x13, 0x0D, 0x0F, 0x16, 0x1C, 0x06, 0x18,
    0x11, 0x12, 0x14, 0x03, 0x1D, 0x02, 0x00, 0x0B,
)

M15_ROWS = (
    "100111011000010",
    "010011101100001",
    "101001110110000",
    "010100111011000",
    "001010011101100",
    "000101001110110",
    "000010100111011",
    "100001010011101",
    "110000101001110",
    "011000010100111",
    "101100001010011",
    "110110000101001",
    "111011000010100",
    "011101100001010",
    "001110110000101",
)
# PDF matrix columns are written left to right.  Python bit j is the j-th
# column, so reverse each printed row before parsing it as a low-bit integer.
M15 = tuple(int(row[::-1], 2) for row in M15_ROWS)
M30_FIRST = (
    1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1,
    1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0,
)
M30 = tuple(
    sum(M30_FIRST[(j - i) % 30] << j for j in range(30))
    for i in range(30)
)

SIGMA = {
    384: (3, 0, 5, 1, 4, 2),
    1088: (9, 2, 15, 0, 6, 12, 4, 16, 1, 10, 7, 14, 3, 11, 5, 13, 8),
    768: (8, 2, 11, 0, 5, 9, 3, 10, 1, 7, 4, 6),
}

RC960 = (
    (0x243F6A8885A308D3, 0xBA7C9045F12C7F99),
    (0x13198A2E03707344, 0x24A19947B3916CF7),
    (0xA4093822299F31D0, 0x0801F2E2858EFC16),
    (0x082EFA98EC4E6C89, 0x636920D871574E69),
    (0x452821E638D01377, 0xA458FEA3F4933D7E),
    (0xBE5466CF34E90C6C, 0x0D95748F728EB658),
    (0xC0AC29B7C97C50DD, 0x718BCD5882154AEE),
    (0x3F84D5B5B5470917, 0x7B54A41DC25A59B5),
    (0x9216D5D98979FB1B, 0x9C30D5392AF26013),
    (0xD1310BA698DFB5AC, 0xC5D1B023286085F0),
    (0x2FFD72DBD01ADFB7, 0xCA417918B8DB38EF),
    (0xB8E1AFED6A267E96, 0x8E79DCB0603A180E),
)

RC1920 = (
    (0xB7E151628AED2A6A, 0x753D0A8F78E537D2),
    (0xBF7158809CF4F3C7, 0xB95BB79D8DCAEC64),
    (0x62E7160F38B4DA56, 0x2C1E9F23B829B5C2),
    (0xA784D9045190CFEF, 0x780BF38737DF8BB3),
    (0x324E7738926CFBE5, 0x00D01334A0D0BD86),
    (0xF4BF8D8D8C31D763, 0x45CBFA73A6160FFE),
    (0xDA06C80ABB1185EB, 0x393C48CB_BBCA060F),
    (0x4F7C7B5757F59584, 0x0FF8EC6D31BEB5CC),
    (0x90CFD47D7C19BB42, 0xEED7F2F0BB088017),
    (0x158D9554F7B46BCE, 0x163BC60DF45A0ECB),
    (0xD55C4D79FD5F24D6, 0x1BCD289B06CBBFEA),
    (0x613C31C3839A2DDF, 0x21AD08E1847F3F73),
    (0x8A9A276BCFBFA1C8, 0x78D56CED94640D6E),
    (0x77C56284DAB79CD4, 0xF0D3D37BE67008E1),
    (0xC2B3293D20E9E5EA, 0x86D1BF275B9B241D),
    (0xF02AC60ACC93ED87, 0xEB64749A47DFDFB9),
    (0x4422A52ECB238FEE, 0x6632C3EB061B6472),
    (0xE5AB6ADD835FD1A0, 0xBBF84C26144E49C2),
)


def rol(x: int, r: int) -> int:
    r %= 64
    if r == 0:
        return x
    return ((x << r) | (x >> (64 - r))) & MASK64


def sbox_bits(u: int) -> int:
    x = [(u >> (4 - i)) & 1 for i in range(5)]
    t = [0] * 52
    t[0] = x[3] & x[4]
    t[1] = x[2] & x[4]
    t[2] = x[2] & x[3]
    t[3] = x[1] & x[4]
    t[4] = x[1] & x[2]
    t[5] = x[0] & x[1]
    t[6] = x[4] ^ x[2]
    t[7] = x[0] ^ t[0]
    t[8] = t[1] ^ t[2]
    t[9] = t[3] ^ t[4]
    t[10] = t[5] ^ t[6]
    t[11] = t[7] ^ t[8]
    t[12] = t[9] ^ t[10]
    t[13] = t[11] ^ t[12]
    t[14] = t[13] ^ 1
    t[15] = x[1] & x[3]
    t[16] = x[0] & x[2]
    t[17] = x[3] ^ x[2]
    t[18] = x[0] ^ t[1]
    t[19] = t[2] ^ t[15]
    t[20] = t[4] ^ t[16]
    t[21] = t[17] ^ t[18]
    t[22] = t[19] ^ t[20]
    t[23] = t[21] ^ t[22]
    t[24] = t[23] ^ 1
    t[25] = x[0] & x[4]
    t[26] = x[2] ^ x[0]
    t[27] = t[0] ^ t[1]
    t[28] = t[3] ^ t[15]
    t[29] = t[4] ^ t[25]
    t[30] = t[16] ^ t[5]
    t[31] = t[26] ^ t[27]
    t[32] = t[28] ^ t[29]
    t[33] = t[30] ^ t[31]
    t[34] = t[32] ^ t[33]
    t[35] = x[0] & x[3]
    t[36] = x[4] ^ x[3]
    t[37] = x[1] ^ x[0]
    t[38] = t[4] ^ t[35]
    t[39] = t[16] ^ t[5]
    t[40] = t[36] ^ t[37]
    t[41] = t[38] ^ t[39]
    t[42] = t[40] ^ t[41]
    t[43] = t[42] ^ 1
    t[44] = x[4] ^ x[2]
    t[45] = x[1] ^ x[0]
    t[46] = t[3] ^ t[15]
    t[47] = t[4] ^ t[25]
    t[48] = t[5] ^ t[44]
    t[49] = t[45] ^ t[46]
    t[50] = t[47] ^ t[48]
    t[51] = t[49] ^ t[50]
    return sum(bit << (4 - i) for i, bit in enumerate((t[14], t[24], t[34], t[43], t[51])))


def sc(flat: list[int], m: int) -> list[int]:
    out = flat[:]
    for j in range(m):
        for k in range(64):
            u = 0
            for i in range(5):
                u = (u << 1) | ((flat[5 * j + i] >> k) & 1)
            s = sbox_bits(u)
            for i in range(5):
                bit = (s >> (4 - i)) & 1
                out[5 * j + i] = (out[5 * j + i] & ~(1 << k)) | (bit << k)
    return out


def matrix(flat: list[int], rows: tuple[int, ...]) -> list[int]:
    out = []
    for row in rows:
        value = 0
        for j, word in enumerate(flat):
            if (row >> j) & 1:
                value ^= word
        out.append(value)
    return out


def perm(words: list[int], alpha: int, width: int) -> list[int]:
    m = 3 if width == 960 else 6
    x = words[:]
    constants = RC960 if width == 960 else RC1920
    rows = M15 if width == 960 else M30
    for gamma, pair in enumerate(constants):
        x = sc(x, m)
        x = matrix(x, rows)
        x[0] ^= pair[alpha - 1]
        x = [rol(x[t], t) ^ rol(x[t], t + 21) ^ rol(x[t], t + 43) for t in range(5 * m)]
    return x


def bits_of(data: bytes) -> list[int]:
    return [(byte >> (7 - i)) & 1 for byte in data for i in range(8)]


def words_of(bits: list[int], count: int) -> list[int]:
    values = []
    for start in range(0, count * 64, 64):
        value = 0
        for bit in bits[start:start + 64]:
            value = (value << 1) | bit
        values.append(value)
    return values


def duet(data: bytes, h: int, nu: int) -> bytes:
    params = {
        512: (384, 576, 960, 1),
        768: (1088, 832, 1920, 2),
        1024: (768, 1152, 1920, 1),
    }
    r, c, width, _ = params[h]
    padded = bits_of(data) + [1]
    padded += [0] * ((-len(padded)) % r)
    rw, cw = r // 64, c // 64
    a, b, cap = [0] * rw, [0] * rw, [0] * cw
    for start in range(0, len(padded), r):
        block = words_of(padded[start:start + r], rw)
        a_in = [x ^ y for x, y in zip(a, block)]
        sigma = SIGMA[r]
        sigma_block = [block[i] for i in sigma]
        b_in = [x ^ y for x, y in zip(b, sigma_block)]
        out = perm(a_in + cap, 1, width)
        a = out[:rw]
        cap1 = [x ^ y for x, y in zip(out[rw:], cap)]
        out = perm(b_in + cap1, 2, width)
        b = out[:rw]
        cap = [x ^ y for x, y in zip(out[rw:], cap1)]
    chunks = []
    chunks.append(cap[:h // 64])
    have = h
    toggle = 1
    while have < nu:
        if toggle == 1:
            out = perm(a + cap, 1, width)
            a = out[:rw]
            cap = [x ^ y for x, y in zip(out[rw:], cap)]
        else:
            out = perm(b + cap, 2, width)
            b = out[:rw]
            cap = [x ^ y for x, y in zip(out[rw:], cap)]
        chunks.append(cap[:h // 64])
        have += h
        toggle ^= 3
    out = b"".join(word.to_bytes(8, "big") for word in sum(chunks, []))
    return out[:nu // 8]


def main() -> None:
    message = b"abc"
    for h in (512, 768, 1024):
        digest = duet(message, h, 1536)
        print(f"h={h} nu=1536 sha256={__import__('hashlib').sha256(digest).hexdigest()}")
        print(digest.hex())


if __name__ == "__main__":
    main()
