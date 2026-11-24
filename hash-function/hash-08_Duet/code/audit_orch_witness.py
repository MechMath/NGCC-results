#!/usr/bin/env python3
"""Independent semantic audit of the orch Duet API witness.

This implementation differs at the nonlinear layer (Table 1 lookup rather
than the Table 2 circuit) and spells out the XOF schedule directly from
Algorithm 1. It is an API-semantics check only, not security evidence.
"""

import hashlib
from check_duet import M15_ROWS, make_m30

SBOX = [
    0x1A, 0x09, 0x10, 0x17, 0x07, 0x08, 0x15, 0x0E, 0x19, 0x1F, 0x1E, 0x0C,
    0x1B, 0x01, 0x04, 0x0A, 0x05, 0x13, 0x0D, 0x0F, 0x16, 0x1C, 0x06, 0x18,
    0x11, 0x12, 0x14, 0x03, 0x1D, 0x02, 0x00, 0x0B,
]
M15 = [[int(x) for x in line.split()] for line in M15_ROWS.splitlines() if line.strip()]
M30 = make_m30()
MASK = (1 << 64) - 1

SIGMA = {
    384: (3, 0, 5, 1, 4, 2),
    768: (8, 2, 11, 0, 5, 9, 3, 10, 1, 7, 4, 6),
    1088: (9, 2, 15, 0, 6, 12, 4, 16, 1, 10, 7, 14, 3, 11, 5, 13, 8),
}

RC = {
    960: (
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
    ),
    1920: (
        (0xB7E151628AED2A6A, 0x753D0A8F78E537D2),
        (0xBF7158809CF4F3C7, 0xB95BB79D8DCAEC64),
        (0x62E7160F38B4DA56, 0x2C1E9F23B829B5C2),
        (0xA784D9045190CFEF, 0x780BF38737DF8BB3),
        (0x324E7738926CFBE5, 0x00D01334A0D0BD86),
        (0xF4BF8D8D8C31D763, 0x45CBFA73A6160FFE),
        (0xDA06C80ABB1185EB, 0x393C48CBBBCA060F),
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
    ),
}


def rol(x, n):
    n %= 64
    return x if n == 0 else ((x << n) | (x >> (64 - n))) & MASK


def permutation(x, alpha, width):
    m = width // 320
    matrix = M15 if width == 960 else M30
    for gamma in range(12 if width == 960 else 18):
        # SC: each (column, bit-position) is a 5-bit S-box input with x0 MSB.
        for col in range(m):
            for bit in range(64):
                u = 0
                for row in range(5):
                    u = (u << 1) | ((x[5 * col + row] >> bit) & 1)
                s = SBOX[u]
                for row in range(5):
                    mask = 1 << bit
                    x[5 * col + row] = (
                        (x[5 * col + row] & ~mask) |
                        (((s >> (4 - row)) & 1) << bit)
                    )
        # MS, with the state's 5m words in column-major order.
        x = [
            __import__("functools").reduce(
                int.__xor__,
                (x[j] for j in range(5 * m) if matrix[i][j]),
                0,
            )
            for i in range(5 * m)
        ]
        x[0] ^= RC[width][gamma][alpha - 1]
        x = [rol(w, t) ^ rol(w, t + 21) ^ rol(w, t + 43) for t, w in enumerate(x)]
    return x


def packed_words(bits, count):
    return [
        int("".join(str(b) for b in bits[64 * i:64 * (i + 1)]), 2)
        for i in range(count)
    ]


def duet(data, h, nu):
    r, c, width = {512: (384, 576, 960), 768: (1088, 832, 1920),
                   1024: (768, 1152, 1920)}[h]
    bits = [int(b) for byte in data for b in f"{byte:08b}"]
    bits += [1]
    bits += [0] * (-len(bits) % r)
    rw, cw = r // 64, c // 64
    A, B, C = [0] * rw, [0] * rw, [0] * cw
    for off in range(0, len(bits), r):
        M = packed_words(bits[off:off + r], rw)
        y = permutation([u ^ v for u, v in zip(A, M)] + C, 1, width)
        A, C1 = y[:rw], [u ^ v for u, v in zip(y[rw:], C)]
        sigma_M = [M[i] for i in SIGMA[r]]
        y = permutation([u ^ v for u, v in zip(B, sigma_M)] + C1, 2, width)
        B, C = y[:rw], [u ^ v for u, v in zip(y[rw:], C1)]

    chunks = [C[:h // 64]]
    while len(chunks) * h < nu:
        index = len(chunks)  # 1 -> F1, 2 -> F2, 3 -> F1, ...
        if index & 1:
            y = permutation(A + C, 1, width)
            A, C = y[:rw], [u ^ v for u, v in zip(y[rw:], C)]
        else:
            y = permutation(B + C, 2, width)
            B, C = y[:rw], [u ^ v for u, v in zip(y[rw:], C)]
        chunks.append(C[:h // 64])
    stream = b"".join(w.to_bytes(8, "big") for chunk in chunks for w in chunk)
    return stream[:nu // 8]


if __name__ == "__main__":
    for h in (512, 768, 1024):
        out = duet(b"abc", h, 1536)
        print(h, len(out), hashlib.sha256(out).hexdigest(), out.hex())
