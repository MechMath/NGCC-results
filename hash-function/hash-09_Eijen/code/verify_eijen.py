#!/usr/bin/env python3
"""Independent executable restatement of the Eijen permutation and Sponge-F mode."""

MASK = (1 << 64) - 1

SIGMA = [
    22, 0, 29, 19, 26, 4, 1, 23, 30, 8, 5, 27, 2, 12, 9, 31,
    6, 16, 13, 3, 10, 20, 17, 7, 14, 24, 21, 11, 18, 28, 25, 15,
]

ROUND_CONSTANTS = [
    (0x243F6A8885A308D3, 0x13198A2E03707344),
    (0xA4093822299F31D0, 0x082EFA98EC4E6C89),
    (0x452821E638D01377, 0xBE5466CF34E90C6C),
    (0xC0AC29B7C97C50DD, 0x3F84D5B5B5470917),
    (0x9216D5D98979FB1B, 0xD1310BA698DFB5AC),
    (0x2FFD72DBD01ADFB7, 0xB8E1AFED6A267E96),
    (0xBA7C9045F12C7F99, 0x24A19947B3916CF7),
    (0x0801F2E2858EFC16, 0x636920D871574E69),
    (0xA458FEA3F4933D7E, 0x0D95748F728EB658),
    (0x718BCD5882154AEE, 0x7B54A41DC25A59B5),
    (0x9C30D5392AF26013, 0xC5D1B023286085F0),
    (0xCA417918B8DB38EF, 0x8E79DCB0603A180E),
    (0x6C9E0E8BB01E8A3E, 0xD71577C1BD314B27),
    (0x78AF2FDA55605C60, 0xE65525F3AA55AB94),
    (0x5748986263E81440, 0x55CA396A2AAB10B6),
    (0xB4CC5C341141E8CE, 0xA15486AF7C72E993),
]

P0 = (36, 54, 45, 44, 18, 9)
P1 = (56, 46, 54, 34, 19, 51)


def rotl(x: int, n: int) -> int:
    assert 0 <= n < 64
    return ((x << n) | (x >> (64 - n))) & MASK


def mixquad(words: list[int], params: tuple[int, ...], c: int) -> None:
    pi0, pi1, pi2, pi3, pi4, pi5 = params
    a, b, cc, d = words
    a = (a + b) & MASK
    d = rotl(d ^ a, pi0)
    a = rotl(a, pi4) ^ c
    cc = (cc + d) & MASK
    b = rotl(b ^ cc, pi1)
    cc = rotl(cc, pi5)
    a = (a + b) & MASK
    d = rotl(d ^ a, pi2)
    cc = (cc + d) & MASK
    b = rotl(b ^ cc, pi3)
    words[:] = [a, b, cc, d]


def inv_mixquad(words: list[int], params: tuple[int, ...], c: int) -> None:
    pi0, pi1, pi2, pi3, pi4, pi5 = params
    a, b, cc, d = words
    b = rotl(b, 64 - pi3) ^ cc
    cc = (cc - d) & MASK
    d = rotl(d, 64 - pi2) ^ a
    a = (a - b) & MASK
    cc = rotl(cc, 64 - pi5)
    b = rotl(b, 64 - pi1) ^ cc
    cc = (cc - d) & MASK
    a = rotl(a ^ c, 64 - pi4)
    d = rotl(d, 64 - pi0) ^ a
    a = (a - b) & MASK
    words[:] = [a, b, cc, d]


def mixquad_layer(state: list[int], round_index: int) -> list[int]:
    out = state[:]
    for j in range(8):
        words = state[4 * j : 4 * j + 4]
        mixquad(words, P0 if j < 4 else P1, ROUND_CONSTANTS[round_index][j // 4])
        out[4 * j : 4 * j + 4] = words
    return out


def inv_mixquad_layer(state: list[int], round_index: int) -> list[int]:
    out = state[:]
    for j in range(8):
        words = state[4 * j : 4 * j + 4]
        inv_mixquad(words, P0 if j < 4 else P1, ROUND_CONSTANTS[round_index][j // 4])
        out[4 * j : 4 * j + 4] = words
    return out


def posperm(state: list[int]) -> list[int]:
    return [state[SIGMA[i]] for i in range(32)]


def inv_posperm(state: list[int]) -> list[int]:
    out = [0] * 32
    for i, source in enumerate(SIGMA):
        out[source] = state[i]
    return out


def amix4(state: list[int]) -> list[int]:
    out = state[:]
    for j in range(8):
        u0, u1, u2, u3 = state[4 * j : 4 * j + 4]
        out[4 * j : 4 * j + 4] = [
            u1 ^ u2 ^ u3,
            u0 ^ u2 ^ u3,
            u0 ^ u1 ^ u3,
            u0 ^ u1 ^ u2,
        ]
    return out


def permutation(state: list[int]) -> list[int]:
    assert len(state) == 32
    cur = state[:]
    for r in range(16):
        cur = mixquad_layer(cur, r)
        cur = posperm(cur)
        cur = amix4(cur)
        cur = posperm(cur)
    return cur


def eijen_published_block(message_prefix: bytes, rate_words: int) -> tuple[list[int], list[int]]:
    """Use the submitted block equation S=lane(M)||1_c and test-vector encoding."""
    state = [0] * 32
    lane = message_prefix + b"\0" * (64 * rate_words - len(message_prefix))
    for i in range(rate_words):
        state[i] = int.from_bytes(lane[8 * i : 8 * i + 8], "little")
    state[31] = 1 << 63
    out = permutation(state)
    x = [(out[i] ^ state[i]) & MASK for i in range(32)]
    return state, x


def main() -> None:
    expected = [
        "C832C8FBDAB9CBB6",
        "0824D2E879ACE7CE",
        "B1F902E54FCAA9DC",
        "81E09F3C71B04F86",
    ]
    s1, x1 = eijen_published_block(b"abc\x01", 27)
    digest1 = [w.to_bytes(8, "little").hex().upper() for w in x1[28:32]]
    print("initial word 0:     ", f"{s1[0]:016X}")
    print("initial capacity 1c:", f"{s1[31]:016X}")
    print("abc digest:         ", " ".join(digest1))
    print("vector matches:     ", digest1 == expected)

    # AMix4 kills the kernel vector (delta,delta,delta,delta) in every
    # column.  Put that vector in output column zero after the first
    # PosPerm.  Pulling it backward through PosPerm and MixQuad gives two
    # distinct first-round inputs whose full 16-round outputs are equal.
    u = [0] * 32
    u2 = u[:]
    delta = 0x0123456789ABCDEF
    for i in range(4):
        u2[i] = delta
    z = inv_posperm(u)
    z2 = inv_posperm(u2)
    a = inv_mixquad_layer(z, 0)
    a2 = inv_mixquad_layer(z2, 0)
    first_output = amix4(posperm(mixquad_layer(a, 0)))
    first_output2 = amix4(posperm(mixquad_layer(a2, 0)))
    print("actual Pi collision:", a != a2 and permutation(a) == permutation(a2))
    print("first round equal:  ", first_output == first_output2)
    print("A:                  ", " ".join(f"{w:016X}" for w in a))
    print("A':                 ", " ".join(f"{w:016X}" for w in a2))


if __name__ == "__main__":
    main()
