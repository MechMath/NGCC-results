#!/usr/bin/env python3
"""Independent workspace model for the WChain byte/bit C API witness.

This is not claimed as a crypto_run-backed experiment.  The two implementations
below intentionally use different representations so their agreement checks the
transcription of the PDF round function and message schedule.
"""

MASK = (1 << 64) - 1

# floor(2^16 * frac(pi)) in consecutive 16-bit words.
PI16 = [
    0x243F, 0x6A88, 0x85A3, 0x08D3, 0x1319, 0x8A2E, 0x0370, 0x7344,
    0xA409, 0x3822, 0x299F, 0x31D0, 0x082E, 0xFA98, 0xEC4E, 0x6C89,
    0x4528, 0x21E6, 0x38D0, 0x1377, 0xBE54, 0x66CF, 0x34E9, 0x0C6C,
]

PI = [0, 7, 5, 3, 1, 8, 6, 4, 2]
D = [0, 1, 10, 20, 25, 32, 41, 46, 50]

L_ROWS = [
    [(0, 5), (1, 22), (2, 3), (3, 28), (7, 27)],
    [(1, 39), (2, 59), (3, 45), (4, 3), (8, 9)],
    [(2, 54), (3, 6), (4, 20), (5, 8), (0, 48)],
    [(3, 0), (4, 57), (5, 55), (6, 46), (1, 28)],
    [(4, 61), (5, 38), (6, 0), (7, 44), (2, 52)],
    [(5, 29), (6, 10), (7, 37), (8, 19), (3, 7)],
    [(6, 56), (7, 5), (8, 50), (0, 27), (4, 13)],
    [(7, 40), (8, 10), (0, 11), (1, 54), (5, 14)],
    [(8, 3), (0, 38), (1, 36), (2, 17), (6, 13)],
]

DELTA = [11, 21, 19, 21, 43, 5, 3, 10, 5]
R_ROWS = [[(j, (a + DELTA[i]) % 64) for j, a in row]
          for i, row in enumerate(L_ROWS)]

CROSS = [(0, 0), (1, 3), (3, 1), (4, 4), (6, 6)]


def rotl(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & MASK if n else x


def chi_words(a):
    return [
        (a[i] ^ (~((~a[(i + 1) % 9]) & a[(i + 2) % 9]))) & MASK
            for i in range(9)]


def linear_words(a, right=False):
    rows = R_ROWS if right else L_ROWS
    out = []
    for row in rows:
        value = 0
        for j, r in row:
            value ^= rotl(a[j], r)
        out.append(value & MASK)
    return out


def permute_words(a):
    c = [0] * 9
    for i, p in enumerate(PI):
        c[p] = a[i]
    return c


def mef_half(a):
    return chi_words([rotl(a[i], D[i]) for i in range(9)])


def xor_state(a, b):
    return [x ^ y for x, y in zip(a, b)]


def pad_bits(message, mu):
    out = list(message) + [1]
    out += [0] * ((-len(out)) % mu)
    assert len(out) % mu == 0
    return out


def bits_to_bytes(bits):
    assert len(bits) % 8 == 0
    out = bytearray()
    for p in range(0, len(bits), 8):
        v = 0
        for b in bits[p:p + 8]:
            v = (v << 1) | b
        out.append(v)
    return bytes(out)


def words_from_block(block):
    assert len(block) % 8 == 0
    return [int.from_bytes(block[i:i + 8], "big")
            for i in range(0, len(block), 8)]


def expansion(block, version):
    words = words_from_block(block)
    half = 9 if version == 1 else 18
    seeds = [words[:half], words[half:2 * half]]
    out = seeds
    rounds = 18 if version == 1 else 24
    for j in range(2, rounds + 1):
        if version == 1:
            nxt = xor_state(mef_half(out[j - 1]), out[j - 2])
        else:
            nxt = (
                xor_state(mef_half(out[j - 1][:9]), out[j - 2][:9])
                + xor_state(mef_half(out[j - 1][9:]), out[j - 2][9:])
            )
        out.append(nxt)
    return out


def round_v1(x, j):
    half = 9
    y = [(x[i] ^ rotl(PI16[j], i)) & MASK for i in range(half)]
    return linear_words(permute_words(chi_words(y)))


def round_v2(x, j):
    left, right = x[:9], x[9:]
    left = [(left[i] ^ rotl(PI16[j], i)) & MASK for i in range(9)]
    right = [(right[i] ^ rotl(PI16[j], i + 9)) & MASK for i in range(9)]
    left, right = permute_words(chi_words(left)), permute_words(chi_words(right))
    for p, q in CROSS:
        left[p], right[q] = right[q], left[p]
    return linear_words(left) + linear_words(right, True)


def compress_words(v, block, version):
    bb = expansion(block, version)
    x = v[:]
    rounds = 18 if version == 1 else 24
    for j in range(rounds):
        injected = xor_state(x, bb[j])
        x = round_v1(injected, j) if version == 1 else round_v2(injected, j)
    return xor_state(xor_state(x, bb[rounds]), v)


def hash_words(message_bits, version):
    mu = 1152 if version == 1 else 2304
    padded = pad_bits(message_bits, mu)
    blocks = [bits_to_bytes(padded[p:p + mu]) for p in range(0, len(padded), mu)]
    sigma_bits = [0] * mu
    for block in blocks:
        for i, b in enumerate(bits_from_block(block)):
            sigma_bits[i] ^= b
    sigma = bits_to_bytes(sigma_bits)

    zero = [0] * (9 if version == 1 else 18)
    h_prev, h = zero, zero
    for block in blocks:
        old_h = h
        h = xor_state(compress_words(h, block, version), h_prev)
        h_prev = old_h
    h = compress_words(h, sigma, version)
    out_words = h[:8] if version == 1 else h[:16]
    return b"".join(w.to_bytes(8, "big") for w in out_words)


def bits_from_block(block):
    return [(byte >> (7 - i)) & 1 for byte in block for i in range(8)]


def word_bits_lsb(w):
    return [(w >> i) & 1 for i in range(64)]


# Independent tuple-of-columns implementation.  The state is (half, lane, z),
# and the S-box is evaluated one bit at a time rather than on packed words.
def slow_chi(state):
    n = len(state) // 9
    out = [[0] * 64 for _ in range(9 * n)]
    for h in range(n):
        base = 9 * h
        for z in range(64):
            a = [state[base + i][z] for i in range(9)]
            b = [
                a[i] ^ (1 ^ ((1 ^ a[(i + 1) % 9]) & a[(i + 2) % 9]))
                for i in range(9)
            ]
            for i in range(9):
                out[base + i][z] = b[i]
    return out


def slow_permute(state):
    n = len(state) // 9
    out = [[0] * 64 for _ in state]
    for h in range(n):
        base = 9 * h
        for i, p in enumerate(PI):
            out[base + p] = state[base + i][:]
    return out


def slow_rotl_lane(lane, n):
    return [lane[(z - n) % 64] for z in range(64)]


def slow_linear(state, rows):
    out = []
    for row in rows:
        lane = [0] * 64
        for tj, r in row:
            term = slow_rotl_lane(state[tj], r)
            lane = [x ^ y for x, y in zip(lane, term)]
        out.append(lane)
    return out


def slow_round(state, j, version):
    n = 1 if version == 1 else 2
    injected = []
    for h in range(n):
        for i in range(9):
            lane = state[9 * h + i][:]
            stream = word_bits_lsb(PI16[j])
            shift = i if h == 0 else i + 9
            c = slow_rotl_lane(stream, shift)
            injected.append([x ^ y for x, y in zip(lane, c)])
    p = slow_permute(slow_chi(injected))
    if version == 1:
        return slow_linear(p, L_ROWS)
    left, right = p[:9], p[9:]
    for a, b in CROSS:
        left[a], right[b] = right[b], left[a]
    return slow_linear(left, L_ROWS) + slow_linear(right, R_ROWS)


def slow_mef(state):
    rotated = [
        slow_rotl_lane(state[h * 9 + i], D[i])
        for h in range(len(state) // 9)
        for i in range(9)
    ]
    return slow_chi(rotated)


def slow_expansion(block, version):
    words = words_from_block(block)
    half = 9 if version == 1 else 18
    seeds = []
    for h in range(2):
        seeds.append([
            word_bits_lsb(words[h * half + i])
            for i in range(half)
        ])
    prev2, prev1 = seeds[0], seeds[1]
    out = [prev2, prev1]

    rounds = 18 if version == 1 else 24
    for _ in range(2, rounds + 1):
        nxt = slow_mef(prev1)
        nxt = [[x ^ y for x, y in zip(a, b)] for a, b in zip(nxt, prev2)]
        out.append(nxt)
        prev2, prev1 = prev1, nxt
    return out


def slow_compress(v, block, version):
    bb = slow_expansion(block, version)
    x = v
    rounds = 18 if version == 1 else 24
    for j in range(rounds):
        x = [
            [a ^ b for a, b in zip(x[i], bb[j][i])]
            for i in range(len(x))
        ]
        x = slow_round(x, j, version)
    return [
        [a ^ b ^ c for a, b, c in zip(x[i], bb[rounds][i], v[i])]
        for i in range(len(x))
    ]


def slow_hash(message_bits, version):
    mu = 1152 if version == 1 else 2304
    padded = pad_bits(message_bits, mu)
    blocks = [bits_to_bytes(padded[p:p + mu]) for p in range(0, len(padded), mu)]
    sigma = bytearray(mu // 8)
    for block in blocks:
        for i, b in enumerate(block):
            sigma[i] ^= b
    zero = [[0] * 64 for _ in range(9 if version == 1 else 18)]
    h_prev, h = zero, zero
    for block in blocks:
        old_h = h
        h = slow_compress(h, block, version)
        h = [[a ^ b for a, b in zip(h[i], h_prev[i])] for i in range(len(h))]
        h_prev = old_h
    h = slow_compress(h, bytes(sigma), version)
    out_words = []
    for lane in h[:8 if version == 1 else 16]:
        value = sum(bit << z for z, bit in enumerate(lane))
        out_words.append(value)
    return b"".join(w.to_bytes(8, "big") for w in out_words)


def main():
    # Same call arguments to wchain_vN_hash_bits_c: one-byte buffer 0x80,
    # msg_len_bits=1.  The PDF never says whether byte bit 7 or bit 0 is first.
    msg = b"\x80"
    msb_bits = [(msg[0] >> (7 - i)) & 1 for i in range(1)]
    lsb_bits = [(msg[0] >> i) & 1 for i in range(1)]
    print("source byte", msg.hex(), "msg_len_bits", 1)
    print("MSB-first source bit list", msb_bits)
    print("LSB-first source bit list", lsb_bits)
    for version, mu in ((1, 1152), (2, 2304)):
        p_msb = pad_bits(msb_bits, mu)
        p_lsb = pad_bits(lsb_bits, mu)
        b_msb = bits_to_bytes(p_msb)
        b_lsb = bits_to_bytes(p_lsb)
        d_msb = hash_words(msb_bits, version)
        d_lsb = hash_words(lsb_bits, version)
        s_msb = slow_hash(msb_bits, version)
        s_lsb = slow_hash(lsb_bits, version)
        print(f"V{version} M1 MSB", b_msb.hex())
        print(f"V{version} M1 LSB", b_lsb.hex())
        print(f"V{version} digest MSB", d_msb.hex())
        print(f"V{version} digest LSB", d_lsb.hex())
        print(f"V{version} fast/slow MSB", d_msb == s_msb)
        print(f"V{version} fast/slow LSB", d_lsb == s_lsb)


if __name__ == "__main__":
    main()
