import sys

MASK = (1 << 64) - 1
SIGMA = [
    22, 0, 29, 19, 26, 4, 1, 23, 30, 8, 5, 27, 2, 12, 9, 31,
    6, 16, 13, 3, 10, 20, 17, 7, 14, 24, 21, 11, 18, 28, 25, 15,
]
ROT = [
    (36, 54, 45, 44, 18, 9),
    (56, 46, 54, 34, 19, 51),
]
RC = [
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


def rotl(x, n):
    return ((x << n) | (x >> (64 - n))) & MASK


def mq(words, p, rc):
    p0, p1, p2, p3, p4, p5 = p
    a, b, c, d = words
    a = (a + b) & MASK
    d = rotl(d ^ a, p0)
    a = rotl(a, p4) ^ rc
    c = (c + d) & MASK
    b = rotl(b ^ c, p1)
    c = rotl(c, p5)
    a = (a + b) & MASK
    d = rotl(d ^ a, p2)
    c = (c + d) & MASK
    b = rotl(b ^ c, p3)
    return [a, b, c, d]


def perm(state):
    a = state[:]
    for rnd in range(16):
        for j in range(8):
            p = ROT[0 if j < 4 else 1]
            rc = RC[rnd][0 if j < 4 else 1]
            a[4*j:4*j+4] = mq(a[4*j:4*j+4], p, rc)
        z = a
        a = [z[SIGMA[l]] for l in range(32)]
        u = a
        v = []
        for j in range(8):
            col = u[4*j:4*j+4]
            s = col[0] ^ col[1] ^ col[2] ^ col[3]
            v.extend([s ^ x for x in col])
        z = v
        a = [z[SIGMA[l]] for l in range(32)]
    return a


def hash_profile(msg, h):
    r = 2048 - h - 64
    msg_bits = len(msg) * 8
    assert msg_bits + 1 <= r and msg_bits < 960
    x = [0] * 32
    block = bytearray(r // 8)
    block[:len(msg)] = msg
    block[len(msg)] = 0x80
    s = x[:]
    for i, b in enumerate(block):
        s[i // 8] ^= int.from_bytes(bytes([b]), "little") << (8 * (i % 8))
    s[31] ^= 1 << 63
    p = perm(s)
    x = [p[i] ^ ((s[i] if i >= (2048 - (h + 64)) // 64 else 0)) for i in range(32)]
    # Equivalent feed-forward(0^r || right_c(s)).
    first = 32 - h // 64
    return x, (sum(x[i] << (64 * (i - first)) for i in range(first, 32)) if h < 2048 else 0)


if __name__ == "__main__":
    for msg in (b"", b"abc"):
        xs = []
        for h in (256, 384, 512, 768, 1024):
            x, y = hash_profile(msg, h)
            xs.append(x)
            print(msg, h, "digest", f"{y:0{h//4}x}")
        print("all states equal", all(x == xs[0] for x in xs))
