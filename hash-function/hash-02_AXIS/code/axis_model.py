"""Independent bit-level AXIS model reconstructed from hash-02-spec.pdf.

Register bit i is the coefficient of 2^i in an integer (the specification's
right-to-left indexing).  State bit 192*j+i belongs to register j.
"""

# Specification array indices run right-to-left.  The printed tuples are
# (ExL[6],...,ExL[0]) and (UpL[5],...,UpL[0]).
EXL = (0, 12, 32, 96, 107, 125, 11)
UPL = (66, 75, 90, 162, 178, 188)
MASK192 = (1 << 192) - 1


def bit(x, i):
    return (x >> i) & 1


def sbox6(x):
    x5, x4, x3, x2, x1, x0 = ((x >> i) & 1 for i in range(6))
    return (x5 & x4) ^ (x3 & x2) ^ (x1 & x0)


def xor_bits(x, idx):
    out = 0
    for i in idx:
        out ^= bit(x, i)
    return out


def extract(x, idx):
    # X[ik-1,...,i0] places the listed most-significant item first.
    out = 0
    for i in idx:
        out = (out << 1) | bit(x, i)
    return out


def up_res(s, j, m):
    sj = s[j]
    sm5 = s[(j + 5) & 7]
    sm3 = s[(j + 3) & 7]
    sm1 = s[(j - 1) & 7]
    sp1 = s[(j + 1) & 7]
    tau = sbox6(
        (extract(sm5, (EXL[3], EXL[2])) << 4)
        | (extract(sm3, (EXL[5], EXL[1])) << 2)
        | extract(sp1, (EXL[4], EXL[0]))
    )
    b = (
        m
        ^ sbox6(extract(sj, (EXL[5], EXL[2], EXL[4], EXL[1], EXL[3], EXL[0])))
        ^ tau
        ^ bit(sm1, EXL[6])
    )
    t0 = xor_bits(sj, EXL[:3]) ^ b
    t1 = xor_bits(sj, EXL[3:6]) ^ b
    delta = 0
    for i in UPL[:3]:
        delta ^= t1 << i
    for i in UPL[3:]:
        delta ^= t0 << i
    # New bit i is old bit i+1 modulo 192.
    rotated = (sj >> 1) | ((sj & 1) << 191)
    s[j] = rotated ^ delta


def full_state(regs):
    return sum(r << (192 * j) for j, r in enumerate(regs))


def regs_from_state(s):
    return [(s >> (192 * j)) & MASK192 for j in range(8)]


def beat(s, mu, nu):
    r = regs_from_state(s)
    for j in range(8):
        up_res(r, j, mu if j % 2 == 0 else nu)
    return full_state(r)


def inverse_up_res(s, j, m, target):
    """Invert register j; s holds all partner registers at forward time j."""
    saved = s[j]
    found = []
    # Undo the cyclic assignment: target bit i is modified-old bit i-1.
    modified = ((target << 1) & MASK192) | (target >> 191)
    p1 = xor_bits(modified, EXL[3:6])
    p0 = xor_bits(modified, EXL[0:3])
    for b in (0, 1):
        # UpL and ExL are disjoint, so the two feedback parities can be
        # computed from the modified word and checked through b.
        t1 = p1 ^ b
        t0 = p0 ^ b
        x = modified
        for i in UPL[:3]:
            x ^= t1 << ((i + 1) % 192)
        for i in UPL[3:]:
            x ^= t0 << ((i + 1) % 192)
        s[j] = x
        up_res(s, j, m)
        if s[j] == target:
            found.append(x)
    s[j] = saved
    return found


def inverse_beat(y, mu, nu):
    states = [regs_from_state(y)]
    for j in range(7, -1, -1):
        next_states = []
        m = mu if j % 2 == 0 else nu
        for r in states:
            target = r[j]
            for x in inverse_up_res(r, j, m, target):
                rr = list(r)
                rr[j] = x
                next_states.append(rr)
        states = next_states
    return [full_state(r) for r in states]


def gen_digest(s):
    r = regs_from_state(s)
    i = EXL[0]
    hm = bit(r[6], i) ^ bit(r[4], i) ^ (bit(r[2], i) & bit(r[0], i))
    hn = bit(r[7], i) ^ bit(r[5], i) ^ (bit(r[3], i) & bit(r[1], i))
    return hm, hn


INIT_HEX = (
    "243F6A8885A308D3B7E151628AED2A6A9E3779B97F4A7C15",
    "7160C6B758B90A76D81F8650363C93F849CA76E19F938DA4",
    "70FF7724ACB762F7B54CBDE35B659CC7CD71C257B752EEB5",
    "4FD6E6B4FBAB7ECD3120355B0549D6B947EA14CFA7D43857",
    "6B634EF404919AAA03F92D7B7FAEEF105DCD2735332E4029",
    "53C1A2C96C4DE7E3CD0814056FA6E00BD57AC41E845348D4",
    "F3FF90522F99DAE5352FF6633C6EFBA6ABDBF53A09476735",
    "B1A270D3653FB5B8D94570230179F8120D875B906F276D2C",
)
INIT_REGS = tuple(int(x, 16) for x in INIT_HEX)
INIT_S = full_state(INIT_REGS)


if __name__ == "__main__":
    z = 0
    o = (1 << 1536) - 1
    print("init bits", INIT_S.bit_count())
    for mu, nu in ((0, 0), (0, 1), (1, 0), (1, 1)):
        print("zero beats to", (mu, nu), beat(z, mu, nu) == z)
        print("one beats to", (mu, nu), beat(o, mu, nu) == o)
    print("init all zero/one?", INIT_S in (0, o))
