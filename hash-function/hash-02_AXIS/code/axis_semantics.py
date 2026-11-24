#!/usr/bin/env python3
"""Exact p.4-21 AXIS execution for two natural register-update semantics."""

CONSTS = [
    0x243F6A8885A308D3B7E151628AED2A6A9E3779B97F4A7C15,
    0x7160C6B758B90A76D81F8650363C93F849CA76E19F938DA4,
    0x70FF7724ACB762F7B54CBDE35B659CC7CD71C257B752EEB5,
    0x4FD6E6B4FBAB7ECD3120355B0549D6B947EA14CFA7D43857,
    0x6B634EF404919AAA03F92D7B7FAEEF105DCD2735332E4029,
    0x53C1A2C96C4DE7E3CD0814056FA6E00BD57AC41E845348D4,
    0xF3FF90522F99DAE5352FF6633C6EFBA6ABDBF53A09476735,
    0xB1A270D3653FB5B8D94570230179F8120D875B906F276D2C,
]

EXL = [0, 12, 32, 96, 107, 125, 11]  # EXL[i] in index notation
UPL = [66, 75, 162, 90, 178, 188]


def bit(x: int, i: int) -> int:
    return (x >> i) & 1


def sbox(xs: list[int]) -> int:
    """SBox(x5,x4,x3,x2,x1,x0)."""
    return xs[0] * xs[1] ^ xs[2] * xs[3] ^ xs[4] * xs[5]


def bits_of(s: int, inds: list[int]) -> list[int]:
    """Return X[inds[0], ..., inds[-1]]."""
    return [bit(s, i) for i in inds]


def up_register(s: list[int], j: int, m: int) -> int:
    """Return the next register word, reading the supplied full state."""
    tau = sbox(
        bits_of(s[(j + 5) % 8], [EXL[3], EXL[2]])
        + bits_of(s[(j + 3) % 8], [EXL[5], EXL[1]])
        + bits_of(s[(j + 1) % 8], [EXL[4], EXL[0]])
    )
    b = (
        m
        ^ sbox(bits_of(s[j], [EXL[5], EXL[2], EXL[4], EXL[1], EXL[3], EXL[0]]))
        ^ tau
        ^ bit(s[(j - 1) % 8], EXL[6])
    )
    t0 = bit(s[j], EXL[2]) ^ bit(s[j], EXL[1]) ^ bit(s[j], EXL[0]) ^ b
    t1 = bit(s[j], EXL[5]) ^ bit(s[j], EXL[4]) ^ bit(s[j], EXL[3]) ^ b
    z = s[j]
    for i in [UPL[2], UPL[1], UPL[0]]:
        z ^= t1 << i
    for i in [UPL[5], UPL[4], UPL[3]]:
        z ^= t0 << i
    # S[191],...,S[0] <- S[0],S[191],...,S[1].
    z = ((z << 1) & ((1 << 192) - 1)) | (z >> 191)
    return z


def up_full(s: list[int], m_mu: int, m_nu: int, semantics: str) -> list[int]:
    if semantics == "simultaneous":
        old = s[:]
        return [up_register(old, j, m_mu if j % 2 == 0 else m_nu) for j in range(8)]
    if semantics == "ascending":
        s = s[:]
        for j in range(8):
            s[j] = up_register(s, j, m_mu if j % 2 == 0 else m_nu)
        return s
    if semantics == "descending":
        s = s[:]
        for j in range(7, -1, -1):
            s[j] = up_register(s, j, m_mu if j % 2 == 0 else m_nu)
        return s
    raise ValueError(semantics)


def pad(message: str, bit_len: int | None = None) -> list[int]:
    """Pad a displayed MSB-first string and return bits in stream-index order.

    The specification writes a state/message as X[last] ... X[0].  Therefore
    the rightmost displayed padded bit is M[0] and is the first stream bit.
    """
    if bit_len is None:
        bit_len = len(message)
    assert len(message) >= bit_len
    displayed_message = [int(c) for c in message[:bit_len]]
    assert bit_len < 1 << 64
    s = (-bit_len - 3) % 64
    displayed_padding = [1] + [0] * (s + 1) + [1]
    displayed_padding += [(bit_len >> i) & 1 for i in range(63, -1, -1)]
    displayed = displayed_message + displayed_padding
    assert len(displayed) % 64 == 0
    return list(reversed(displayed))


def message_positions(version: int, padded_len: int) -> list[tuple[int, int]]:
    """For each beat return (mu_index, nu_index), duplicate index if one bit."""
    out = []
    if version == 512:
        assert padded_len % 2 == 0
        for p in range(0, padded_len, 2):
            out.append((p + 1, p))
        return out
    if version == 1024:
        return [(p, p) for p in range(padded_len)]
    if version != 768:
        raise ValueError(version)

    r = padded_len % 192
    normal_bits = padded_len if r == 0 else padded_len - r
    p = 0
    beat = 0
    while p < normal_bits:
        if beat % 2 == 0:
            out.append((p, p))
            p += 1
        else:
            out.append((p + 1, p))
            p += 2
        beat += 1
    if r == 64:
        while p < padded_len:
            out.append((p, p))
            p += 1
    elif r == 128:
        while p < normal_bits + 96:
            if beat % 2 == 0:
                out.append((p, p))
                p += 1
            else:
                out.append((p + 1, p))
                p += 2
            beat += 1
        while p < padded_len:
            out.append((p, p))
            p += 1
    elif r != 0:
        raise AssertionError(r)
    assert p == padded_len
    return out


def gen_digest(s: list[int]) -> tuple[int, int]:
    i = EXL[0]
    h_mu = bit(s[6], i) ^ bit(s[4], i) ^ (bit(s[2], i) & bit(s[0], i))
    h_nu = bit(s[7], i) ^ bit(s[5], i) ^ (bit(s[3], i) & bit(s[1], i))
    return h_mu, h_nu


def axis(message: str, version: int, semantics: str, bit_len: int | None = None):
    padded = pad(message, bit_len)
    positions = message_positions(version, len(padded))
    s = CONSTS[:]
    traces = []
    for beat, (imu, inu) in enumerate(positions):
        s = up_full(s, padded[imu], padded[inu], semantics)
        if beat in (0, 1, 2, 31, 32):
            traces.append((beat, s[:]))
    n_fin = 1024
    n_dig = {512: 256, 768: 512, 1024: 1024}[version]
    # initS begins with Constant0. Its bit indices 0..191 occur first in the
    # lowest-to-highest stream order, followed by Constant1 and so on.
    stream_bits = 8 * (n_fin + n_dig)
    const_bits = [
        bit(CONSTS[(i % 1536) // 192], i % 192)
        for i in range(stream_bits)
    ]
    for beat in range(n_fin):
        c = const_bits[8 * beat : 8 * beat + 8]
        # ReUpFull: c7,...,c0; j receives c_j.
        if semantics == "simultaneous":
            old = s[:]
            s = [up_register(old, j, c[j]) for j in range(8)]
        elif semantics == "ascending":
            for j in range(8):
                s[j] = up_register(s, j, c[j])
        else:
            for j in range(7, -1, -1):
                s[j] = up_register(s, j, c[j])
    digest = []
    for beat in range(n_dig):
        h_mu, h_nu = gen_digest(s)
        if version == 512:
            digest.extend([h_mu, h_nu])
        elif version == 768:
            if beat % 2 == 0:
                digest.append(h_mu)
            else:
                digest.extend([h_mu, h_nu])
        else:
            digest.append(h_mu)
        c = const_bits[8 * (n_fin + beat) : 8 * (n_fin + beat) + 8]
        if semantics == "simultaneous":
            old = s[:]
            s = [up_register(old, j, c[j]) for j in range(8)]
        elif semantics == "ascending":
            for j in range(8):
                s[j] = up_register(s, j, c[j])
        else:
            for j in range(7, -1, -1):
                s[j] = up_register(s, j, c[j])
    assert len(digest) == version
    return digest, s, traces


def digest_hex(bits: list[int]) -> str:
    # This display convention is immaterial to equality; index 0 is the rightmost bit.
    return "".join(str(b) for b in bits)


if __name__ == "__main__":
    for version in (512, 768, 1024):
        ds = {}
        for sem in ("simultaneous", "ascending", "descending"):
            ds[sem], final, traces = axis("", version, sem)
            if sem != "simultaneous":
                first = next(
                    i
                    for i, b in enumerate(ds[sem])
                    if b != ds["simultaneous"][i]
                )
                print(version, sem, "first_digest_diff", first)
            print(version, sem, "digest_digest", digest_hex(ds[sem]))
        print(version, "equal_all", len(set(map(tuple, ds.values()))) == 1)
