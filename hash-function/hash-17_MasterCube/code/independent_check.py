#!/usr/bin/env python3
"""Independent flat-array check of the corrected MasterCube round inverse."""

from __future__ import annotations

import random

M = 0xFFFF
R = ((0, 1, 8), (14, 5, 0), (9, 12, 8),
     (14, 5, 0), (0, 1, 8), (8, 9, 0))
XM = ((1, 1, 0, 0, 1, 0), (0, 1, 1, 0, 0, 1),
      (1, 0, 1, 1, 0, 0), (0, 1, 0, 1, 1, 0),
      (0, 0, 1, 0, 1, 1), (1, 0, 0, 1, 0, 1))
YM = ((1, 1, 0, 1), (1, 1, 1, 0),
      (0, 1, 1, 1), (1, 0, 1, 1))
C0 = ((0, 1, 1), (1, 0, 1), (1, 1, 1))
C1 = ((1, 0, 1), (0, 1, 1), (1, 1, 1))
RC = (0x243F, 0x6A88, 0x85A3, 0x08D3,
      0x1319, 0x8A2E, 0x0370, 0x7344)


def ix(x, y, z):
    return 12 * x + 2 * y + z


def rr(v, k):
    return v if k == 0 else ((v >> k) | (v << (16 - k))) & M


def mv(mat, v):
    ans = []
    for row in mat:
        acc = 0
        for a, b in zip(row, v):
            if a:
                acc ^= b
        ans.append(acc)
    return ans


def cross(a):
    b = a[:]
    for x in range(8):
        for parity in (0, 1):
            ys = (parity, parity + 2, parity + 4)
            v = [a[ix(x, y, z)] for z in (0, 1) for y in ys]
            w = mv(XM, v)
            for j, y in enumerate(ys):
                b[ix(x, y, 0)] = w[j]
                b[ix(x, y, 1)] = w[j + 3]
    return b


def rows(a):
    b = a[:]
    for x in range(8):
        for y in (0, 2, 4):
            i, j = ix(x, y, 1), ix(x, y + 1, 1)
            b[i], b[j] = a[j], a[i]
    return b


def cols(a, inv=False):
    b = a[:]
    mats = (C1, C0) if inv else (C0, C1)
    for x in range(8):
        for parity in (0, 1):
            ys = (parity, parity + 2, parity + 4)
            for z in (0, 1):
                w = mv(mats[z], [a[ix(x, y, z)] for y in ys])
                for y, v in zip(ys, w):
                    b[ix(x, y, z)] = v
    return b


def shifts(a, inverse=False):
    b = a[:]
    for x in range(8):
        for y in range(6):
            for z in (0, 1):
                d = ((x + y) if z == 0 else (x - y)) % 8 if inverse else (
                    (x - y) if z == 0 else (x + y)) % 8
                b[ix(d, y, z)] = a[ix(x, y, z)]
    return b


def mixrows(a):
    b = a[:]
    for x in range(8):
        for y in range(6):
            for z in (0, 1):
                for parity in (0, 1):
                    xs = (parity, parity + 2, parity + 4, parity + 6)
                    w = mv(YM, [a[ix(i, y, z)] for i in xs])
                    for i, v in zip(xs, w):
                        b[ix(i, y, z)] = v
    return b


def m_and_rx(a, inverse=False):
    b = a[:]
    order = tuple(reversed(R)) if inverse else R
    for x in range(8):
        for y in range(6):
            l, r = a[ix(x, y, 0)], a[ix(x, y, 1)]
            if inverse:
                for sa, sb, sc in order:
                    lp, rp = l, r
                    f = (rr(rp, sa) & rr(rp, sb)) ^ rr(rp, sc)
                    l, r = rp, (lp ^ f) & M
            else:
                for sa, sb, sc in order:
                    f = (rr(l, sa) & rr(l, sb)) ^ rr(l, sc)
                    l, r = (f ^ r) & M, l
            b[ix(x, y, 0)], b[ix(x, y, 1)] = l, r
    return b


def add_rc(a, i):
    b = a[:]
    for x in range(8):
        b[ix(x, 0, 0)] ^= RC[x] ^ i
    return b


def swap_z(a):
    b = a[:]
    for x in range(8):
        for y in range(6):
            u, v = ix(x, y, 0), ix(x, y, 1)
            b[u], b[v] = a[v], a[u]
    return b


def forward(a, i):
    a = cross(a)
    a = rows(a)
    a = m_and_rx(a)
    a = cross(a)
    a = rows(a)
    a = cols(a)
    a = shifts(a)
    a = mixrows(a)
    return add_rc(a, i)


def inverse(a, i):
    a = add_rc(a, i)
    a = mixrows(a)
    a = shifts(a, True)
    a = cols(a, True)
    a = rows(a)
    a = cross(a)
    a = m_and_rx(a, True)
    a = rows(a)
    return cross(a)


def literal(a, i):
    a = add_rc(a, i)
    a = mixrows(a)
    a = swap_z(a)
    a = shifts(a)
    a = cols(a)
    a = swap_z(a)
    a = rows(a)
    a = cross(a)
    a = swap_z(a)
    a = m_and_rx(a)
    a = rows(a)
    return cross(a)


def delete_line10(a, i):
    a = add_rc(a, i)
    a = mixrows(a)
    a = swap_z(a)
    a = shifts(a)
    a = cols(a)
    a = swap_z(a)
    a = rows(a)
    a = cross(a)
    a = m_and_rx(a)
    a = rows(a)
    return cross(a)


def invert_line11(a, i):
    a = add_rc(a, i)
    a = mixrows(a)
    a = swap_z(a)
    a = shifts(a)
    a = cols(a)
    a = swap_z(a)
    a = rows(a)
    a = cross(a)
    a = swap_z(a)
    a = m_and_rx(a, True)
    a = rows(a)
    return cross(a)


def xor_states(a, b):
    return [u ^ v for u, v in zip(a, b)]


def nine_forward(a):
    for i in range(9):
        a = forward(a, i)
    return a


def nine_inverse(a):
    for i in range(8, -1, -1):
        a = inverse(a, i)
    return a


def structured():
    zero = [0] * 96
    full = [M] * 96
    pattern = [((7 * i + 11) ^ (i << 3)) & M for i in range(96)]
    return [("zero", zero), ("full", full), ("pattern", pattern)]


def random_states(n=32):
    g = random.Random(0xC0DEF00D)
    return [("random", [g.getrandbits(16) for _ in range(96)])
            for _ in range(n)]


def main():
    checked = 0
    nine_checked = 0
    for label, a in structured() + random_states():
        for i in range(18):
            assert inverse(forward(a, i), i) == a, (label, i, "left")
            assert forward(inverse(a, i), i) == a, (label, i, "right")
            checked += 1
    print("independent corrected-round checks passed:", checked)
    print("cases: 3 structured + 32 random; all round indices i=0..17; both sides")

    for label, a in (structured() + random_states(8)):
        assert nine_inverse(nine_forward(a)) == a, (label, "nine-round inverse")
        assert nine_forward(nine_inverse(a)) == a, (label, "nine-round forward")
        nine_checked += 1
    print("independent nine-round checks passed:", nine_checked)

    a = [0] * 96
    a[ix(0, 0, 0)] = 1
    a[ix(0, 0, 1)] = 2
    b = forward(a, 0)
    assert sum(u != v for u, v in zip(a, literal(b, 0))) == 11
    assert sum(u != v for u, v in zip(a, delete_line10(b, 0))) == 8
    assert sum(u != v for u, v in zip(a, invert_line11(b, 0))) == 12
    assert inverse(b, 0) == a
    print("independent targeted repair witness checks passed")


if __name__ == "__main__":
    main()
