#!/usr/bin/env python3
"""Independent bit-array check of axis_semantics_refute.py."""

import hashlib


EX = (0, 12, 32, 96, 107, 125, 11)
UP = (66, 75, 90, 162, 178, 188)
CONSTANTS = (
    "243F6A8885A308D3B7E151628AED2A6A9E3779B97F4A7C15",
    "7160C6B758B90A76D81F8650363C93F849CA76E19F938DA4",
    "70FF7724ACB762F7B54CBDE35B659CC7CD71C257B752EEB5",
    "4FD6E6B4FBAB7ECD3120355B0549D6B947EA14CFA7D43857",
    "6B634EF404919AAA03F92D7B7FAEEF105DCD2735332E4029",
    "53C1A2C96C4DE7E3CD0814056FA6E00BD57AC41E845348D4",
    "F3FF90522F99DAE5352FF6633C6EFBA6ABDBF53A09476735",
    "B1A270D3653FB5B8D94570230179F8120D875B906F276D2C",
)


def as_bits(h):
    return [int(c) for c in f"{int(h, 16):0192b}"[::-1]]


INIT0 = [as_bits(c) for c in CONSTANTS]
INIT_STREAM = "".join("".join(map(str, reg)) for reg in INIT0)


def sb6(bits):
    assert len(bits) == 6
    return (bits[0] & bits[1]) ^ (bits[2] & bits[3]) ^ (bits[4] & bits[5])


def slice2(reg, hi, lo):
    return [reg[hi], reg[lo]]


def single_update(regs, j, m):
    r = [x[:] for x in regs]
    selfreg = regs[j]
    tau = sb6(
        slice2(regs[(j + 5) % 8], EX[3], EX[2])
        + slice2(regs[(j + 3) % 8], EX[5], EX[1])
        + slice2(regs[(j + 1) % 8], EX[4], EX[0])
    )
    b = (
        m
        ^ sb6([selfreg[EX[5]], selfreg[EX[2]], selfreg[EX[4]],
               selfreg[EX[1]], selfreg[EX[3]], selfreg[EX[0]]])
        ^ tau
        ^ regs[(j - 1) % 8][EX[6]]
    )
    t0 = selfreg[EX[2]] ^ selfreg[EX[1]] ^ selfreg[EX[0]] ^ b
    t1 = selfreg[EX[5]] ^ selfreg[EX[4]] ^ selfreg[EX[3]] ^ b
    for i in UP[:3]:
        r[j][i] ^= t1
    for i in UP[3:]:
        r[j][i] ^= t0
    old = r[j]
    r[j] = old[1:] + old[:1]
    return r


def full_update(regs, controls, semantics):
    if semantics == "ascending":
        r = regs
        for j, m in enumerate(controls):
            r = single_update(r, j, m)
        return r
    r = [x[:] for x in regs]
    for j, m in enumerate(controls):
        r[j] = single_update(regs, j, m)[j]
    return r


def digest_bits(regs):
    i = EX[0]
    return (
        regs[6][i] ^ regs[4][i] ^ (regs[2][i] & regs[0][i]),
        regs[7][i] ^ regs[5][i] ^ (regs[3][i] & regs[1][i]),
    )


def controls_from_displayed(displayed, order):
    stream = displayed[::-1] if order == "literal" else displayed
    return [[int(stream[2 * i + 1]), int(stream[2 * i])] + [0] * 6
            for i in range(len(stream) // 2)]


def digest(order, semantics):
    regs = [x[:] for x in INIT0]
    displayed_pad = "1" + "0" * 62 + "1" + "0" * 64
    message = controls_from_displayed(displayed_pad, order)
    position = 0
    for controls in message:
        regs = full_update(regs, controls, semantics)

    pos = 0
    for _ in range(1024):
        c = [int(INIT_STREAM[(pos + i) % len(INIT_STREAM)]) for i in range(8)]
        regs = full_update(regs, c, semantics)
        pos += 8

    words = []
    for _ in range(256):
        words.append(digest_bits(regs))
        c = [int(INIT_STREAM[(pos + i) % len(INIT_STREAM)]) for i in range(8)]
        regs = full_update(regs, c, semantics)
        pos += 8

    out = "".join(str(bit) for word in reversed(words) for bit in word)
    return f"{int(out, 2):0128x}", words[0], words[-1], message[0]


def main():
    expected = {
        ("literal", "snapshot"):
            "54ec67756514e8f7dfc398cd01082939f8931cd12ad5929cdcdf7997a2cdeeef"
            "b0b833265b322a50824090cb4e5dec45c1e020de9a8b315c1568171ea9b86368",
        ("literal", "ascending"):
            "81f83a2969f4c67be7a1d5bb1bc8817b33c2b8ea289697a9502cdcc9b7a4a69d"
            "b03ddf490d1445184eff1237c21e970562a33001f33bc13fabbe26e5cdd72862",
        ("handoff", "snapshot"):
            "e7bb2d22d73824a07e32801e59f33da4f4b4e7823ff0dfae638fda12778b1239"
            "eeaa1312e01bb64b7f7a04e38260049d6d6102a20b446862f58080d760cf88cb",
        ("handoff", "ascending"):
            "fa5ddda8d536e330305e408f6d5e4bbd8d4a44b66afaf19de80d25de16665b24"
            "131378141e5942e5b4fc64ed0b160d56348dfc41575b31fd073765f4358b7cd9",
    }
    for order in ("literal", "handoff"):
        for semantics in ("snapshot", "ascending"):
            got, first_generated, first_returned, first_controls = digest(order, semantics)
            assert got == expected[(order, semantics)]
            print(order, semantics)
            print(got)
            print("first beat", first_controls)
            print("h0 pair", first_generated, "h255 pair", first_returned)
            print("sha256", hashlib.sha256(bytes.fromhex(got)).hexdigest())


if __name__ == "__main__":
    main()
