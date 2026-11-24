#!/usr/bin/env python3
"""Word-level Vedak replay used to resolve physical bit/nibble conventions."""

from __future__ import annotations

import itertools
import re

import pymupdf

from vedak_check import EXPECTED, LAMBDA, PSI_ROT, PSI_WORD_PERM, RC, SBOX


def rol32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF if n else x


def ror32(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF if n else x


def permutation(
    words: list[int],
    *,
    left: bool,
    rc_low: bool,
    split_low: bool,
    sbox_low: bool,
) -> list[int]:
    st = list(words)
    rotate = rol32 if left else ror32
    for rnd in range(40):
        nxt = []
        for word in st:
            z = 0
            for k in range(16):
                shift = 4 * k if sbox_low else 60 - 4 * k
                z |= SBOX[(word >> shift) & 0xF] << shift
            nxt.append(z)
        st = nxt

        nxt = [0] * 40
        for col in range(4):
            for bit in range(4):
                source = [(st[4 * i + col] >> bit) & 1 for i in range(10)]
                for i, row in enumerate(LAMBDA):
                    y = 0
                    for j, coefficient in enumerate(row):
                        y ^= source[j] & coefficient
                    nxt[4 * i + col] |= y << bit
        st = nxt

        nxt = [0] * 40
        for row in range(10):
            halves = []
            for word in st[4 * row:4 * row + 4]:
                high, low = (word >> 32) & 0xFFFFFFFF, word & 0xFFFFFFFF
                halves.extend([low, high] if split_low else [high, low])
            moved = [
                rotate(halves[PSI_WORD_PERM[row][j]], PSI_ROT[row])
                for j in range(8)
            ]
            for j in range(4):
                first, second = moved[2 * j:2 * j + 2]
                if split_low:
                    nxt[4 * row + j] = (second << 32) | first
                else:
                    nxt[4 * row + j] = (first << 32) | second
        st = nxt
        st[0] ^= RC[rnd] if rc_low else RC[rnd] << 32
    return st


def pad_bits(msglen: int, rate: int) -> list[int]:
    return [0] * msglen + [1] + [0] * ((-msglen - 2) % rate) + [1]


def hash_message(
    msg: str,
    *,
    rate: int,
    digest: int,
    left: bool,
    rc_low: bool,
    split_low: bool,
    sbox_low: bool,
    msg_low: bool,
    out_low: bool,
) -> str:
    bits = [int(bit) for ch in msg for bit in f"{int(ch, 16):04b}"]
    stream = pad_bits(len(bits), rate)
    state = [0] * 40
    for start in range(0, len(stream), rate):
        for p, bit in enumerate(stream[start:start + rate]):
            if not bit:
                continue
            word, off = divmod(p, 64)
            state[word] ^= 1 << (off if msg_low else 63 - off)
        state = permutation(
            state, left=left, rc_low=rc_low, split_low=split_low, sbox_low=sbox_low
        )

    outbits: list[int] = []
    while len(outbits) < digest:
        for word in state:
            outbits.extend(
                (word >> (off if out_low else 63 - off)) & 1 for off in range(64)
            )
        if len(outbits) < digest:
            state = permutation(
                state,
                left=left,
                rc_low=rc_low,
                split_low=split_low,
                sbox_low=sbox_low,
            )
    value = 0
    for bit in outbits[:digest]:
        value = (value << 1) | bit
    return f"{value:0{digest // 4}X}"


def explicit_examples() -> list[tuple[str, int, int, str]]:
    doc = pymupdf.open("/tmp/vedak-hash27-spec.pdf")
    text = "\n".join(doc[i].get_text("text") for i in range(37, 43))
    starts = [m.start() for m in re.finditer(r"Example 4:", text)]
    ends = [
        text.index("8.2", starts[0]),
        text.index("8.3", starts[1]),
        text.index("References", starts[2]),
    ]
    out = []
    for start, end, digest, rate in zip(
        starts, ends, (512, 768, 1024), (1536, 1024, 512)
    ):
        segment = text[start:end]
        msg_match = re.search(r"Msg\s*=\s*(.*?)\s*Dst_Len", segment, re.S)
        dst_match = re.search(r"Dst\s*=\s*(.*)", segment, re.S)
        assert msg_match and dst_match
        msg = "".join(
            line for line in msg_match.group(1).splitlines()
            if len(line) > 2 and re.fullmatch(r"[0-9A-Fa-f]+", line)
        )
        dst = "".join(
            line for line in dst_match.group(1).splitlines()
            if len(line) > 2 and re.fullmatch(r"[0-9A-Fa-f]+", line)
        )
        assert len(msg) * 4 == 8192
        out.append((msg, digest, rate, dst))
    return out


def main() -> None:
    examples = explicit_examples()
    names = ("left", "rc_low", "split_low", "sbox_low", "msg_low", "out_low")
    survivors = []
    for flags in itertools.product((False, True), repeat=6):
        kw = dict(zip(names, flags))
        empty = hash_message(
            "", rate=1536, digest=512, **kw
        )
        if empty != EXPECTED[512]:
            continue
        msg, digest, rate, expected = examples[0]
        got = hash_message(msg, rate=rate, digest=digest, **kw)
        print("empty-survivor", kw, "nonempty-match", got == expected, got[:32])
        if got == expected:
            survivors.append(flags)
    print("survivors", survivors)


if __name__ == "__main__":
    main()
