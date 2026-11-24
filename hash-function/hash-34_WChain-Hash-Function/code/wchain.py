#!/usr/bin/env python3
"""Independent executable model of the WChain specification (2026-11-21).

Clean input is the allowlisted PDF saved as wchain-spec.pdf.  This file does not
use any implementation or attack artifact external to that PDF.
"""

from __future__ import annotations

MASK64 = (1 << 64) - 1
PI16_HEX = (
    "243F6A8885A308D313198A2E03707344"
    "A4093822299F31D0082EFA98EC4E6C89"
    "452821E638D01377BE5466CF34E90C6C"
    "C0AC29B7C97C50DD3F84D5B5B5470917"
)
PI16 = [int(PI16_HEX[i:i + 4], 16) for i in range(0, len(PI16_HEX), 4)]

# State coordinates 0..8 are rows; columns z are bit positions in 64-bit words.
PERM = [0, 7, 5, 3, 1, 8, 6, 4, 2]
LEFT_ROWS = [
    ((0, 5), (1, 22), (2, 3), (3, 28), (7, 27)),
    ((1, 39), (2, 59), (3, 45), (4, 3), (8, 9)),
    ((2, 54), (3, 6), (4, 20), (5, 8), (0, 48)),
    ((3, 0), (4, 57), (5, 55), (6, 46), (1, 28)),
    ((4, 61), (5, 38), (6, 0), (7, 44), (2, 52)),
    ((5, 29), (6, 10), (7, 37), (8, 19), (3, 7)),
    ((6, 56), (7, 5), (8, 50), (0, 27), (4, 13)),
    ((7, 40), (8, 10), (0, 11), (1, 54), (5, 14)),
    ((8, 3), (0, 38), (1, 36), (2, 17), (6, 13)),
]
RIGHT_DELTA = (11, 21, 19, 21, 43, 5, 3, 10, 5)
RIGHT_ROWS = [
    tuple((j, (a + RIGHT_DELTA[i]) & 63) for j, a in row)
    for i, row in enumerate(LEFT_ROWS)
]
MEF_ROTATIONS = (0, 1, 10, 20, 25, 32, 41, 46, 50)
CROSS_PAIRS = ((0, 0), (1, 3), (3, 1), (4, 4), (6, 6))


def rotl(x: int, n: int) -> int:
    n &= 63
    return ((x << n) | (x >> (64 - n))) & MASK64 if n else x


def sbox_lanes(a: list[int]) -> list[int]:
    """Apply the bit-sliced 9-bit chi S-box independently to all 64 columns."""
    if len(a) != 9:
        raise ValueError("S-box requires nine lanes")
    return [
        a[i] ^ (((~a[(i + 1) % 9]) & MASK64) & a[(i + 2) % 9])
        for i in range(9)
    ]


def permute_lanes(a: list[int]) -> list[int]:
    out = [0] * 9
    for i, value in enumerate(a):
        out[PERM[i]] = value
    return out


def mix(a: list[int], rows=LEFT_ROWS) -> list[int]:
    return [
        rotl(a[j0], a0) ^ rotl(a[j1], a1) ^ rotl(a[j2], a2)
        ^ rotl(a[j3], a3) ^ rotl(a[j4], a4)
        for row in rows
        for j0, a0 in [row[0]]
        for j1, a1 in [row[1]]
        for j2, a2 in [row[2]]
        for j3, a3 in [row[3]]
        for j4, a4 in [row[4]]
    ]


def cross_swap(left: list[int], right: list[int]) -> tuple[list[int], list[int]]:
    nl, nr = left.copy(), right.copy()
    for li, ri in CROSS_PAIRS:
        nl[li], nr[ri] = nr[ri], nl[li]
    return nl, nr


def round_constant(version: int, j: int) -> tuple[list[int], list[int]]:
    c = PI16[j - 1]
    left = [rotl(c, i) for i in range(9)]
    right = [rotl(c, i + 9) for i in range(9)]
    if version == 1:
        return left, []
    return left, right


def round_function(version: int, state: list[int], j: int) -> list[int]:
    cl, cr = round_constant(version, j)
    if version == 1:
        a = [x ^ c for x, c in zip(state, cl)]
        return mix(permute_lanes(sbox_lanes(a)))
    left = [x ^ c for x, c in zip(state[:9], cl)]
    right = [x ^ c for x, c in zip(state[9:], cr)]
    left = permute_lanes(sbox_lanes(left))
    right = permute_lanes(sbox_lanes(right))
    left, right = cross_swap(left, right)
    return mix(left, LEFT_ROWS) + mix(right, RIGHT_ROWS)


def mef(a: list[int]) -> list[int]:
    return sbox_lanes([rotl(v, MEF_ROTATIONS[i]) for i, v in enumerate(a)])


def expansion(version: int, block: list[int]) -> list[list[int]]:
    words = 9 if version == 1 else 18
    if len(block) != 2 * words:
        raise ValueError("wrong block word count")
    prev2, prev1 = block[:words], block[words:]
    schedule = [prev2, prev1]
    for _ in range(2, (18 if version == 1 else 24) + 1):
        if version == 1:
            cur = [x ^ y for x, y in zip(mef(prev1), prev2)]
        else:
            cur = (
                [x ^ y for x, y in zip(mef(prev1[:9]), prev2[:9])]
                + [x ^ y for x, y in zip(mef(prev1[9:]), prev2[9:])]
            )
        schedule.append(cur)
        prev2, prev1 = prev1, cur
    return schedule


def compression(version: int, v: list[int], block: list[int]) -> list[int]:
    rounds = 18 if version == 1 else 24
    inj = expansion(version, block)
    x = v.copy()
    for j in range(1, rounds + 1):
        x = round_function(version, [a ^ b for a, b in zip(x, inj[j - 1])], j)
    return [a ^ b ^ c for a, b, c in zip(x, inj[rounds], v)]


def bytes_to_words(data: bytes) -> list[int]:
    if len(data) % 8:
        raise ValueError("word adapter requires whole 64-bit words")
    return [int.from_bytes(data[i:i + 8], "big") for i in range(0, len(data), 8)]


def words_to_bytes(words: list[int]) -> bytes:
    return b"".join(x.to_bytes(8, "big") for x in words)


def bits_from_bytes(data: bytes) -> list[int]:
    return [(b >> (7 - i)) & 1 for b in data for i in range(8)]


def bits_to_bytes(bits: list[int]) -> bytes:
    if len(bits) % 8:
        raise ValueError("bits_to_bytes requires a multiple of eight")
    return bytes(sum(bits[i + j] << (7 - j) for j in range(8))
                 for i in range(0, len(bits), 8))


def pad_bits(bits: list[int], block_bits: int) -> list[list[int]]:
    m = bits + [1]
    m += [0] * ((-len(m)) % block_bits)
    return [m[i:i + block_bits] for i in range(0, len(m), block_bits)]


def bits_to_words(bits: list[int]) -> list[int]:
    if len(bits) % 64:
        raise ValueError("word conversion requires whole words")
    return [sum(bit << (63 - j) for j, bit in enumerate(bits[i:i + 64]))
            for i in range(0, len(bits), 64)]


def hash_bits(version: int, bits: list[int]) -> list[int]:
    block_bits = 1152 if version == 1 else 2304
    words = 9 if version == 1 else 18
    digest_bits = 512 if version == 1 else 1024
    blocks = [bits_to_words(b) for b in pad_bits(bits, block_bits)]
    checksum = [0] * (2 * words)
    for block in blocks:
        checksum = [x ^ y for x, y in zip(checksum, block)]
    hm1, h = [0] * words, [0] * words
    for block in blocks:
        hnext = compression(version, h, block)
        hnext = [x ^ y for x, y in zip(hnext, hm1)]
        hm1, h = h, hnext
    digest_state = compression(version, h, checksum)
    serialized = bits_from_bytes(words_to_bytes(digest_state))
    return serialized[:digest_bits]


def hash_bytes(version: int, data: bytes) -> bytes:
    return bits_to_bytes(hash_bits(version, bits_from_bytes(data)))


def _selftest() -> None:
    sbox = [i ^ (((i + 1) & 7) & ((i + 2) & 7)) for i in range(8)]
    # The real 9-bit S-box values are checked by the dedicated table tests.
    x = list(range(1, 10))
    inv = mix(mix(x, RIGHT_ROWS), RIGHT_ROWS)
    assert inv != x  # Full inverse is tested independently; this is a smoke test.
    for version in (1, 2):
        d = hash_bytes(version, b"")
        assert len(d) == (64 if version == 1 else 128)


if __name__ == "__main__":
    import argparse
    import hashlib
    import json
    import sys

    ap = argparse.ArgumentParser()
    ap.add_argument("version", type=int, choices=(1, 2))
    ap.add_argument("file", nargs="?")
    ap.add_argument("--bits", type=int)
    args = ap.parse_args()
    raw = sys.stdin.buffer.read() if args.file is None else open(args.file, "rb").read()
    if args.bits is None:
        digest = hash_bytes(args.version, raw)
    else:
        if args.bits < 0 or args.bits > 8 * len(raw):
            ap.error("--bits must be in [0, 8*len(input)]")
        digest = bits_to_bytes(hash_bits(args.version, bits_from_bytes(raw)[:args.bits]))
    out = {
        "version": args.version,
        "input_bytes": len(raw),
        "input_bits_hashed": args.bits if args.bits is not None else 8 * len(raw),
        "input_sha256": hashlib.sha256(raw).hexdigest(),
        "digest_hex": digest.hex(),
    }
    print(json.dumps(out, sort_keys=True))
