#!/usr/bin/env python3
"""Exact checker for JuziHash Appendix B initial-state disambiguation.

The state is always the serialized byte array X[0..255].
Interpretation A is the Section 3.3 changing-axis MDS convention.
Interpretation B is the Appendix A.3 fixed S0..S3 / S4..S7 convention.
Both use the same A.4 byte permutation, round constants, S-box, and modes.
"""

from __future__ import annotations

import hashlib
import sys


S4 = [9, 0, 4, 11, 13, 12, 3, 15, 1, 10, 2, 6, 7, 5, 8, 14]

MDS = (
    (0x02, 0x03, 0x01, 0x01),
    (0x01, 0x02, 0x03, 0x01),
    (0x01, 0x01, 0x02, 0x03),
    (0x03, 0x01, 0x01, 0x02),
)

RC0_WORDS = (
    0x243F6A8885A308D3,
    0x13198A2E03707344,
    0xA4093822299F31D0,
    0x082EFA98EC4E6C89,
    0x452821E638D01377,
    0xBE5466CF34E90C6C,
    0xC0AC29B7C97C50DD,
    0x3F84D5B5B5470917,
)

PUBLISHED_512 = bytes.fromhex(
    "da67341bc43d1f97c385e99bae65d59ecf1d960ddae77906a6f4f96b4a8d26c3"
    "f6f3a1b21344279d68f1a22f031e7702e503ea25cbf5de3045b447ac973299c4"
    "15b574d6cbc33ac2a9b87cc493982423723b518e2f48478ce904fc5c908e99d8"
    "20e4c645662371789d26650d2e8cf4cc7bb83765ec06e09cee897edb581804d3"
    "f56cefad4827374ae8b8365c0c8742890a131c0f8b60a42742f9810ac9a00813"
    "db3122544422ca4b6d1376c3c45080bd43445c2312d1584c228b8b11d4bc6d2f"
    "efb96f8bfb01cb43de71b14d2bbe43329306ef5f4b77a9c1f5ecfff16852d7ee"
    "ab6ff3fe5c5b1080fe597713aa717cf5d3a033228de22e6ba05ec0a10db1abf0"
)

PUBLISHED_1024 = bytes.fromhex(
    "66fa3243c9c144bfdceecfd1e789432d4a102929d5670e9f1d130a72e67dcdad"
    "40d7b941d1927a1d281654e2c4418b03f8b7d044b896e5305a383e09e22a4435"
    "049e741c2a29383974645e2d1c1d18bb7b3980b4ef511feec630f5a642b38045"
    "efefadd77dc32ed7bdd6fe8c3cfbe65d68490d25b61aff368fa4a61deb35c1a3"
    "9d1ca813520fe0f3708965bdd1a0680620d17ba3c76d8b98175082f4fe9ab41f"
    "fb85ba3f752cccdc3342a7a2f7fc5f79c970531329404dd9c79137d7e3bdf05a"
    "00dd6a3533a85a3071d042dd9820293434f34658f40d9676bf068d2484717e22"
    "a5a1df28b0c28afed04adfd0dcc4e8d7661ae040920585b3ba1fe24d907111fc"
)


def gf_mul(x: int, y: int) -> int:
    """Multiplication modulo x^8+x^4+x^3+x+1."""
    out = 0
    for _ in range(8):
        if y & 1:
            out ^= x
        y >>= 1
        x = ((x << 1) ^ (0x11B if x & 0x80 else 0)) & 0xFF
    return out


def sbox(x: int) -> int:
    left, right = x >> 4, x & 0x0F
    for _ in range(3):
        left, right = right, left ^ S4[right]
    return (left << 4) | right


S8 = [sbox(x) for x in range(256)]


def mds4(v: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    return tuple(
        gf_mul(row[0], v[0])
        ^ gf_mul(row[1], v[1])
        ^ gf_mul(row[2], v[2])
        ^ gf_mul(row[3], v[3])
        for row in MDS
    )


def rotl_seq(x: bytearray, start: int, length: int, n: int) -> None:
    n %= length
    if not n:
        return
    old = bytes(x[start : start + length])
    for k in range(length):
        x[start + k] = old[(k + n) % length]


def byte_permute(x: bytearray, t: int) -> None:
    """Appendix A.4, using serialized S_i,j = X[32*i+j]."""
    if t % 3 == 0:
        for i in range(8):
            for g in range(8):
                rotl_seq(x, 32 * i + 4 * g, 4, i % 4)
    elif t % 3 == 1:
        for i in range(8):
            for g in range(2):
                rotl_seq(x, 32 * i + 16 * g, 16, 4 * (i % 4))
    else:
        for i in range(4):
            n = 16 * i
            if n:
                # The pair is the noncontiguous serialized word pair S_i||S_i+4.
                old = bytes(x[32 * i : 32 * (i + 1)]) + bytes(
                    x[32 * (i + 4) : 32 * (i + 5)]
                )
                for k in range(64):
                    dst = 32 * i + k if k < 32 else 32 * (i + 4) + k - 32
                    x[dst] = old[(k + n) % 64]


def mds_a(x: bytearray, t: int) -> None:
    """Section 3.3 changing-axis MDS in serialized T order."""
    axis = (3 - t) % 4
    strides = (64, 16, 4, 1)
    stride = strides[axis]
    for base in range(256):
        # Visit exactly the smallest member of each line in this axis.
        coord = (base // 64, (base // 16) % 4, (base // 4) % 4, base % 4)
        if coord[axis] != 0:
            continue
        idx = [base + k * stride for k in range(4)]
        vals = tuple(x[p] for p in idx)
        out = mds4(vals)
        for p, v in zip(idx, out):
            x[p] = v


def mds_b(x: bytearray, _t: int) -> None:
    """Appendix A.3 fixed S0..S3/S4..S7 MDS convention."""
    for block in (0, 4):
        for j in range(32):
            idx = [32 * (block + r) + j for r in range(4)]
            vals = tuple(x[p] for p in idx)
            out = mds4(vals)
            for p, v in zip(idx, out):
                x[p] = v


def rotl64(v: int, k: int) -> int:
    return ((v << k) | (v >> (64 - k))) & ((1 << 64) - 1)


def constants() -> list[bytes]:
    words = list(RC0_WORDS)
    out = []
    for _ in range(6):
        out.append(b"".join(w.to_bytes(8, "big") for w in words) + bytes(192))
        words = [
            rotl64(w, 3) ^ rotl64(w, 7) ^ rotl64(w, 12)
            for w in words
        ]
    return out


def permute(state: bytes, which: str) -> tuple[bytes, list[str]]:
    x = bytearray(state)
    layer = mds_a if which == "A" else mds_b
    round_hashes = []
    rcs = constants()
    for t in range(24):
        if t % 4 == 0:
            rc = rcs[t // 4]
            for j in range(256):
                x[j] ^= rc[j]
        for j in range(256):
            x[j] = S8[x[j]]
        layer(x, t)
        byte_permute(x, t)
        round_hashes.append(
            hashlib.sha256(bytes(x[:16])).hexdigest()[:16]
            + " | "
            + hashlib.sha256(bytes(x)).hexdigest()[:16]
        )
    return bytes(x), round_hashes


def h_minus_one(digest_size: int) -> bytes:
    size = digest_size.to_bytes(2, "big")
    return size + bytes(254)


def update_1024(previous: bytes, permuted: bytes) -> bytes:
    out = bytearray(permuted)
    # Capacity positions S2,S3,S6,S7 are xored with the old capacity.
    for word in (2, 3, 6, 7):
        for j in range(32):
            out[32 * word + j] ^= previous[32 * word + j]
    return bytes(out)


def first_difference(a: bytes, b: bytes) -> int | None:
    return next((i for i, (p, q) in enumerate(zip(a, b)) if p != q), None)


def hamming_bits(a: bytes, b: bytes) -> int:
    return sum((p ^ q).bit_count() for p, q in zip(a, b))


def run() -> int:
    expected = {512: PUBLISHED_512, 1024: PUBLISHED_1024}
    results: dict[tuple[int, str], bytes] = {}
    hashes: dict[tuple[int, str], str] = {}
    for size in (512, 1024):
        for which in ("A", "B"):
            permuted, rounds = permute(h_minus_one(size), which)
            result = permuted if size == 512 else update_1024(h_minus_one(size), permuted)
            results[size, which] = result
            hashes[size, which] = hashlib.sha256(result).hexdigest()
            print(f"{size}/{which}: sha256={hashes[size, which]}")
            print("  round hashes (first-16 | full): " + ", ".join(rounds))
            d = first_difference(result, expected[size])
            print(
                f"  vs Appendix B: equal={result == expected[size]} "
                f"first_diff={d} differing_bits={hamming_bits(result, expected[size])} "
                f"matching_bytes={sum(a == b for a, b in zip(result, expected[size]))}/256"
            )
            if size == 512:
                print(f"  first 32 bytes: {result[:32].hex()}")
            else:
                # Digest of the fDM state is its capacity projection.
                print(
                    "  first 32 capacity bytes: "
                    f"{(result[64:96] + result[192:224]).hex()}"
                )

        da = first_difference(results[size, "A"], results[size, "B"])
        print(
            f"{size}/A-vs-B: equal={results[size, 'A'] == results[size, 'B']} "
            f"first_diff={da} differing_bits="
            f"{hamming_bits(results[size, 'A'], results[size, 'B'])}"
        )

    ok = all(results[size, "B"] == expected[size] for size in (512, 1024))
    different = all(results[size, "A"] != expected[size] for size in (512, 1024))
    print(f"VERDICT: B_reproduces_both={ok}; A_fails_both={different}")
    return 0 if ok and different else 1


if __name__ == "__main__":
    sys.exit(run())
