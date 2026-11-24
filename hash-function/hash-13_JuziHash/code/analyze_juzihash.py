from __future__ import annotations

import re
import hashlib
from pathlib import Path


S4 = [9, 0, 4, 11, 13, 12, 3, 15, 1, 10, 2, 6, 7, 5, 8, 14]

INITIAL_RC = [
    0x243F6A8885A308D3,
    0x13198A2E03707344,
    0xA4093822299F31D0,
    0x082EFA98EC4E6C89,
    0x452821E638D01377,
    0xBE5466CF34E90C6C,
    0xC0AC29B7C97C50DD,
    0x3F84D5B5B5470917,
]

PUBLISHED = {
    512: """da67341b c43d1f97 c385e99b ae65d59e cf1d960d dae77906 a6f4f96b 4a8d26c3
f6f3a1b2 1344279d 68f1a22f 031e7702 e503ea25 cbf5de30 45b447ac 973299c4
15b574d6 cbc33ac2 a9b87cc4 93982423 723b518e 2f48478c e904fc5c 908e99d8
20e4c645 66237178 9d26650d 2e8cf4cc 7bb83765 ec06e09c ee897edb 581804d3
f56cefad 4827374a e8b8365c 0c874289 0a131c0f 8b60a427 42f9810a c9a00813
db312254 4422ca4b 6d1376c3 c45080bd 43445c23 12d1584c 228b8b11 d4bc6d2f
efb96f8b fb01cb43 de71b14d 2bbe4332 9306ef5f 4b77a9c1 f5ecfff1 6852d7ee
ab6ff3fe 5c5b1080 fe597713 aa717cf5 d3a03322 8de22e6b a05ec0a1 0db1abf0""",
    1024: """66fa3243 c9c144bf dceecfd1 e789432d 4a102929 d5670e9f 1d130a72 e67dcdad
40d7b941 d1927a1d 281654e2 c4418b03 f8b7d044 b896e530 5a383e09 e22a4435
049e741c 2a293839 74645e2d 1c1d18bb 7b3980b4 ef511fee c630f5a6 42b38045
efefadd7 7dc32ed7 bdd6fe8c 3cfbe65d 68490d25 b61aff36 8fa4a61d eb35c1a3
9d1ca813 520fe0f3 708965bd d1a06806 20d17ba3 c76d8b98 175082f4 fe9ab41f
fb85ba3f 752cccdc 3342a7a2 f7fc5f79 c9705313 29404dd9 c79137d7 e3bdf05a
00dd6a35 33a85a30 71d042dd 98202934 34f34658 f40d9676 bf068d24 84717e22
a5a1df28 b0c28afe d04adfd0 dcc4e8d7 661ae040 920585b3 ba1fe24d 907111fc""",
}


def published(bits: int) -> bytes:
    return bytes.fromhex(PUBLISHED[bits])


def xtime(x: int) -> int:
    return ((x << 1) ^ (0x11B if x & 0x80 else 0)) & 0xFF


def mul(a: int, b: int) -> int:
    out = 0
    while b:
        if b & 1:
            out ^= a
        a = xtime(a)
        b >>= 1
    return out


def sbox(x: int) -> int:
    left, right = x >> 4, x & 0xF
    left, right = right, left ^ S4[right]
    left, right = right, left ^ S4[right]
    left, right = right, left ^ S4[right]
    return (left << 4) | right


def add_rc(state: bytearray, group: int) -> None:
    words = INITIAL_RC[:]
    for _ in range(group):
        words = [
            ((w << 3) | (w >> 61)) ^ ((w << 7) | (w >> 57)) ^ ((w << 12) | (w >> 52))
            for w in words
        ]
        words = [w & 0xFFFFFFFFFFFFFFFF for w in words]
    rc = b"".join(w.to_bytes(8, "big") for w in words)
    state[:64] = bytes(a ^ b for a, b in zip(state[:64], rc))


def mds(state: bytearray) -> None:
    for base in (0, 128):
        old = state[base : base + 128]
        for j in range(32):
            x0, x1, x2, x3 = (old[r * 32 + j] for r in range(4))
            state[base + j] = mul(2, x0) ^ mul(3, x1) ^ x2 ^ x3
            state[base + 32 + j] = x0 ^ mul(2, x1) ^ mul(3, x2) ^ x3
            state[base + 64 + j] = x0 ^ x1 ^ mul(2, x2) ^ mul(3, x3)
            state[base + 96 + j] = mul(3, x0) ^ x1 ^ x2 ^ mul(2, x3)


def mds_axis(state: bytearray, axis: int) -> None:
    old = bytes(state)
    for a in range(4):
        for b in range(4):
            for c in range(4):
                for d in range(4):
                    coord = [a, b, c, d]
                    values = []
                    positions = []
                    for k in range(4):
                        coord[axis] = k
                        aa, bb, cc, dd = coord
                        positions.append(64 * aa + 16 * bb + 4 * cc + dd)
                        values.append(old[positions[-1]])
                    x0, x1, x2, x3 = values
                    outputs = (
                        mul(2, x0) ^ mul(3, x1) ^ x2 ^ x3,
                        x0 ^ mul(2, x1) ^ mul(3, x2) ^ x3,
                        x0 ^ x1 ^ mul(2, x2) ^ mul(3, x3),
                        mul(3, x0) ^ x1 ^ x2 ^ mul(2, x3),
                    )
                    for j, value in zip(positions, outputs):
                        state[j] = value


def rot_slice(buf: bytearray, lo: int, size: int, shift: int) -> None:
    if not shift:
        return
    chunk = buf[lo : lo + size]
    for k, value in enumerate(chunk):
        buf[lo + (k - shift) % size] = value


def byte_perm(state: bytearray, t: int) -> None:
    if t % 3 == 0:
        for i in range(8):
            for group in range(8):
                rot_slice(state, 32 * i + 4 * group, 4, i % 4)
    elif t % 3 == 1:
        for i in range(8):
            for group in range(2):
                rot_slice(state, 32 * i + 16 * group, 16, 4 * (i % 4))
    else:
        for i in range(1, 4):
            pair = bytearray(state[32 * i : 32 * i + 32] + state[32 * (i + 4) : 32 * (i + 5)])
            shift = 16 * i
            pair[:] = pair[shift:] + pair[:shift]
            state[32 * i : 32 * i + 32] = pair[:32]
            state[32 * (i + 4) : 32 * (i + 5)] = pair[32:]


def permutation(state: bytes | bytearray, changing_axis: bool = False) -> bytearray:
    out = bytearray(state)
    for t in range(24):
        if t % 4 == 0:
            add_rc(out, t // 4)
        out[:] = bytes(sbox(x) for x in out)
        if changing_axis:
            mds_axis(out, (3 - t) % 4)
        else:
            mds(out)
        byte_perm(out, t)
    return out


def initial_state(digest_bits: int, changing_axis: bool = False) -> bytes:
    hminus1 = bytearray(256)
    hminus1[0:2] = digest_bits.to_bytes(2, "big")
    y = permutation(hminus1, changing_axis=changing_axis)
    if digest_bits == 512:
        return bytes(y)
    previous = hminus1
    result = bytearray(y)
    for base in (64, 96, 192, 224):
        for j in range(32):
            result[base + j] ^= previous[base + j]
    return bytes(result)


def padded_blocks(message: bytes) -> list[bytes]:
    bit_length = len(message) * 8
    zero_bytes = (-len(message)) % 128
    extended = message + bytes(zero_bytes)
    tail = (bit_length).to_bytes(128, "big")
    return [extended[i : i + 128] for i in range(0, len(extended), 128)] + [tail]


def update(state: bytes, block: bytes, digest_bits: int, changing_axis: bool) -> bytes:
    injected = bytearray(state)
    for base, word in zip((0, 32, 128, 160), range(4)):
        injected[base : base + 32] = bytes(
            a ^ b for a, b in zip(injected[base : base + 32], block[32 * word : 32 * (word + 1)])
        )
    permuted = permutation(injected, changing_axis=changing_axis)
    if digest_bits == 512:
        return bytes(permuted)
    result = bytearray(permuted)
    for base in (64, 96, 192, 224):
        result[base : base + 32] = bytes(
            a ^ b for a, b in zip(permuted[base : base + 32], state[base : base + 32])
        )
    return bytes(result)


def hash_message(message: bytes, digest_bits: int, changing_axis: bool = False) -> bytes:
    state = initial_state(digest_bits, changing_axis=changing_axis)
    for block in padded_blocks(message):
        state = update(state, block, digest_bits, changing_axis)
    if digest_bits == 512:
        return state[:64]
    return state[64:128] + state[192:256]


def hexdiff(got: bytes, want: bytes) -> tuple[int, list[int]]:
    diffs = [i for i, (a, b) in enumerate(zip(got, want)) if a != b]
    return len(diffs), diffs[:20]


def main() -> None:
    for bits in (512, 1024):
        got = initial_state(bits)
        want = published(bits)
        count, first = hexdiff(got, want)
        print("variant", bits)
        print("mismatched_bytes", count)
        print("first_mismatches", first)
        for i in first[:4]:
            print(i, f"got={got[i]:02x}", f"want={want[i]:02x}")
        changed = initial_state(bits, changing_axis=True)
        print("appendix_hash", hashlib.sha256(got).hexdigest())
        print("changing_axis_hash", hashlib.sha256(changed).hexdigest())
        for message in (b"", b"abc"):
            print(
                "message", repr(message),
                "appendix_digest", hash_message(message, bits).hex(),
                "changing_axis_digest", hash_message(message, bits, True).hex(),
            )


if __name__ == "__main__":
    main()
