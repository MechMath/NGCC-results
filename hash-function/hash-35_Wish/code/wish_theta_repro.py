#!/usr/bin/env python3
"""Independent finite reproducer for the two theta readings in Wish v1.0.

The specification constants are transcribed from:
  hash-35-spec.pdf (pinned in the task), printed pp. 4--8.
  SHA-256 a84b946a93f0fe772c1b08d29c90f894d928ea13cef9ee6ed1fd2fdee118dd2c

This is an implementation of the printed specification, not an official
implementation.  Run with no arguments for JSON output; ``--out PATH`` also
writes that JSON to PATH.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path
from typing import Callable


SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16"
)

# Table 3, printed p. 7.  The PDF prints two 12-row columns.
RCON = [
    bytes.fromhex(x)
    for x in (
        "243f6a8885a308d313198a2e03707344",
        "497fd5110b4610a72632155d06e1e788",
        "92ffab22168c204e4d652aba0cc2ce11",
        "25fe56452c19419c9acb557418859d22",
        "4bfcac8a593282393597aae9300b3b45",
        "96f85815b26505736b2f54d26116778a",
        "2df0b02a64cb0ae7d75fa8a5c32cef15",
        "5be06055c99714ceafbe504a8759de2a",
        "b6c0c1aa932f289d5e7ca0940fb2bd55",
        "6c818354275f513bbcf940291e647aaa",
        "d90307a84fbea27778f280533cc9f554",
        "b3060e509e7c44eff1e401a67993eaa8",
        "660c1ca03df988dee2c8024cf327d450",
        "cd1838407bf211bdc4910498e64fa9a0",
        "9b307180f7e4227a89230831cc9e5240",
        "3761e301eec845f513471063993da480",
        "6fc3c602dc918aea268e20c7337b4801",
        "df878d04b92315d44d1d418f67f79002",
        "bf0f1b0872472aa99a3a821fcfee2104",
        "7e1e3610e58e55523575053e9fdc4308",
        "fd3c6d20ca1daaa46beb0a7d3fb98610",
        "fa79db41953a5448d7d614fb7f720d20",
        "f4f3b7822b75a890afad28f6ffe51a41",
        "e8e66e0557eb50215e5a51ecfeca3482",
    )
]


def _rows(rows: tuple[tuple[int, ...], ...]) -> tuple[int, ...]:
    out = tuple(x for row in rows for x in row)
    assert sorted(out) == list(range(len(out)))
    return out


# Equations (2) and (3), printed p. 6.  For output byte i, entry i is
# the input-byte position supplying it.
MIX1024 = _rows(
    (
        (0,16,32,48,1,17,33,49,64,80,96,112,65,81,97,113),
        (8,24,40,56,9,25,41,57,72,88,104,120,73,89,105,121),
        (4,20,36,52,5,21,37,53,68,84,100,116,69,85,101,117),
        (12,28,44,60,13,29,45,61,76,92,108,124,77,93,109,125),
        (2,18,34,50,3,19,35,51,66,82,98,114,67,83,99,115),
        (10,26,42,58,11,27,43,59,74,90,106,122,75,91,107,123),
        (6,22,38,54,7,23,39,55,70,86,102,118,71,87,103,119),
        (14,30,46,62,15,31,47,63,78,94,110,126,79,95,111,127),
    )
)

MIX2048 = _rows(
    (
        (0,16,32,48,64,80,96,112,128,144,160,176,192,208,224,240),
        (8,24,40,56,72,88,104,120,136,152,168,184,200,216,232,248),
        (4,20,36,52,68,84,100,116,132,148,164,180,196,212,228,244),
        (12,28,44,60,76,92,108,124,140,156,172,188,204,220,236,252),
        (2,18,34,50,66,82,98,114,130,146,162,178,194,210,226,242),
        (10,26,42,58,74,90,106,122,138,154,170,186,202,218,234,250),
        (6,22,38,54,70,86,102,118,134,150,166,182,198,214,230,246),
        (14,30,46,62,78,94,110,126,142,158,174,190,206,222,238,254),
        (1,17,33,49,65,81,97,113,129,145,161,177,193,209,225,241),
        (9,25,41,57,73,89,105,121,137,153,169,185,201,217,233,249),
        (5,21,37,53,69,85,101,117,133,149,165,181,197,213,229,245),
        (13,29,45,61,77,93,109,125,141,157,173,189,205,221,237,253),
        (3,19,35,51,67,83,99,115,131,147,163,179,195,211,227,243),
        (11,27,43,59,75,91,107,123,139,155,171,187,203,219,235,251),
        (7,23,39,55,71,87,103,119,135,151,167,183,199,215,231,247),
        (15,31,47,63,79,95,111,127,143,159,175,191,207,223,239,255),
    )
)


def gf_mul(a: int, b: int) -> int:
    """Multiplication in GF(2)[x]/(x^8+x^4+x^3+x+1)."""
    z = 0
    for _ in range(8):
        if b & 1:
            z ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return z


def generated_aes_sbox() -> bytes:
    # In GF(256), a^254 is the multiplicative inverse for a != 0.
    inv = [0] + [pow_gf(a, 254) for a in range(1, 256)]
    out = []
    for x in inv:
        # AES affine transform x -> x xor rotl(x,1) xor ... xor rotl(x,4) xor 0x63.
        y = x ^ rotl8(x, 1) ^ rotl8(x, 2) ^ rotl8(x, 3) ^ rotl8(x, 4) ^ 0x63
        out.append(y)
    return bytes(out)


def pow_gf(a: int, e: int) -> int:
    z = 1
    while e:
        if e & 1:
            z = gf_mul(z, a)
        a = gf_mul(a, a)
        e >>= 1
    return z


def rotl8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xFF


INV_SBOX = bytes(generated_aes_sbox().index(i) for i in range(256))


def aesr(lane: bytes) -> bytes:
    assert len(lane) == 16
    s = [SBOX[x] for x in lane]
    # ShiftRows, using byte(row, column) = row + 4*column.
    t = [0] * 16
    for c in range(4):
        for r in range(4):
            t[r + 4*c] = s[r + 4*((c + r) & 3)]
    out = bytearray(16)
    for c in range(4):
        a0, a1, a2, a3 = t[4 * c : 4 * c + 4]
        out[4*c:4*c+4] = bytes(
            (
                gf_mul(2, a0) ^ gf_mul(3, a1) ^ a2 ^ a3,
                a0 ^ gf_mul(2, a1) ^ gf_mul(3, a2) ^ a3,
                a0 ^ a1 ^ gf_mul(2, a2) ^ gf_mul(3, a3),
                gf_mul(3, a0) ^ a1 ^ a2 ^ gf_mul(2, a3),
            )
        )
    return bytes(out)


def aesr_inv(lane: bytes) -> bytes:
    s = bytearray(16)
    for c in range(4):
        a0, a1, a2, a3 = lane[4 * c : 4 * c + 4]
        s[4*c:4*c+4] = bytes(
            (
                gf_mul(14, a0) ^ gf_mul(11, a1) ^ gf_mul(13, a2) ^ gf_mul(9, a3),
                gf_mul(9, a0) ^ gf_mul(14, a1) ^ gf_mul(11, a2) ^ gf_mul(13, a3),
                gf_mul(13, a0) ^ gf_mul(9, a1) ^ gf_mul(14, a2) ^ gf_mul(11, a3),
                gf_mul(11, a0) ^ gf_mul(13, a1) ^ gf_mul(9, a2) ^ gf_mul(14, a3),
            )
        )
    t = bytearray(16)
    for c in range(4):
        for r in range(4):
            t[r + 4*c] = INV_SBOX[s[r + 4*((c - r) & 3)]]
    return bytes(t)


def lfsr_byte(x: int) -> int:
    return ((x << 1) & 0xFF) | (((x >> 7) ^ (x >> 5)) & 1)


def lfsr(word: bytes) -> bytes:
    return bytes(lfsr_byte(x) for x in word)


def xor(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))


def wish_perm(state: bytes, ell: int, tweak: bytes) -> bytes:
    t = {8: 9, 16: 12}[ell]
    assert len(state) == 16 * ell and len(tweak) == 16
    mix = {8: MIX1024, 16: MIX2048}[ell]
    out = bytearray(state)
    cap_lane = (ell // 2) * 16
    for j in range(t):
        out[cap_lane : cap_lane + 16] = xor(out[cap_lane : cap_lane + 16], tweak)
        for k in range(ell):
            lo = 16 * k
            out[lo : lo + 16] = aesr(out[lo : lo + 16])
        out[0:16] = xor(out[0:16], RCON[2 * j])
        for k in range(ell):
            lo = 16 * k
            out[lo : lo + 16] = aesr(out[lo : lo + 16])
        out[0:16] = xor(out[0:16], RCON[2 * j + 1])
        out = bytearray(out[p] for p in mix)
    return bytes(out)


def theta(reading: str, capacity_bytes: int) -> bytes:
    if reading == "section3.4":
        return bytes(capacity_bytes - 1) + b"\x01"
    if reading == "algorithm2":
        return b"\xff" * capacity_bytes
    raise ValueError(reading)


def wish_hash(message: bytes, ell: int, reading: str) -> bytes:
    rate_bytes = 8 * ell  # r/8; capacity has the same byte length.
    padded = bytearray(message)
    padded.append(0x80)
    padded.extend(bytes((-len(padded)) % rate_bytes))
    assert len(padded) % rate_bytes == 0
    blocks = [bytes(padded[i : i + rate_bytes]) for i in range(0, len(padded), rate_bytes)]

    state = bytes(16 * ell)
    final_mask = theta(reading, rate_bytes)
    for i, block in enumerate(blocks):
        x = bytearray(xor(state[:rate_bytes], block) + state[rate_bytes:])
        if i == len(blocks) - 1:
            x[rate_bytes:] = xor(x[rate_bytes:], final_mask)
        x = bytes(x)
        feed = x[rate_bytes:]
        tweak = i.to_bytes(8, "big") + bytes(8)
        y = wish_perm(x, ell, tweak)
        state = y[:rate_bytes] + xor(y[rate_bytes:], feed)
    return state[rate_bytes:]


def hash_reading(message: bytes, ell: int, reading: str) -> str:
    return wish_hash(message, ell, reading).hex()


def self_tests() -> dict:
    assert SBOX == generated_aes_sbox()
    assert len(set(SBOX)) == 256 and all(SBOX[SBOX[i]] != SBOX[i] for i in range(256))
    assert len(set(INV_SBOX)) == 256 and all(INV_SBOX[SBOX[i]] == i for i in range(256))
    assert all(lfsr(RCON[i - 1]) == RCON[i] for i in range(1, len(RCON)))
    assert len(set(MIX1024)) == len(MIX1024) == 128
    assert len(set(MIX2048)) == len(MIX2048) == 256

    rng = random.Random(0x57495348)
    aes_round_trips = 0
    for _ in range(2048):
        x = bytes(rng.randrange(256) for _ in range(16))
        assert aesr_inv(aesr(x)) == x
        aes_round_trips += 1

    perm_round_trips = 0
    for ell in (8, 16):
        rng = random.Random(0x1000 + ell)
        for _ in range(32):
            x = bytes(rng.randrange(256) for _ in range(16 * ell))
            tweak = bytes(rng.randrange(256) for _ in range(16))
            assert inv_perm(wish_perm(x, ell, tweak), ell, tweak) == x
            perm_round_trips += 1

    return {
        "aes_sbox_matches_field_affine_generation": True,
        "aes_sbox_bijective": True,
        "rcon_24_word_recurrence": True,
        "mix1024_is_byte_permutation": True,
        "mix2048_is_byte_permutation": True,
        "aesr_inverse_round_trips": aes_round_trips,
        "wish_permutation_inverse_round_trips": perm_round_trips,
    }


def inv_perm(y: bytes, ell: int, tweak: bytes) -> bytes:
    """Inverse of wish_perm, used only as a structural self-test."""
    t = {8: 9, 16: 12}[ell]
    mix = {8: MIX1024, 16: MIX2048}[ell]
    inv_mix = [0] * len(mix)
    for dst, src in enumerate(mix):
        inv_mix[src] = dst
    out = bytearray(y)
    cap_lane = (ell // 2) * 16
    for j in reversed(range(t)):
        out = bytearray(out[p] for p in inv_mix)
        out[0:16] = xor(out[0:16], RCON[2 * j + 1])
        for k in range(ell):
            lo = 16 * k
            out[lo : lo + 16] = aesr_inv(out[lo : lo + 16])
        out[0:16] = xor(out[0:16], RCON[2 * j])
        for k in range(ell):
            lo = 16 * k
            out[lo : lo + 16] = aesr_inv(out[lo : lo + 16])
        out[cap_lane : cap_lane + 16] = xor(out[cap_lane : cap_lane + 16], tweak)
    return bytes(out)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    messages = {
        "empty": b"",
        "nonempty_abc": b"abc",
    }
    vectors = {}
    for ell, name in ((8, "Wish-512"), (16, "Wish-1024")):
        vectors[name] = {}
        for label, message in messages.items():
            a = hash_reading(message, ell, "section3.4")
            b = hash_reading(message, ell, "algorithm2")
            vectors[name][label] = {
                "message_hex": message.hex(),
                "H_S": a,
                "H_A": b,
                "distinct": a != b,
            }
    result = {
        "specification": "hash-35-spec.pdf v1.0 pinned artifact",
        "spec_pdf_sha256": "a84b946a93f0fe772c1b08d29c90f894d928ea13cef9ee6ed1fd2fdee118dd2c",
        "implementation_status": "independent transcription; not an official implementation",
        "theta_readings": {
            "H_S": "Section 3.4: theta = 0^(c-1) || 1",
            "H_A": "Algorithm 2 line 3: theta = 1^c",
        },
        "self_tests": self_tests(),
        "vectors": vectors,
    }
    assert all(
        row["distinct"]
        for variant in vectors.values()
        for row in variant.values()
    ), "the two theta readings must yield distinct finite witnesses"
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    print(text, end="")
    if args.out:
        args.out.write_text(text)


if __name__ == "__main__":
    main()
