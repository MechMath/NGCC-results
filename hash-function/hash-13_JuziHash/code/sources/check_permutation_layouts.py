#!/usr/bin/env python3
"""Local checks for the competing JuziHash permutation layouts.

This is a researcher artifact, not verification evidence.  It implements the
explicitly specified S-box, MixColumns matrix, byte permutations, round
constants, and message injection, and compares the two stated MDS layouts.
"""

from __future__ import annotations

import argparse
import json


S4 = [9, 0, 4, 11, 13, 12, 3, 15, 1, 10, 2, 6, 7, 5, 8, 14]


def make_s8() -> list[int]:
    out = []
    for value in range(256):
        left, right = value >> 4, value & 15
        for _ in range(3):
            left, right = right, left ^ S4[right]
        out.append((left << 4) | right)
    assert sorted(out) == list(range(256))
    return out


S8 = make_s8()


def gf_mul(left: int, right: int) -> int:
    result = 0
    for _ in range(8):
        if right & 1:
            result ^= left
        right >>= 1
        left = ((left << 1) ^ 0x11B) if left & 0x80 else left << 1
    return result & 0xFF


def mix_column(values: list[int]) -> list[int]:
    x0, x1, x2, x3 = values
    return [
        gf_mul(2, x0) ^ gf_mul(3, x1) ^ x2 ^ x3,
        x0 ^ gf_mul(2, x1) ^ gf_mul(3, x2) ^ x3,
        x0 ^ x1 ^ gf_mul(2, x2) ^ gf_mul(3, x3),
        gf_mul(3, x0) ^ x1 ^ x2 ^ gf_mul(2, x3),
    ]


def index_of(a: int, b: int, c: int, d: int) -> int:
    return 64 * a + 16 * b + 4 * c + d


def mds_main_text(state: list[int], round_index: int) -> list[int]:
    """Section 3.3: MDS along dimension (3-round_index) mod 4."""
    axis = (3 - round_index) % 4
    out = state[:]
    for i0 in range(4):
        for i1 in range(4):
            for i2 in range(4):
                coords = [i0, i1, i2]
                indices = []
                for coordinate in range(4):
                    full = coords[:]
                    full.insert(axis, coordinate)
                    indices.append(index_of(*full))
                for index, value in zip(
                    indices, mix_column([state[index] for index in indices])
                ):
                    out[index] = value
    return out


def mds_appendix(
    state: list[int], round_index: int | None = None
) -> list[int]:
    """Appendix A.3: fixed MDS on S0..S3 and S4..S7 at each byte position."""
    del round_index
    out = state[:]
    for byte_position in range(32):
        for base in (0, 128):
            indices = [
                base + byte_position,
                base + 32 + byte_position,
                base + 64 + byte_position,
                base + 96 + byte_position,
            ]
            for index, value in zip(
                indices, mix_column([state[index] for index in indices])
            ):
                out[index] = value
    return out


def byte_permute(state: list[int], round_index: int) -> list[int]:
    """Appendix A.4 byte permutation on the eight 32-byte words."""
    out = state[:]
    residue = round_index % 3
    if residue == 0:
        for word in range(8):
            shift = word % 4
            for group in range(8):
                indices = [32 * word + 4 * group + j for j in range(4)]
                values = [state[index] for index in indices]
                values = values[shift:] + values[:shift]
                for index, value in zip(indices, values):
                    out[index] = value
    elif residue == 1:
        for word in range(8):
            shift = 4 * (word % 4)
            for group in range(2):
                indices = [32 * word + 16 * group + j for j in range(16)]
                values = [state[index] for index in indices]
                values = values[shift:] + values[:shift]
                for index, value in zip(indices, values):
                    out[index] = value
    else:
        for word in range(4):
            indices = [32 * word + j for j in range(32)]
            indices += [32 * (word + 4) + j for j in range(32)]
            shift = 16 * word
            values = [state[index] for index in indices]
            values = values[shift:] + values[:shift]
            for index, value in zip(indices, values):
                out[index] = value
    return out


RC_WORDS_0 = [
    0x243F6A8885A308D3,
    0x13198A2E03707344,
    0xA4093822299F31D0,
    0x082EFA98EC4E6C89,
    0x452821E638D01377,
    0xBE5466CF34E90C6C,
    0xC0AC29B7C97C50DD,
    0x3F84D5B5B5470917,
]


def rotl64(value: int, amount: int) -> int:
    return ((value << amount) | (value >> (64 - amount))) & ((1 << 64) - 1)


def round_constants(count: int) -> list[bytes]:
    words = RC_WORDS_0[:]
    out = []
    for _ in range(count):
        out.append(b"".join(word.to_bytes(8, "big") for word in words))
        words = [
            rotl64(word, 3) ^ rotl64(word, 7) ^ rotl64(word, 12)
            for word in words
        ]
    return out


def permute(state: list[int], layout: str, rounds: int = 24) -> list[int]:
    assert rounds % 4 == 0
    mds = mds_main_text if layout == "main" else mds_appendix
    state = state[:]
    constants = round_constants(rounds // 4)
    for round_index in range(rounds):
        if round_index % 4 == 0:
            for index, value in enumerate(constants[round_index // 4]):
                state[index] ^= value
        state = [S8[value] for value in state]
        state = mds(state, round_index)
        state = byte_permute(state, round_index)
    return state


def initial_state(variant: str, layout: str) -> bytes:
    state = [0] * 256
    state[0] = 0x02 if variant == "512" else 0x04
    permuted = permute(state, layout)
    if variant == "512":
        return bytes(permuted)
    output = permuted[:]
    # H = f_DM(H(-1), 0): preserve the rate; feed the old capacity forward.
    for index in (2, 3, 6, 7):
        for byte in range(32):
            output[32 * index + byte] ^= state[32 * index + byte]
    return bytes(output)


def inject_message(state: list[int], block: bytes) -> list[int]:
    assert len(block) == 128
    out = state[:]
    out[0:32] = bytes(a ^ b for a, b in zip(out[0:32], block[0:32]))
    out[32:64] = bytes(a ^ b for a, b in zip(out[32:64], block[32:64]))
    out[128:160] = bytes(a ^ b for a, b in zip(out[128:160], block[64:96]))
    out[160:192] = bytes(a ^ b for a, b in zip(out[160:192], block[96:128]))
    return out


def hash_message(variant: str, message: bytes, layout: str) -> bytes:
    """Hash a byte-aligned message with the specified permutation layout."""
    bit_length = 8 * len(message)
    if bit_length >= 1 << 64:
        raise ValueError("message length exceeds the supported domain")
    zero_bits = (-bit_length) % 1024
    assert zero_bits % 8 == 0
    padded = message + bytes(zero_bits // 8)
    padded += bytes(120) + bit_length.to_bytes(8, "big")
    assert len(padded) % 128 == 0

    state = list(initial_state(variant, "appendix"))
    for offset in range(0, len(padded), 128):
        old = state
        permuted = permute(inject_message(old, padded[offset : offset + 128]), layout)
        if variant == "512":
            state = permuted
        else:
            state = permuted
            for word in (2, 3, 6, 7):
                start = 32 * word
                for byte in range(start, start + 32):
                    state[byte] ^= old[byte]
    if variant == "512":
        return bytes(state[:64])
    return b"".join(bytes(state[32 * word : 32 * word + 32]) for word in (2, 3, 6, 7))


EXPECTED = {
    "512": bytes.fromhex(
        "da67341b c43d1f97 c385e99b ae65d59e "
        "cf1d960d dae77906 a6f4f96b 4a8d26c3 "
        "f6f3a1b2 1344279d 68f1a22f 031e7702 "
        "e503ea25 cbf5de30 45b447ac 973299c4 "
        "15b574d6 cbc33ac2 a9b87cc4 93982423 "
        "723b518e 2f48478c e904fc5c 908e99d8 "
        "20e4c645 66237178 9d26650d 2e8cf4cc "
        "7bb83765 ec06e09c ee897edb 581804d3 "
        "f56cefad 4827374a e8b8365c 0c874289 "
        "0a131c0f 8b60a427 42f9810a c9a00813 "
        "db312254 4422ca4b 6d1376c3 c45080bd "
        "43445c23 12d1584c 228b8b11 d4bc6d2f "
        "efb96f8b fb01cb43 de71b14d 2bbe4332 "
        "9306ef5f 4b77a9c1 f5ecfff1 6852d7ee "
        "ab6ff3fe 5c5b1080 fe597713 aa717cf5 "
        "d3a03322 8de22e6b a05ec0a1 0db1abf0"
    ),
    "1024": bytes.fromhex(
        "66fa3243 c9c144bf dceecfd1 e789432d "
        "4a102929 d5670e9f 1d130a72 e67dcdad "
        "40d7b941 d1927a1d 281654e2 c4418b03 "
        "f8b7d044 b896e530 5a383e09 e22a4435 "
        "049e741c 2a293839 74645e2d 1c1d18bb "
        "7b3980b4 ef511fee c630f5a6 42b38045 "
        "efefadd7 7dc32ed7 bdd6fe8c 3cfbe65d "
        "68490d25 b61aff36 8fa4a61d eb35c1a3 "
        "9d1ca813 520fe0f3 708965bd d1a06806 "
        "20d17ba3 c76d8b98 175082f4 fe9ab41f "
        "fb85ba3f 752cccdc 3342a7a2 f7fc5f79 "
        "c9705313 29404dd9 c79137d7 e3bdf05a "
        "00dd6a35 33a85a30 71d042dd 98202934 "
        "34f34658 f40d9676 bf068d24 84717e22 "
        "a5a1df28 b0c28afe d04adfd0 dcc4e8d7 "
        "661ae040 920585b3 ba1fe24d 907111fc"
    ),
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    results = {}
    for variant in ("512", "1024"):
        for layout in ("main", "appendix"):
            actual = initial_state(variant, layout)
            expected = EXPECTED[variant]
            differing = [
                index for index, (left, right) in enumerate(zip(actual, expected))
                if left != right
            ]
            results[f"{variant}-{layout}"] = {
                "match": actual == expected,
                "differing_byte_count": len(differing),
                "first_differences": [
                    {
                        "offset": index,
                        "actual": f"{actual[index]:02x}",
                        "expected": f"{expected[index]:02x}",
                    }
                    for index in differing[:16]
                ],
                "actual_sha256": __import__("hashlib").sha256(actual).hexdigest(),
                "actual_prefix": actual[:32].hex(),
            }
    for variant in ("512", "1024"):
        for message in (b"", b"abc"):
            digests = {
                layout: hash_message(variant, message, layout).hex()
                for layout in ("main", "appendix")
            }
            results[f"{variant}-message-{message.hex() or 'empty'}"] = {
                "digests": digests,
                "equal": digests["main"] == digests["appendix"],
            }
    print(json.dumps(results, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
