#!/usr/bin/env python3
"""Independent JuziHash reproduction from the allowlisted specification PDF.

This script implements two literal readings of the MDS layer:

* fixed_word: Appendix A.3, applied by byte position to word pairs (0..3)
  and (4..7).
* changing_dimension: Section 3.3, applied along T[a][b][c][d] dimension
  (3 - round) mod 4.

All other operations follow the serialized-state conventions in Appendix A.
The script emits deterministic JSON containing initialization checks, padding,
full chaining states, and published projections for empty and b"abc".
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from pathlib import Path
from typing import Callable


S4 = (9, 0, 4, 11, 13, 12, 3, 15, 1, 10, 2, 6, 7, 5, 8, 14)

RC_INITIAL_WORDS = (
    0x243F6A8885A308D3,
    0x13198A2E03707344,
    0xA4093822299F31D0,
    0x082EFA98EC4E6C89,
    0x452821E638D01377,
    0xBE5466CF34E90C6C,
    0xC0AC29B7C97C50DD,
    0x3F84D5B5B5470917,
)

PUBLISHED_H0_HEX = {
    "JuziHash-512": (
        "da67341bc43d1f97c385e99bae65d59ecf1d960ddae77906a6f4f96b4a8d26c3"
        "f6f3a1b21344279d68f1a22f031e7702e503ea25cbf5de3045b447ac973299c4"
        "15b574d6cbc33ac2a9b87cc493982423723b518e2f48478ce904fc5c908e99d8"
        "20e4c645662371789d26650d2e8cf4cc7bb83765ec06e09cee897edb581804d3"
        "f56cefad4827374ae8b8365c0c8742890a131c0f8b60a42742f9810ac9a00813"
        "db3122544422ca4b6d1376c3c45080bd43445c2312d1584c228b8b11d4bc6d2f"
        "efb96f8bfb01cb43de71b14d2bbe43329306ef5f4b77a9c1f5ecfff16852d7ee"
        "ab6ff3fe5c5b1080fe597713aa717cf5d3a033228de22e6ba05ec0a10db1abf0"
    ),
    "JuziHash-1024": (
        "66fa3243c9c144bfdceecfd1e789432d4a102929d5670e9f1d130a72e67dcdad"
        "40d7b941d1927a1d281654e2c4418b03f8b7d044b896e5305a383e09e22a4435"
        "049e741c2a29383974645e2d1c1d18bb7b3980b4ef511feec630f5a642b38045"
        "efefadd77dc32ed7bdd6fe8c3cfbe65d68490d25b61aff368fa4a61deb35c1a3"
        "9d1ca813520fe0f3708965bdd1a0680620d17ba3c76d8b98175082f4fe9ab41f"
        "fb85ba3f752cccdc3342a7a2f7fc5f79c970531329404dd9c79137d7e3bdf05a"
        "00dd6a3533a85a3071d042dd9820293434f34658f40d9676bf068d2484717e22"
        "a5a1df28b0c28afed04adfd0dcc4e8d7661ae040920585b3ba1fe24d907111fc"
    ),
}


def sbox4(value: int) -> int:
    if not 0 <= value < 16:
        raise ValueError("S4 input must be a nibble")
    return S4[value]


def sbox8(value: int) -> int:
    if not 0 <= value < 256:
        raise ValueError("S8 input must be a byte")
    left, right = value >> 4, value & 0xF
    for _ in range(3):
        left, right = right, left ^ sbox4(right)
    return (left << 4) | right


def gf_mul(left: int, right: int) -> int:
    """Multiply in F_2[z]/(z^8+z^4+z^3+z+1)."""
    product = 0
    while right:
        if right & 1:
            product ^= left
        right >>= 1
        left <<= 1
        if left & 0x100:
            left ^= 0x11B
    return product


def mds_vector(values: list[int] | bytearray) -> list[int]:
    x0, x1, x2, x3 = values
    return [
        gf_mul(2, x0) ^ gf_mul(3, x1) ^ x2 ^ x3,
        x0 ^ gf_mul(2, x1) ^ gf_mul(3, x2) ^ x3,
        x0 ^ x1 ^ gf_mul(2, x2) ^ gf_mul(3, x3),
        gf_mul(3, x0) ^ x1 ^ x2 ^ gf_mul(2, x3),
    ]


def rotate_left(values: bytearray, amount: int) -> bytearray:
    if not values:
        return values
    amount %= len(values)
    return values[amount:] + values[:amount]


def byte_permutation(state: list[bytearray], round_index: int) -> None:
    mode = round_index % 3
    if mode == 0:
        for word_index, word in enumerate(state):
            shift = word_index % 4
            for group in range(8):
                start = 4 * group
                word[start : start + 4] = rotate_left(word[start : start + 4], shift)
    elif mode == 1:
        for word_index, word in enumerate(state):
            shift = 4 * (word_index % 4)
            for group in range(2):
                start = 16 * group
                word[start : start + 16] = rotate_left(
                    word[start : start + 16], shift
                )
    else:
        for row in range(4):
            pair = state[row] + state[row + 4]
            pair = rotate_left(pair, 16 * row)
            state[row] = bytearray(pair[:32])
            state[row + 4] = bytearray(pair[32:])


def apply_fixed_word_mds(state: list[bytearray]) -> None:
    for word_base in (0, 4):
        for column in range(32):
            output = mds_vector([state[word_base + row][column] for row in range(4)])
            for row in range(4):
                state[word_base + row][column] = output[row]


def t_index(a: int, b: int, c: int, d: int) -> int:
    return 64 * a + 16 * b + 4 * c + d


def apply_changing_dimension_mds(state: list[bytearray], round_index: int) -> None:
    """Apply Appendix A.3's MDS convention along Section 3.3's chosen axis.

    The line order is increasing coordinate, while every other T coordinate is
    fixed. A single flat array is used for in-place access through t_index.
    """
    dimension = (3 - round_index) % 4
    flat = bytearray().join(state)
    for outer0 in range(4):
        for outer1 in range(4):
            for outer2 in range(4):
                coords = [outer0, outer1, outer2]
                line_indices: list[int] = []
                for line_position in range(4):
                    coords.insert(dimension, line_position)
                    line_indices.append(t_index(*coords))
                    del coords[dimension]
                output = mds_vector([flat[index] for index in line_indices])
                for index, value in zip(line_indices, output):
                    flat[index] = value
    for word_index in range(8):
        state[word_index] = flat[32 * word_index : 32 * (word_index + 1)]


def rotl64(value: int, amount: int) -> int:
    return ((value << amount) | (value >> (64 - amount))) & 0xFFFFFFFFFFFFFFFF


def round_constant(group: int) -> bytes:
    words = list(RC_INITIAL_WORDS)
    for _ in range(group):
        words = [
            rotl64(word, 3) ^ rotl64(word, 7) ^ rotl64(word, 12) for word in words
        ]
    return b"".join(word.to_bytes(8, "big") for word in words)


def permute(state: list[bytearray], mds_mode: str) -> None:
    if mds_mode not in {"fixed_word", "changing_dimension"}:
        raise ValueError(f"unknown MDS mode: {mds_mode}")
    for round_index in range(24):
        if round_index % 4 == 0:
            constant = round_constant(round_index // 4)
            state[0] = bytearray(a ^ b for a, b in zip(state[0], constant[:32]))
            state[1] = bytearray(a ^ b for a, b in zip(state[1], constant[32:]))
        for word in state:
            for index, value in enumerate(word):
                word[index] = sbox8(value)
        if mds_mode == "fixed_word":
            apply_fixed_word_mds(state)
        else:
            apply_changing_dimension_mds(state, round_index)
        byte_permutation(state, round_index)


def xor_word(word: bytearray, value: bytes) -> bytearray:
    if len(word) != len(value):
        raise ValueError("word length mismatch")
    return bytearray(a ^ b for a, b in zip(word, value))


def message_state(message_block: bytes) -> list[bytearray]:
    if len(message_block) != 128:
        raise ValueError("message block must be 1024 bits")
    return [
        bytearray(message_block[0:32]),
        bytearray(message_block[32:64]),
        bytearray(32),
        bytearray(32),
        bytearray(message_block[64:96]),
        bytearray(message_block[96:128]),
        bytearray(32),
        bytearray(32),
    ]


def fsp(state: list[bytearray], message_block: bytes, mds_mode: str) -> list[bytearray]:
    injected = message_state(message_block)
    output = [xor_word(left, right) for left, right in zip(state, injected)]
    permute(output, mds_mode)
    return output


def fdm(state: list[bytearray], message_block: bytes, mds_mode: str) -> list[bytearray]:
    output = fsp([bytearray(word) for word in state], message_block, mds_mode)
    return [
        output[0],
        output[1],
        xor_word(state[2], output[2]),
        xor_word(state[3], output[3]),
        output[4],
        output[5],
        xor_word(state[6], output[6]),
        xor_word(state[7], output[7]),
    ]


def pad_message(message: bytes) -> tuple[bytes, dict[str, int]]:
    bit_length = 8 * len(message)
    if bit_length >= 1 << 64:
        raise ValueError("message bit length is outside the supported range")
    zero_bits = (-bit_length) % 1024
    if zero_bits % 8:
        raise ValueError("this byte-oriented reproducer only supports byte lengths")
    padded = message + bytes(zero_bits // 8) + bytes(120) + bit_length.to_bytes(8, "big")
    return padded, {
        "message_bits": bit_length,
        "zero_padding_bits": zero_bits,
        "length_block_bits": 1024,
        "padded_bits": len(padded) * 8,
        "blocks": len(padded) // 128,
    }


def hash_message(
    message: bytes, variant: str, mds_mode: str, initial_state: bytes
) -> tuple[list[bytearray], bytes]:
    if len(initial_state) != 256:
        raise ValueError("initial state must be 2048 bits")
    state = [bytearray(initial_state[32 * i : 32 * (i + 1)]) for i in range(8)]
    padded, _ = pad_message(message)
    update: Callable[[list[bytearray], bytes, str], list[bytearray]]
    update = fsp if variant == "JuziHash-512" else fdm
    for offset in range(0, len(padded), 128):
        state = update(state, padded[offset : offset + 128], mds_mode)
    serialized = bytes().join(state)
    if variant == "JuziHash-512":
        digest = serialized[:64]
    else:
        digest = serialized[64:128] + serialized[192:256]
    return state, digest


def recompute_h0(variant: str, mds_mode: str) -> bytes:
    domain = bytes.fromhex("0200" if variant == "JuziHash-512" else "0400")
    initial = domain + bytes(254)
    state = [bytearray(initial[32 * i : 32 * (i + 1)]) for i in range(8)]
    update = fsp if variant == "JuziHash-512" else fdm
    return bytes().join(update(state, bytes(128), mds_mode))


def check_sbox() -> None:
    assert tuple(sbox4(x) for x in range(16)) == S4
    assert sorted(sbox8(x) for x in range(256)) == list(range(256))


def check_mds() -> None:
    basis = [mds_vector([1 if i == j else 0 for i in range(4)]) for j in range(4)]
    assert basis == [
        [0x02, 0x01, 0x01, 0x03],
        [0x03, 0x02, 0x01, 0x01],
        [0x01, 0x03, 0x02, 0x01],
        [0x01, 0x01, 0x03, 0x02],
    ]
    for weight_in in range(1, 4):
        for mask in range(1, 16):
            if mask.bit_count() != weight_in:
                continue
            output = mds_vector([mask >> i & 1 for i in range(4)])
            assert weight_in + sum(value != 0 for value in output) >= 5


def main() -> None:
    check_sbox()
    check_mds()
    script_path = Path(__file__).resolve()
    spec_path = script_path.with_name("hash-13-spec.pdf")
    if not spec_path.exists():
        raise SystemExit("hash-13-spec.pdf is required beside the reproducer")

    published = {
        variant: bytes.fromhex(value) for variant, value in PUBLISHED_H0_HEX.items()
    }
    results: dict[str, object] = {
        "schema": "juzihash-independent-reproduction-v1",
        "provenance": {
            "specification_url": (
                "https://cdn.jsdelivr.net/gh/ngcc-dev/ngcc-harness@"
                "dc66c6cb3c06e75bdea0048e21fa4e13c63f00af/hash-13/hash-13-spec.pdf"
            ),
            "specification_sha256": hashlib.sha256(spec_path.read_bytes()).hexdigest(),
            "script_sha256": hashlib.sha256(script_path.read_bytes()).hexdigest(),
            "script": script_path.name,
            "command": f"{sys.executable} {script_path.name}",
        },
        "environment": {
            "python": sys.version,
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "machine": platform.machine(),
        },
        "conventions": {
            "sbox4_index": "integer 0..15; input/output bit x0 is the least significant bit",
            "sbox8_split": "x=L0||R0, so L0 is the high nibble and R0 is the low nibble",
            "state": "serialized S0||...||S7; bytes within each word use increasing j",
            "words": "big-endian hexadecimal in Appendix B; no integer round-trip in this implementation",
            "mds_fixed_word": (
                "Appendix A.3: A*(S[row,j], row=0..3) for j=0..31 and then rows 4..7"
            ),
            "mds_changing_dimension": (
                "Section 3.3: A along T dimension (3-round) mod 4, increasing coordinate; "
                "Appendix A byte permutation retained unchanged"
            ),
            "length_encoding": "enc64(original bit length), 64-bit big-endian after 960 zero bits",
            "capacity_feed_forward": (
                "fDM capacity = Cap(S) xor Cap(P(S xor In(M))); rate is copied from P output"
            ),
            "digest_512": "S0||S1",
            "digest_1024": "S2||S3||S6||S7",
        },
        "tests": {
            "sbox4_matches_table": True,
            "sbox8_is_bijection": True,
            "mds_supports_mds_branch_number_for_unit_inputs": True,
        },
        "initialization": {},
        "messages": {},
        "cross_interpretation_comparisons": {},
    }

    for mds_mode in ("fixed_word", "changing_dimension"):
        mode_results: dict[str, object] = {}
        for variant in ("JuziHash-512", "JuziHash-1024"):
            recomputed = recompute_h0(variant, mds_mode)
            mode_results[variant] = {
                "recomputed_h0_hex": recomputed.hex(),
                "published_h0_matches": recomputed == published[variant],
            }
        results["initialization"][mds_mode] = mode_results  # type: ignore[index]

    messages = {"empty": b"", "abc": b"abc"}
    for label, message in messages.items():
        padded, padding = pad_message(message)
        message_results: dict[str, object] = {
            "message_hex": message.hex(),
            "padding": padding,
            "padded_message_hex": padded.hex(),
            "implementations": {},
        }
        for mds_mode in ("fixed_word", "changing_dimension"):
            mode_results = {}
            for variant in ("JuziHash-512", "JuziHash-1024"):
                state, digest = hash_message(
                    message, variant, mds_mode, published[variant]
                )
                mode_results[variant] = {
                    "final_state_hex": bytes().join(state).hex(),
                    "digest_bits": len(digest) * 8,
                    "digest_hex": digest.hex(),
                }
            message_results["implementations"][mds_mode] = mode_results  # type: ignore[index]
        results["messages"][label] = message_results  # type: ignore[index]

        comparisons = {}
        for variant in ("JuziHash-512", "JuziHash-1024"):
            fixed = message_results["implementations"]["fixed_word"][variant]  # type: ignore[index]
            changing = message_results["implementations"]["changing_dimension"][variant]  # type: ignore[index]
            fixed_state = bytes.fromhex(fixed["final_state_hex"])
            changing_state = bytes.fromhex(changing["final_state_hex"])
            fixed_digest = bytes.fromhex(fixed["digest_hex"])
            changing_digest = bytes.fromhex(changing["digest_hex"])
            comparisons[variant] = {
                "final_states_equal": fixed_state == changing_state,
                "final_state_differing_bits": sum(
                    (left ^ right).bit_count()
                    for left, right in zip(fixed_state, changing_state)
                ),
                "final_state_first_difference_byte": next(
                    index
                    for index, (left, right) in enumerate(
                        zip(fixed_state, changing_state)
                    )
                    if left != right
                ),
                "digests_equal": fixed_digest == changing_digest,
                "digest_differing_bits": sum(
                    (left ^ right).bit_count()
                    for left, right in zip(fixed_digest, changing_digest)
                ),
                "digest_first_difference_byte": next(
                    index
                    for index, (left, right) in enumerate(
                        zip(fixed_digest, changing_digest)
                    )
                    if left != right
                ),
            }
        results["cross_interpretation_comparisons"][label] = comparisons  # type: ignore[index]

    print(json.dumps(results, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
