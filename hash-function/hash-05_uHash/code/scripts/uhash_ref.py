#!/usr/bin/env python3
"""Independent uHash/uBlock-1024 reference.

The PDF specifies nibble positions and 32-bit word rotations but does not state
the byte order of its hexadecimal examples.  Every byte-order choice is therefore
an explicit command-line option.  The defaults are only a debugging convention;
they are not claimed to be normative until published vectors pass.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from hashlib import sha256

MASK32 = (1 << 32) - 1
MASK128 = (1 << 128) - 1
MASK256 = (1 << 256) - 1

SBOX = [
    0x3, 0x0, 0x6, 0x2, 0x5, 0x4, 0xF, 0xE,
    0xA, 0x8, 0x7, 0x9, 0x1, 0xC, 0xD, 0xB,
]
PL = [
    28, 18, 16, 26, 30, 22, 29, 23, 27, 17, 24, 31, 25, 19, 21, 20,
    3, 10, 4, 15, 14, 5, 7, 13, 12, 0, 11, 1, 9, 2, 6, 8,
]
PR = [
    0, 2, 1, 12, 11, 8, 13, 7, 10, 4, 6, 5, 3, 14, 9, 15,
    22, 18, 27, 23, 24, 31, 20, 28, 29, 17, 16, 19, 25, 30, 26, 21,
]
PF = [
    11, 3, 14, 2, 9, 10, 12, 0, 4, 13, 7, 8, 15, 6, 5, 1,
    16, 19, 27, 22, 31, 26, 20, 30, 23, 29, 25, 18, 24, 21, 28, 17,
]
PG = [
    23, 3, 31, 2, 0, 20, 21, 15, 13, 29, 14, 30, 12, 28, 22, 1,
    17, 24, 8, 5, 27, 16, 6, 11, 25, 18, 19, 10, 7, 9, 26, 4,
]
RC = [
    0x988CC9DD, 0xF0E4A1B5, 0x21357064, 0x8397D2C6,
    0xC7D39682, 0x4F5B1E0A, 0x5E4A0F1B, 0x7C682D39,
    0x392D687C, 0xB3A7E2F6, 0xA7B3F6E2, 0x8E9ADFCB,
]


@dataclass(frozen=True)
class Convention:
    nibble_msb_first: bool = True
    word_msb_first: bool = True
    permutation_output_index: bool = True
    rc_placement: str = "repeat"
    rc_shift: int = 0
    byte_order: str = "big"
    swap_state_halves: bool = False
    swap_round_keys: bool = False
    pl_output_index: bool = True
    pr_output_index: bool = True
    pf_output_index: bool = True
    pg_output_index: bool = True
    reverse_rc_bytes: bool = False


def xor_bytes(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))


def xor_low_counter(data: bytes, counter: int) -> bytes:
    n = int.from_bytes(data, "big") ^ counter
    return n.to_bytes(len(data), "big")


def to_nibbles(value: int, conv: Convention) -> list[int]:
    words = [((value >> (32 * i)) & MASK32) for i in range(4)]
    if conv.word_msb_first:
        words.reverse()
    result = []
    for word in words:
        nibbles = [(word >> (4 * i)) & 0xF for i in range(8)]
        result.extend(reversed(nibbles) if conv.nibble_msb_first else nibbles)
    return result


def from_nibbles(nibbles: list[int], conv: Convention) -> int:
    words_in_order = []
    for start in range(0, 32, 8):
        chunk = nibbles[start:start + 8]
        if conv.nibble_msb_first:
            chunk = list(reversed(chunk))
        words_in_order.append(sum(n << (4 * i) for i, n in enumerate(chunk)))
    if conv.word_msb_first:
        words_in_order.reverse()
    return sum(word << (32 * i) for i, word in enumerate(words_in_order))


def permute(value: int, permutation: list[int], conv: Convention, output_index: bool = True) -> int:
    source = to_nibbles(value, conv)
    output = [0] * 32
    for i, pi in enumerate(permutation):
        if output_index:
            output[i] = source[pi]
        else:
            output[pi] = source[i]
    return from_nibbles(output, conv)


def substitute(value: int, conv: Convention) -> int:
    nibbles = to_nibbles(value, conv)
    return from_nibbles([SBOX[x] for x in nibbles], conv)


def rotl32_words(value: int, amount: int, conv: Convention) -> int:
    words = [((value >> (32 * i)) & MASK32) for i in range(4)]
    if conv.word_msb_first:
        words.reverse()
    words = [((w << amount) | (w >> (32 - amount))) & MASK32 for w in words]
    if conv.word_msb_first:
        words.reverse()
    return sum(w << (32 * i) for i, w in enumerate(words))


def rc_word(rc: int, conv: Convention) -> int:
    if conv.reverse_rc_bytes:
        rc = int.from_bytes(rc.to_bytes(4, "big"), "little")
    if conv.rc_placement in ("low", "single"):
        return rc << conv.rc_shift
    if conv.rc_placement == "high":
        return rc << 96
    if conv.rc_placement == "repeat":
        return rc | (rc << 32) | (rc << 64) | (rc << 96)
    raise ValueError(f"unknown rc placement {conv.rc_placement}")


def key_schedule(key: bytes, conv: Convention) -> list[tuple[int, int]]:
    assert len(key) == 128
    k = [int.from_bytes(key[16 * i:16 * (i + 1)], conv.byte_order) for i in range(8)]
    rk: list[tuple[int, int]] = []
    for i in range(4):
        rk.append((k[2 * i], k[2 * i + 1]))
    for i, rc in enumerate(RC, 1):
        k = [
            permute(k[2] ^ rc_word(rc, conv), PF, conv, conv.pf_output_index),
            permute(k[5], PG, conv, conv.pg_output_index),
            permute(k[1], PF, conv, conv.pf_output_index),
            permute(k[0], PG, conv, conv.pg_output_index),
            permute(k[3], PF, conv, conv.pf_output_index),
            permute(k[6], PG, conv, conv.pg_output_index),
            permute(k[7], PF, conv, conv.pf_output_index),
            permute(k[4], PG, conv, conv.pg_output_index),
        ]
        for j in range(4):
            rk.append((k[2 * j], k[2 * j + 1]))
    assert len(rk) == 52
    return rk


def ublock_encrypt(block: bytes, key: bytes, conv: Convention) -> bytes:
    assert len(block) == 32 and len(key) == 128
    x0 = int.from_bytes(block[:16], conv.byte_order)
    x1 = int.from_bytes(block[16:], conv.byte_order)
    if conv.swap_state_halves:
        x0, x1 = x1, x0
    for rk0, rk1 in key_schedule(key, conv):
        if conv.swap_round_keys:
            rk0, rk1 = rk1, rk0
        x0 = substitute(x0 ^ rk0, conv)
        x1 = substitute(x1 ^ rk1, conv)
        x1 ^= x0
        x0 ^= rotl32_words(x1, 4, conv)
        x1 ^= rotl32_words(x0, 8, conv)
        x0 ^= rotl32_words(x1, 8, conv)
        x1 ^= rotl32_words(x0, 20, conv)
        x0 ^= x1
        x0 = permute(x0, PL, conv, conv.pl_output_index)
        x1 = permute(x1, PR, conv, conv.pr_output_index)
    if conv.swap_state_halves:
        x0, x1 = x1, x0
    return x0.to_bytes(16, conv.byte_order) + x1.to_bytes(16, conv.byte_order)


def iv_for(branches: int) -> bytes:
    bn = branches * 256
    parts = [
        (0 << 192) | (0 << 128) | bn,
        (0 << 192) | (bn << 128) | 0,
        (0 << 192) | (bn << 64) | 0,
        (bn << 192) | (0 << 128) | 0,
    ]
    return b"".join(parts[i].to_bytes(32, "big") for i in range(branches))


def pad_message(message: bytes, branches: int, message_bits: int | None = None) -> tuple[bytes, int]:
    length_bits = len(message) * 8 if message_bits is None else message_bits
    if length_bits < 0 or length_bits > len(message) * 8:
        raise ValueError("message_bits out of range")
    chunk_bits = (5 - branches) * 256
    needed = (-length_bits) % chunk_bits
    if needed == 0:
        needed = chunk_bits
    value = int.from_bytes(message, "big")
    total_zeros = len(message) * 8 - length_bits + needed - 1
    value <<= 1 + total_zeros
    value |= 1 << total_zeros
    nbytes = (length_bits + needed + 7) // 8
    return value.to_bytes(nbytes, "big"), length_bits + needed


def uhash(message: bytes, digest_bits: int, conv: Convention, message_bits: int | None = None) -> dict:
    if digest_bits not in (512, 768, 1024):
        raise ValueError("digest_bits must be 512, 768, or 1024")
    branches = digest_bits // 256
    chunk_bytes = (5 - branches) * 32
    padded, padded_bits = pad_message(message, branches, message_bits)
    chunks = [padded[i:i + chunk_bytes] for i in range(0, len(padded), chunk_bytes)]
    state = iv_for(branches)
    block_calls = 0
    stage_trace = []
    for index, chunk in enumerate(chunks):
        u1 = state[:32]
        key = state[32:] + chunk
        assert len(key) == 128
        final = index == len(chunks) - 1
        outputs = []
        for j in range(1, branches + 1):
            k = xor_low_counter(key, j + 15) if final else key
            block = xor_low_counter(u1, j - 1)
            outputs.append(xor_bytes(ublock_encrypt(block, k, conv), u1))
            block_calls += 1
        state = b"".join(outputs)
        stage_trace.append({
            "chunk": index + 1,
            "final": final,
            "message_hex": chunk.hex(),
            "state_in_hex": (u1 + key[:len(key) - len(chunk)]).hex(),
            "state_out_hex": state.hex(),
        })
    digest = state.hex().upper()
    return {
        "digest_bits": digest_bits,
        "digest_hex": digest,
        "digest_sha256": sha256(state).hexdigest(),
        "message_bits": len(message) * 8 if message_bits is None else message_bits,
        "padded_bits": padded_bits,
        "message_chunks": len(chunks),
        "ublock_calls": block_calls,
        "padded_hex": padded.hex(),
        "trace": stage_trace,
        "convention": asdict(conv),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--digest", type=int, choices=(512, 768, 1024), required=True)
    parser.add_argument("--message-hex", default="")
    parser.add_argument("--message-bits", type=int)
    parser.add_argument("--nibble-order", choices=("msb", "lsb"), default="msb")
    parser.add_argument("--word-order", choices=("msb", "lsb"), default="msb")
    parser.add_argument("--perm-map", choices=("output-index", "input-index"), default="output-index")
    parser.add_argument("--rc-placement", choices=("low", "high", "repeat"), default="repeat")
    args = parser.parse_args()
    message = bytes.fromhex(args.message_hex)
    conv = Convention(
        nibble_msb_first=args.nibble_order == "msb",
        word_msb_first=args.word_order == "msb",
        permutation_output_index=args.perm_map == "output-index",
        rc_placement=args.rc_placement,
    )
    print(json.dumps(uhash(message, args.digest, conv, args.message_bits), indent=2))


if __name__ == "__main__":
    main()
