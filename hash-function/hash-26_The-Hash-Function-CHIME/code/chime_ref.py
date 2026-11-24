#!/usr/bin/env python3
"""Independent direct implementation of CHIME from the clean specification."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import argparse
import json


MASK64 = (1 << 64) - 1
MASK256 = (1 << 256) - 1

SBOX = (0, 5, 3, 2, 6, 1, 4, 7)


def rol64(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & MASK64


def ror64(x: int, n: int) -> int:
    return rol64(x, 64 - n)


def apply_words(x: int, fn) -> int:
    return (
        (fn((x >> 192) & MASK64) << 192)
        | (fn((x >> 128) & MASK64) << 128)
        | (fn((x >> 64) & MASK64) << 64)
        | fn(x & MASK64)
    )


def perm64(x: int) -> int:
    """b || c || d || a <- a || b || c || d."""
    a = (x >> 192) & MASK64
    b = (x >> 128) & MASK64
    c = (x >> 64) & MASK64
    d = x & MASK64
    return (b << 192) | (c << 128) | (d << 64) | a


def swap64(x: int) -> int:
    """b || a || d || c <- a || b || c || d."""
    a = (x >> 192) & MASK64
    b = (x >> 128) & MASK64
    c = (x >> 64) & MASK64
    d = x & MASK64
    return (b << 192) | (a << 128) | (d << 64) | c


def perm32(x: int) -> int:
    """Rotate the four 32-bit words in each 128-bit half by one word."""
    chunks = [(x >> (32 * i)) & 0xFFFFFFFF for i in range(8)]
    # Input display order a1,b1,c1,d1,a0,b0,c0,d0.
    # Output display order d1,a1,b1,c1,d0,a0,b0,c0.
    src = chunks[::-1]
    out = (src[3], src[0], src[1], src[2],
           src[7], src[4], src[5], src[6])
    return sum(v << (32 * i) for i, v in enumerate(out[::-1]))


def swap128(x: int) -> int:
    """b || a <- a || b."""
    return ((x & ((1 << 128) - 1)) << 128) | (x >> 128)


def linear(state: list[int]) -> list[int]:
    a0, a1, b0, b1, c0, c1 = state
    b1 ^= perm32(c1)
    b0 ^= a1
    c0 ^= apply_words(a0, lambda w: rol64(w, 29))
    b1 ^= apply_words(a1, lambda w: rol64(w, 31))
    c1 ^= apply_words(a0, lambda w: rol64(w, 13))
    c0 ^= b1
    a0 = perm64(a0)
    c1 ^= perm32(b1)
    a1 = swap128(a1)
    a0 ^= swap64(c0)
    a1 ^= perm32(b0)
    b1 ^= apply_words(a0, lambda w: rol64(w, 7))
    c1 ^= apply_words(a1, lambda w: ror64(w, 5))
    return [a0 & MASK256, a1 & MASK256, b0 & MASK256,
            b1 & MASK256, c0 & MASK256, c1 & MASK256]


def chi(state: list[int], rnd: int) -> list[int]:
    a0, a1, b0, b1, c0, c1 = state
    if rnd % 2 == 0:
        pairs = ((a0, b0, c0), (a1, b1, c1))
    else:
        pairs = ((a0, b1, c1), (a1, b0, c0))
    out = [0] * 6
    names = (
        (0, 2, 4) if rnd % 2 == 0 else (0, 3, 5)
    )
    names1 = (
        (1, 3, 5) if rnd % 2 == 0 else (1, 2, 4)
    )
    for idxs, (x0, x1, x2) in zip((names, names1), pairs):
        y0 = x0 ^ ((~x1) & x2)
        y1 = x1 ^ ((~x2) & x0)
        y2 = x2 ^ ((~x0) & x1)
        out[idxs[0]], out[idxs[1]], out[idxs[2]] = (
            y0 & MASK256, y1 & MASK256, y2 & MASK256
        )
    return out


def tau(state: list[int], rnd: int) -> list[int]:
    a0, a1, b0, b1, c0, c1 = state
    if (rnd // 3) % 2 == 0:
        return [c1, a0, a1, b0, b1, c0]
    return [a1, b0, b1, c0, c1, a0]


def round_constant(rnd: int) -> int:
    return (0xDEADBEEF00000000 ^ rnd ^
            ((0x9E3779B97F4A7C15 * (rnd + 1)) & MASK64)) & MASK64


def repeat_word(x: int) -> int:
    return x | (x << 64) | (x << 128) | (x << 192)


def round_function(state: list[int], rnd: int) -> list[int]:
    s = linear(state)
    s[0] ^= repeat_word(round_constant(rnd))
    s = chi(s, rnd)
    return tau(s, rnd)


def permutation(state: list[int], rounds: int, trace: list | None = None) -> list[int]:
    for rnd in range(rounds):
        if trace is not None:
            trace.append(tuple(state))
        state = round_function(state, rnd)
    if trace is not None:
        trace.append(tuple(state))
    return state


def bits_to_array(bits: str) -> int:
    if len(bits) > 256 or any(c not in "01" for c in bits):
        raise ValueError("expected at most 256 bits")
    return int(bits.ljust(256, "0"), 2) if bits else 0


def array_to_bits(x: int) -> str:
    return f"{x:0256b}"


def state_to_bytes(state: list[int]) -> bytes:
    return b"".join(x.to_bytes(32, "big") for x in state)


def state_from_bits(bits: str) -> list[int]:
    if len(bits) != 1536:
        raise ValueError("state must have 1536 bits")
    return [int(bits[256 * i:256 * (i + 1)], 2) for i in range(6)]


def xor_rate(state: list[int], block: int, rate: int) -> list[int]:
    out = state.copy()
    for i in range(rate // 256):
        out[i] ^= (block >> (256 * (rate // 256 - 1 - i))) & MASK256
    left = rate % 256
    if left:
        shift = 256 - left
        out[rate // 256] ^= ((block & ((1 << left) - 1)) << shift)
    return out


def pad_message(message: bytes, rate: int) -> bytes:
    bits = "".join(f"{b:08b}" for b in message) + "1"
    zeroes = (-len(bits) - 1) % rate
    bits += "0" * zeroes + "1"
    return int(bits, 2).to_bytes(len(bits) // 8, "big")


PAD_WORD = 0x8000000000000001


def invariant_message_words(profile: int, words: list[int]) -> bytes:
    """Build a byte-aligned message whose every padded rate block is 4-repeat.

    For B data/padded blocks, ``words`` must contain B values. The last value is
    forced to PAD_WORD because that word is the padding word 1 || 0^62 || 1.
    """
    rate = 512 if profile == 512 else 448
    if not words or words[-1] != PAD_WORD:
        raise ValueError(f"last word must be {PAD_WORD:016x}")
    repeated = []
    for word in words:
        repeated.extend([f"{word:064b}"] * (rate // 64))
    bits = "".join(repeated)
    # The final 64-bit word is the padding word, so strip it from the message.
    bits = bits[:-64]
    if len(bits) % 8:
        raise AssertionError("construction must be byte-aligned")
    return int(bits, 2).to_bytes(len(bits) // 8, "big")


def output_word_repetition(result: bytes, profile: int) -> list[tuple[int, int]]:
    """Return (word, multiplicity) for projected hash words for verification."""
    words = [int.from_bytes(result[i:i + 8], "big")
             for i in range(0, len(result), 8)]
    runs = []
    i = 0
    while i < len(words):
        j = i + 1
        while j < len(words) and words[j] == words[i]:
            j += 1
        runs.append((words[i], j - i))
        i = j
    return runs


def chime(message: bytes, profile: int, trace: bool = False) -> bytes:
    if profile == 512:
        rate, rounds, out_bits, feedforward = 512, 15, 512, False
    elif profile == 1024:
        rate, rounds, out_bits, feedforward = 448, 20, 1024, True
    else:
        raise ValueError("profile must be 512 or 1024")
    padded = pad_message(message, rate)
    state = [0] * 6
    block_ints = [int.from_bytes(padded[i:i + rate // 8], "big")
                  for i in range(0, len(padded), rate // 8)]
    per_block = []
    for block in block_ints:
        injected = xor_rate(state, block, rate)
        before_feedforward = permutation(injected, rounds)
        if feedforward:
            # Append the old capacity in the last 1088 bits.
            state_bits = "".join(array_to_bits(x) for x in state)
            cap = int(state_bits[-1088:], 2)
            state = before_feedforward.copy()
            state[0] ^= 0  # rate prefix remains the P output
            tail = ((before_feedforward[1] << 832)
                    | (before_feedforward[2] << 576)
                    | (before_feedforward[3] << 320)
                    | (before_feedforward[4] << 64)
                    | (before_feedforward[5] & ((1 << 64) - 1)))
            tail ^= cap
            state[1] = (tail >> 832) & MASK256
            state[2] = (tail >> 576) & MASK256
            state[3] = (tail >> 320) & MASK256
            state[4] = (tail >> 64) & MASK256
            state[5] = tail & MASK256
        else:
            state = before_feedforward
        if trace:
            per_block.append(tuple(state))
    if feedforward:
        state[5] ^= 1
    allbits = "".join(array_to_bits(x) for x in state)
    result = allbits[:out_bits] if profile == 512 else allbits[-out_bits:]
    raw = int(result, 2).to_bytes(out_bits // 8, "big")
    if trace:
        return raw, per_block
    return raw


def rank_and_kernel() -> tuple[int, list[list[int]], int]:
    """Return rank, input-kernel basis, and nullity for CHIME's linear layer."""
    columns = []
    for i in range(1536):
        state = [0] * 6
        state[i // 256] = 1 << (255 - (i % 256))
        out = linear(state)
        columns.append(sum(out[j] << (256 * j) for j in range(6)))
    basis: dict[int, int] = {}
    combos: dict[int, int] = {}
    kernel: list[list[int]] = []
    for i, col in enumerate(columns):
        x = col
        combo = 1 << i
        for pivot in sorted(basis, reverse=True):
            if (x >> pivot) & 1:
                x ^= basis[pivot]
                combo ^= combos[pivot]
        if x:
            pivot = x.bit_length() - 1
            basis[pivot] = x
            combos[pivot] = combo
        else:
            # This is an exact dependency among the input columns.
            kernel.append([(combo >> (256 * j)) & MASK256 for j in range(6)])
    return len(basis), kernel, 1536 - len(basis)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--message", default="")
    ap.add_argument("--hex", action="store_true")
    ap.add_argument("--profile", type=int, choices=(512, 1024), default=512)
    ap.add_argument("--linear-rank", action="store_true")
    args = ap.parse_args()
    if args.linear_rank:
        print("linear rank inspection moved to chime_search.py")
        return
    msg = bytes.fromhex(args.message) if args.hex else args.message.encode()
    print(chime(msg, args.profile).hex())


if __name__ == "__main__":
    main()
