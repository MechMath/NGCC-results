#!/usr/bin/env python3
"""Exact empty-message cross-layout digest comparison for JuziHash.

This reuses the reviewed state operations in verify_juzi.py and adds only the
specified padding, rate injection, iterative update, and digest projections.
"""

from __future__ import annotations

import hashlib

import verify_juzi as v


def pad_empty_message() -> bytes:
    # ell=0 gives z=0; Len_1024(0) = 0^960 || enc64(0).
    return bytes(128)


def initial_state(size: int, layout: str) -> bytes:
    seed = v.h_minus_one(size)
    permuted, _ = v.permute(seed, layout)
    return permuted if size == 512 else v.update_1024(seed, permuted)


def process_block(state: bytes, block: bytes, size: int, layout: str) -> bytes:
    injected = bytearray(state)
    # Rate words (S0,S1,S4,S5) receive message words M0..M3.
    for state_offset, message_offset in ((0, 0), (32, 32), (128, 64), (160, 96)):
        for j in range(32):
            injected[state_offset + j] ^= block[message_offset + j]
    permuted, _ = v.permute(bytes(injected), layout)
    return permuted if size == 512 else v.update_1024(bytes(injected), permuted)


def digest(state: bytes, size: int) -> bytes:
    if size == 512:
        return state[:64]  # Trsp_512 = S0||S1
    return state[64:128] + state[192:256]  # Cap_1024 = S2||S3||S6||S7


def empty_digest(size: int, layout: str) -> bytes:
    state = initial_state(size, layout)
    state = process_block(state, pad_empty_message(), size, layout)
    return digest(state, size)


def main() -> int:
    ok = True
    for size in (512, 1024):
        a = empty_digest(size, "A")
        b = empty_digest(size, "B")
        equal_bytes = sum(x == y for x, y in zip(a, b))
        differing_bits = sum((x ^ y).bit_count() for x, y in zip(a, b))
        print(f"{size}/A sha256={hashlib.sha256(a).hexdigest()}")
        print(f"{size}/B sha256={hashlib.sha256(b).hexdigest()}")
        print(f"{size}/A digest={a.hex()}")
        print(f"{size}/B digest={b.hex()}")
        print(
            f"{size}/A-vs-B equal={a == b} equal_bytes={equal_bytes}/{len(a)} "
            f"differing_bits={differing_bits}"
        )
        ok &= a != b
    print(f"VERDICT: different_empty_digests_for_both={ok}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
