#!/usr/bin/env python3
"""Literal reference model for the FEILIAN compression primitive.

This is a working model used to compare the written specification, source
excerpts, and published test vectors. It is not execution evidence.
"""

from __future__ import annotations

import argparse

MASK64 = (1 << 64) - 1

IV = [
    0x243F6A8885A308D3,
    0x13198A2E03707344,
    0xA4093822299F31D0,
    0x082EFA98EC4E6C89,
    0x452821E638D01377,
    0xBE5466CF34E90C6C,
    0xC0AC29B7C97C50DD,
    0x3D84D5B5B5470917,
    0x9216D5D98979FB1B,
    0xD1310BA698DFB5AC,
    0x2FFD72DBD01ADFB7,
    0xB8E1AFED6A267E96,
    0xBA7C9045F12C7F99,
    0x24A19947B3916CF7,
    0x0801F2E2858EFC16,
    0x636920D871574E69,
]

CONST = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
]


def rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (64 - n))) & MASK64


def sigma0(x: int) -> int:
    return x ^ rotr(x, 5) ^ rotr(x, 48)


def sigma1(x: int) -> int:
    return x ^ rotr(x, 11) ^ rotr(x, 40)


def subcolumn(column: list[int]) -> list[int]:
    a1, b1, a0, b0 = column
    a1 = (a1 + b1) & MASK64
    s0 = a1
    a0 = (a0 + b0) & MASK64
    b0 = rotr(b0 ^ s0, 8)
    a0 = (a0 + sigma0(b0)) & MASK64
    s1 = a0
    b1 = rotr(b1 ^ s1, 63)
    a1 = (a1 + sigma1(b1)) & MASK64
    return [a1, b1, a0, b0]


def submatrix(state: list[int]) -> list[int]:
    out = [0] * 16
    for c in range(4):
        out[c], out[4 + c], out[8 + c], out[12 + c] = subcolumn(
            [state[c], state[4 + c], state[8 + c], state[12 + c]]
        )
    return out


def shift_rows(state: list[int]) -> list[int]:
    return [
        state[0],
        state[1],
        state[2],
        state[3],
        state[5],
        state[6],
        state[7],
        state[4],
        state[10],
        state[11],
        state[8],
        state[9],
        state[15],
        state[12],
        state[13],
        state[14],
    ]


def add_constants_normative(
    state: list[int], group: int, domain: list[int]
) -> list[int]:
    out = state.copy()
    for c in range(4):
        out[4 + c] ^= domain[c]
        out[12 + c] ^= CONST[(group + c) % 4]
    return out


def add_constants_submitted(
    state: list[int], group: int, domain: list[int]
) -> list[int]:
    out = state.copy()
    for c in range(4):
        out[4 + c] ^= CONST[(group + c) % 4]
        out[12 + c] ^= domain[c]
    return out


def round_function(
    state: list[int],
    message: list[int] | None,
    group: int,
    domain: list[int],
    ac_mode: str = "normative",
) -> list[int]:
    if message is not None:
        for c in range(4):
            state[c] ^= message[c]
            state[8 + c] ^= message[4 + c]
        state = shift_rows(submatrix(state))
        for c in range(4):
            state[c] ^= message[8 + c]
            state[8 + c] ^= message[12 + c]
        state = shift_rows(submatrix(state))
    else:
        state = shift_rows(submatrix(state))
        state = shift_rows(submatrix(state))
    if ac_mode == "normative":
        return add_constants_normative(state, group, domain)
    if ac_mode == "submitted":
        return add_constants_submitted(state, group, domain)
    raise ValueError(f"unknown AC mode: {ac_mode}")


def compression(
    chaining: list[int],
    message: list[int],
    version: int,
    final: bool,
    bit_length: int,
    stop_after: int = 20,
    ac_mode: str = "normative",
) -> tuple[list[int], list[list[int]]]:
    domain = [
        version,
        MASK64 if final else 0,
        (bit_length >> 64) & MASK64,
        bit_length & MASK64,
    ]
    state = chaining.copy()
    states = [state.copy()]
    for rnd in range(stop_after):
        state = round_function(
            state,
            message if rnd % 4 == 0 else None,
            (rnd // 4) % 5,
            domain,
            ac_mode,
        )
        states.append(state.copy())
    return [a ^ b for a, b in zip(state, chaining)], states


def words_from_bytes(data: bytes) -> list[int]:
    block = data[:128].ljust(128, b"\0")
    return [
        int.from_bytes(block[i : i + 8], "little")
        for i in range(0, 128, 8)
    ]


def fmt(state: list[int]) -> str:
    return "\n".join(f"{w:016x}" for w in state)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", type=lambda x: int(x, 0), default=0x400)
    parser.add_argument("--message-hex", default="616263")
    parser.add_argument("--bit-length", type=int)
    parser.add_argument("--stop-after", type=int, default=20)
    parser.add_argument("--partial-twice", action="store_true")
    parser.add_argument(
        "--ac-mode", choices=("normative", "submitted"), default="normative"
    )
    args = parser.parse_args()

    data = bytes.fromhex(args.message_hex)
    bit_length = args.bit_length if args.bit_length is not None else 8 * len(data)
    message = words_from_bytes(data)
    chaining = IV
    if args.partial_twice and bit_length % 1024:
        chaining, _ = compression(
            chaining,
            message,
            args.version,
            False,
            1024,
            ac_mode=args.ac_mode,
        )
    digest, states = compression(
        chaining,
        message,
        args.version,
        True,
        bit_length,
        stop_after=args.stop_after,
        ac_mode=args.ac_mode,
    )
    for i in (1, 2, 5, 10, 20):
        if i <= args.stop_after:
            print(f"State after {i} rounds:\n{fmt(states[i])}")
    print(f"Compression output:\n{fmt(digest)}")


if __name__ == "__main__":
    main()
