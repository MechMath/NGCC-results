#!/usr/bin/env python3
"""Recompute the two literal length-placement readings for all LLH profiles.

This is an audit wrapper around the independently written literal model at
../34fb32beeebd48b5/llh_research.py.  It changes the assignment to the last 64
state positions and implements the full absorption recurrence, including the
old-capacity feed-forward.  It is deterministic reproducibility material, not
a statistical experiment.
"""

from __future__ import annotations

import argparse
import runpy
from pathlib import Path


DEFAULT_MODEL = (
    Path(__file__).resolve().parent.parent / "34fb32beeebd48b5" / "llh_research.py"
)


def reverse_bits(x: int, width: int) -> int:
    return int(f"{x:0{width}b}"[::-1], 2)


def initial_state(width: int, message_bits: int, reading: str) -> list[int]:
    """Return S0 for LLH-256/512/768/1024 and M=00.

    Reading A puts length bit k at final-coordinate k.  Reading B puts length
    bit 63-k at final-coordinate k.  For w=32, the final coords are W22 then
    W23; for the larger widths they are the final 64 coordinates of W23.
    """
    if message_bits != 8:
        raise ValueError("this audit intentionally covers only the one-byte message 00")
    state = [0] * 24
    if reading == "A":
        if width == 32:
            state[22] = message_bits
        elif width == 64:
            state[23] = message_bits
        elif width == 96:
            state[23] = message_bits << 32
        elif width == 128:
            state[23] = message_bits << 64
        else:
            raise ValueError(f"unsupported width: {width}")
        return state
    if reading != "B":
        raise ValueError(f"unknown reading: {reading}")

    if width == 32:
        state[23] = reverse_bits(message_bits, 32)
    elif width == 64:
        state[23] = reverse_bits(message_bits, 64)
    elif width == 96:
        state[23] = reverse_bits(message_bits, 64) << 32
    elif width == 128:
        state[23] = reverse_bits(message_bits, 64) << 64
    else:
        raise ValueError(f"unsupported width: {width}")
    return state


def digest(model: dict, width: int, reading: str) -> str:
    message = b"\x00"
    rounds = model["ROUNDS"][width]
    padded = model["pad_message"](message, 8, width)
    state = initial_state(width, 8, reading)
    words_per_block = 8 * (width // 8)
    for offset in range(0, len(padded), words_per_block):
        previous = state
        state = model["permutation"](previous, width, rounds)
        block = model["bytes_to_words_little"](
            padded[offset : offset + words_per_block], width
        )
        for i, word in enumerate(block):
            state[i] ^= word
        # The specification absorbs M_i || C(S_{i-1}), not M_i alone.
        for i in range(8, 24):
            state[i] ^= previous[i]
    state = model["permutation"](state, width, rounds)
    return model["words_to_bytes_little"](state[:8], width).hex()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    args = parser.parse_args()
    model = runpy.run_path(str(args.model))
    for width in (32, 64, 96, 128):
        a = digest(model, width, "A")
        b = digest(model, width, "B")
        print(f"w={width} equal={a == b}")
        print(f"A {a}")
        print(f"B {b}")


if __name__ == "__main__":
    main()
