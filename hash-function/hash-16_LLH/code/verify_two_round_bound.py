#!/usr/bin/env python3
"""Exhaustive verification of the two-round LLH-256 differential bound.

The script checks the finite S6 DDT, the two linear-layer support lemmas, and
the explicit optimal trail.  State [j][c] is the 6-bit S24 input at slide
(matrix column) j and S6 column c.
"""

from __future__ import annotations

from collections import Counter
from functools import lru_cache

from llh_trail_search import (
    DIFF_TABLE,
    DERANGEMENT,
    SHIFTS,
    linear_layer_int,
    s6,
    verify_trail,
)


def columns(mask: int) -> list[int]:
    """Convert a row-major 24-bit S24 output to four 6-bit column values."""
    return [
        sum(((mask >> (4 * r + c)) & 1) << r for r in range(6))
        for c in range(4)
    ]


def forward_state(outputs: list[list[int]], w: int) -> list[list[int]]:
    masks = [linear_layer_int(row) for row in outputs]
    nxt = [[0] * 4 for _ in range(w)]
    for j in range(w):
        for c in range(4):
            for r in range(6):
                position = 4 * r + c
                source = (j - SHIFTS[w][position]) % w
                nxt[j][c] |= ((masks[source] >> position) & 1) << r
    return nxt


def inverse_state(nxt: list[list[int]], w: int) -> list[list[int]]:
    """Invert D, derangement, XOR-linear layer and ShiftRows.

    D=J-I over GF(2) for size four satisfies D^2=I, so D is its own inverse.
    Undoing ShiftRows assigns word-position-p bits back to slide
    j-sigma_p.
    """
    masks_before_linear = [0] * w
    for j in range(w):
                for c in range(4):
                    for r in range(6):
                        position = 4 * r + c
                        src = (j - SHIFTS[w][position]) % w
                        masks_before_linear[src] |= (
                            ((nxt[j][c] >> r) & 1) << position
                        )
    dos = []
    for mask in masks_before_linear:
        after_derangement = [0] * 24
        for r in range(6):
            row = [(mask >> (4 * r + j)) & 1 for j in range(4)]
            parity = sum(row) & 1
            for j in range(4):
                after_derangement[4 * r + j] = row[j] ^ parity
        before_derangement = [0] * 24
        for src, dst in enumerate(DERANGEMENT):
            before_derangement[src] = after_derangement[dst]
        dos.append(columns(sum(
            before_derangement[4 * r + c] << (4 * r + c)
            for r in range(6) for c in range(4)
        )))
    return dos


def active(state: list[list[int]]) -> int:
    return sum(value != 0 for row in state for value in row)


def shifted_mask_active(mask: int, source_slide: int, w: int) -> int:
    """Count active (slide,column) cells after ShiftRows."""
    occupied = [0] * 4
    for position in range(24):
        if (mask >> position) & 1:
            destination = (source_slide + SHIFTS[w][position]) % w
            occupied[position % 4] |= 1 << destination
    return sum(mask.bit_count() for mask in occupied)


@lru_cache(maxsize=None)
def inverse_linear_columns(position: int) -> int:
    """Return the nonzero S6-output columns from one post-D word bit."""
    mask = 1 << position
    after_derangement = 0
    for r in range(6):
        row = [(mask >> (4 * r + x)) & 1 for x in range(4)]
        parity = sum(row) & 1
        for x in range(4):
            after_derangement |= (row[x] ^ parity) << (4 * r + x)
    before_derangement = 0
    for src, dst in enumerate(DERANGEMENT):
        before_derangement |= ((after_derangement >> dst) & 1) << src
    columns_mask = 0
    for q in range(4):
        if any((before_derangement >> (4 * r + q)) & 1 for r in range(6)):
            columns_mask |= 1 << q
    return columns_mask


def one_next_preimages(j: int, c: int, value: int, w: int) -> int:
    """Count S6-output columns before ShiftRows and the linear map."""
    columns_at_slide = {}
    for r in range(6):
        if (value >> r) & 1:
            position = 4 * r + c
            source = (j - SHIFTS[w][position]) % w
            columns_at_slide[source] = (
                columns_at_slide.get(source, 0)
                | inverse_linear_columns(position)
            )
    return sum(mask.bit_count() for mask in columns_at_slide.values())


def main() -> None:
    profile = Counter(DIFF_TABLE.values())
    assert profile == Counter({4: 784, 16: 56, 64: 1})
    assert DIFF_TABLE[(0, 0)] == 64
    assert max(count for (din, dout), count in DIFF_TABLE.items()
               if din != 0) == 16

    lemma_results = {}
    for w in (32, 64, 96, 128):
        # Lemma 1: one active input S6 forces at least three active S-boxes
        # after the S24 linear layer and ShiftRows.
        one_input_next_min = 10 ** 9
        for din in range(1, 64):
            for dout in range(64):
                if DIFF_TABLE.get((din, dout), 0) == 0:
                    continue
                mask = linear_layer_int([dout, 0, 0, 0])
                one_input_next_min = min(one_input_next_min,
                                         shifted_mask_active(mask, 0, w))
        assert one_input_next_min == 3

        # Lemma 2: every state with one active input S-box has at least three
        # active S6-output preimages under the invertible linear layer.
        one_next_preimage_min = 10 ** 9
        for j in range(w):
            for c in range(4):
                for value in range(1, 64):
                    one_next_preimage_min = min(
                        one_next_preimage_min,
                        one_next_preimages(j, c, value, w),
                    )
        assert one_next_preimage_min == 3
        lemma_results[w] = (one_input_next_min, one_next_preimage_min)

    # Explicit optimal trail: probabilities 16/64 in each active S-box.
    w = 32
    state = [[0] * 4 for _ in range(w)]
    state[23] = [0x15, 0x2A, 0x00, 0x2A]
    outputs = [[[0] * 4 for _ in range(w)] for _ in range(2)]
    outputs[0][23] = [0x02, 0x01, 0x00, 0x10]
    outputs[1][22][2] = 0x05
    witness = verify_trail(w, 2, state, outputs)
    assert witness["active_per_round"] == [3, 1]
    assert witness["trail_probability"] == "1/256"
    assert witness["trail_weight"] == 8
    assert witness["output_difference_nonzero"]

    print("S6 DDT profile:", dict(sorted(profile.items())))
    print("support lemma minima by w:", lemma_results)
    print("witness:", witness)
    print("verified: every nonzero two-round differential trail at each "
          "supported w has weight >= 8; an LLH-256 trail attains weight 8")


if __name__ == "__main__":
    main()
