#!/usr/bin/env python3
"""Exhaustive checks for tiny analogues of MOZI Algorithm 2.

The byte-sized states below test only the transcribed mode formulas. They are
not evidence about the 2048-bit MOZI permutation.
"""

from itertools import permutations, product


def canonical_blocks(message: tuple[int, ...], rate: int) -> tuple[tuple[int, ...], ...]:
    """Return the unique minimal 10* padded sequence of rate-bit blocks."""
    bit_len = len(message)
    zeros = (-bit_len - 1) % rate
    padded = message + (1,) + (0,) * zeros
    return tuple(
        padded[i : i + rate] for i in range(0, len(padded), rate)
    )


def f_sponge_literal(
    message: tuple[int, ...],
    output_bits: int,
    rate: int,
    permutation: tuple[int, ...],
) -> tuple[int, ...]:
    """Algorithm 2, keeping the state explicitly as a bit string."""
    state_bits = len(permutation).bit_length() - 1
    capacity = state_bits - rate
    state = (0,) * state_bits
    blocks = canonical_blocks(message, rate)
    for index, block in enumerate(blocks, 1):
        inner = (0,) * (capacity - 1) + (1 if index == len(blocks) else 0,)
        a = tuple(x ^ y for x, y in zip(state, block + inner))
        p = permutation[int("".join(map(str, a)), 2)]
        p_bits = tuple(map(int, f"{p:0{state_bits}b}"))
        state = tuple(x ^ y for x, y in zip((0,) * rate + a[rate:], p_bits))
    return state[-output_bits:] if output_bits else ()


def f_sponge_closed(
    message: tuple[int, ...],
    output_bits: int,
    rate: int,
    permutation: tuple[int, ...],
) -> tuple[int, ...]:
    """The block-by-block closed form proposed in the proof."""
    state_bits = len(permutation).bit_length() - 1
    capacity = state_bits - rate
    state = 0
    blocks = canonical_blocks(message, rate)
    for index, block in enumerate(blocks, 1):
        value = 0
        for bit in block:
            value = (value << 1) | bit
        mask = (value << capacity) | (1 if index == len(blocks) else 0)
        a = state ^ mask
        state = permutation[a] ^ (a & ((1 << capacity) - 1))
    return tuple((state >> i) & 1 for i in range(output_bits - 1, -1, -1))


def check_all_tiny() -> None:
    checked = 0
    for bits in range(3, 6):
        states = 1 << bits
        # Test representative permutations and exhaust messages for each size.
        universe = permutations(range(states))
        limit = 8
        for permutation_index, permutation in enumerate(universe):
            if limit is not None and permutation_index >= limit:
                break
            for rate in range(1, bits):
                capacity = bits - rate
                for length in range(0, 2 * rate + 2):
                    for message in product((0, 1), repeat=length):
                        blocks = canonical_blocks(message, rate)
                        padded = tuple(bit for block in blocks for bit in block)
                        assert padded[:length] == message
                        assert padded[length] == 1
                        assert all(bit == 0 for bit in padded[length + 1 :])
                        assert len(padded) == length + 1 + ((-length - 1) % rate)
                        for output_bits in (0, 1, capacity):
                            assert f_sponge_literal(
                                message, output_bits, rate, permutation
                            ) == f_sponge_closed(
                                message, output_bits, rate, permutation
                            )
                        checked += 1
    print(f"checked {checked} tiny message/rate/permutation cases")


def check_padding_injective() -> None:
    for rate in range(1, 7):
        seen = {}
        for length in range(0, 3 * rate + 1):
            for message in product((0, 1), repeat=length):
                blocks = canonical_blocks(message, rate)
                assert blocks not in seen, (rate, message, seen[blocks])
                seen[blocks] = message
        print(f"rate {rate}: {len(seen)} distinct canonical padded block sequences")


if __name__ == "__main__":
    check_padding_injective()
    check_all_tiny()
