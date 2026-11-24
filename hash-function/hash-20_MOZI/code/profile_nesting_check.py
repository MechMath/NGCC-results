#!/usr/bin/env python3
"""Toy corroboration for the MOZI profile-nesting theorem.

This checks the structural prefix/suffix identities on an 8-bit generic
permutation with analogous rate/capacity pairs. It is not evidence about the
2048-bit MOZI permutation or any security level.
"""

import itertools
import random


STATE_BITS = 8


def random_permutation(seed: int) -> dict[tuple[str, ...], tuple[str, ...]]:
    rng = random.Random(seed)
    domain = list(itertools.product("01", repeat=STATE_BITS))
    image = domain[:]
    rng.shuffle(image)
    return dict(zip(domain, image))


def pad(message: str, rate: int) -> list[str]:
    zeros = (-(len(message) + 1)) % rate
    padded = message + "1" + "0" * zeros
    return [padded[i : i + rate] for i in range(0, len(padded), rate)]


def sponge(
    message: str,
    permutation: dict[tuple[str, ...], tuple[str, ...]],
    rate: int,
    output_bits: int,
) -> str:
    state = "0" * STATE_BITS
    for block in pad(message, rate):
        capacity = "0" * (STATE_BITS - rate)
        state = "".join(
            permutation[
                tuple(str(int(a) ^ int(b)) for a, b in zip(state, block + capacity))
            ]
        )
    return state[:output_bits]


def f_sponge(
    message: str,
    permutation: dict[tuple[str, ...], tuple[str, ...]],
    rate: int,
    capacity: int,
    output_bits: int,
) -> str:
    state = "0" * STATE_BITS
    blocks = pad(message, rate)
    for index, block in enumerate(blocks):
        final_mask = "0" * (capacity - 1) + ("1" if index + 1 == len(blocks) else "0")
        perm_input = "".join(
            str(int(a) ^ int(b)) for a, b in zip(state, block + final_mask)
        )
        state = "0" * rate + perm_input[rate:]
        state = "".join(
            str(int(a) ^ int(b)) for a, b in zip(state, permutation[tuple(perm_input)])
        )
    return state[-output_bits:]


def messages(max_bits: int):
    yield from ("".join(bits) for n in range(max_bits + 1) for bits in itertools.product("01", repeat=n))


def main() -> None:
    sponge_permutation = random_permutation(104)
    for message in messages(2):
        short = sponge(message, sponge_permutation, rate=5, output_bits=2)
        long = sponge(message, sponge_permutation, rate=3, output_bits=4)
        assert short == long[:2]

    f_permutation = random_permutation(104)
    for message in messages(2):
        low = f_sponge(message, f_permutation, rate=5, capacity=3, output_bits=2)
        high = f_sponge(message, f_permutation, rate=3, capacity=5, output_bits=4)
        assert low == high[-2:]

    print("passed: 7 Sponge prefix cases and 7 F-SPONGE suffix cases")


if __name__ == "__main__":
    main()
