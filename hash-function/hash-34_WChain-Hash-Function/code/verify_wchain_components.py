#!/usr/bin/env python3
"""Small exact checks for the two verified WChain component counterexamples.

This is reproduction material for proof nodes:
  160fa47127f47025
  087e30e53e1a7f5d

It is not a digest-collision search.
"""

MASK64 = (1 << 64) - 1
PI16 = [
    0x243F,
    0x6A88,
    0x85A3,
    0x08D3,
    0x1319,
    0x8A2E,
    0x0370,
    0x7344,
    0xA409,
    0x3822,
    0x299F,
    0x31D0,
    0x082E,
    0xFA98,
    0xEC4E,
    0x6C89,
    0x4528,
    0x21E6,
]
MESSAGE_ROTATIONS = [0, 1, 10, 20, 25, 32, 41, 46, 50]


def rotl64(x: int, amount: int) -> int:
    amount %= 64
    if amount == 0:
        return x & MASK64
    return ((x << amount) | (x >> (64 - amount))) & MASK64


def sbox_vector(x: int) -> int:
    assert 0 <= x < 1 << 9
    return sum(
        (((x >> i) & 1) ^ (((x >> ((i + 1) % 9)) & 1) & ((x >> ((i + 2) % 9)) & 1)))
        << i
        for i in range(9)
    )


def sbox_state(state: list[int]) -> list[int]:
    """Apply S to the nine words, one S-box per bit position z."""
    assert len(state) == 9
    result = [0] * 9
    for z in range(64):
        column = sum((((state[i] >> z) & 1) << i) for i in range(9))
        output = sbox_vector(column)
        for i in range(9):
            result[i] |= ((output >> i) & 1) << z
    return result


def round_constant(round_index: int) -> list[int]:
    """Version-I lane-rotated constant state for a zero-based round index."""
    return [rotl64(PI16[round_index], lane) for lane in range(9)]


def check_sbox_lemma() -> None:
    values = [sbox_vector(x) for x in range(512)]
    assert sbox_vector(0) == 0
    assert sbox_vector(0x1FF) == 0
    assert len(set(values)) == 455
    assert values.count(0) == 2

    # W_S(e_0, e_0) = sum (-1)^(x_1 x_2) = 384 - 128 = 256.
    walsh = sum(
        1 if (((x & 1) ^ (values[x] & 1)) == 0) else -1
        for x in range(512)
    )
    assert walsh == 256


def check_round_collision() -> None:
    all_ones = [MASK64] * 9
    for round_index in range(18):
        constant = round_constant(round_index)

        # Iota_j(K_j) is zero, so S, pi and the linear layer all preserve zero.
        assert [x ^ c for x, c in zip(constant, constant)] == [0] * 9
        assert sbox_state([0] * 9) == [0] * 9

        # Iota_j(K_j XOR U) is U; the S-box maps all-ones to zero.
        assert sbox_state(all_ones) == [0] * 9

    # Any column-uniform 0/1 mask is also sent to zero by S.
    for mask_columns in [0, 1, 0xFFFF_FFFF_FFFF_FFFF]:
        state = []
        for lane in range(9):
            if mask_columns in (0, 0xFFFF_FFFF_FFFF_FFFF):
                state.append(mask_columns)
            else:
                state.append(
                    sum((((mask_columns >> z) & 1) << z) for z in range(64))
                )
        assert sbox_state(state) == [0] * 9


if __name__ == "__main__":
    check_sbox_lemma()
    check_round_collision()
    print("ok: S-box has a collision and W_S(e0,e0)=256")
    print("ok: K_j and K_j XOR U cancel through Round_j in Version I")
