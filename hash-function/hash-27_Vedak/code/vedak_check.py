#!/usr/bin/env python3
"""Independent Vedak replay from the allowlisted public specification.

This is a research workspace artifact.  It is not itself external evidence.
"""

from __future__ import annotations

import argparse
import json


SBOX = [
    0x1, 0x0, 0x5, 0x6, 0xC, 0x9, 0x2, 0x8,
    0xA, 0x7, 0x3, 0xF, 0xE, 0xB, 0x4, 0xD,
]

LAMBDA = [
    [1, 0, 1, 0, 0, 0, 1, 1, 1, 0],
    [0, 0, 1, 0, 1, 1, 0, 0, 1, 1],
    [1, 0, 0, 1, 0, 1, 1, 0, 0, 1],
    [0, 1, 0, 0, 1, 1, 1, 1, 0, 0],
    [0, 1, 0, 1, 0, 0, 0, 1, 1, 1],
    [1, 1, 1, 0, 0, 1, 0, 1, 0, 1],
    [1, 0, 0, 1, 1, 1, 0, 1, 1, 0],
    [0, 0, 1, 1, 1, 0, 1, 1, 0, 1],
    [0, 1, 1, 1, 0, 1, 1, 0, 1, 0],
    [1, 1, 0, 0, 1, 0, 1, 0, 1, 1],
]

PSI_WORD_PERM = [
    [5, 4, 7, 6, 1, 0, 3, 2],
    [2, 3, 0, 1, 6, 7, 4, 5],
    [6, 7, 4, 5, 2, 3, 0, 1],
    [7, 6, 5, 4, 3, 2, 1, 0],
    [3, 2, 1, 0, 7, 6, 5, 4],
    [0, 1, 2, 3, 4, 5, 6, 7],
    [0, 1, 3, 2, 4, 5, 7, 6],
    [4, 5, 7, 6, 0, 1, 3, 2],
    [5, 4, 6, 7, 1, 0, 2, 3],
    [1, 0, 2, 3, 5, 4, 6, 7],
]

PSI_ROT = [16, 4, 12, 0, 28, 0, 20, 12, 20, 4]

RC = [
    0x2C387D69, 0x988CC9DD, 0xF0E4A1B5, 0x21357064,
    0x8397D2C6, 0xC7D39682, 0x4F5B1E0A, 0x5E4A0F1B,
    0x7C682D39, 0x392D687C, 0xB3A7E2F6, 0xA7B3F6E2,
    0x8E9ADFCB, 0xDCC88D99, 0x786C293D, 0x30246175,
    0xA1B5F0E4, 0x8296D3C7, 0xC5D19480, 0x4A5E1B0F,
    0x55410410, 0x6B7F3A2E, 0x17034652, 0xEFFBBEAA,
    0x1F0B4E5A, 0xFFEBAEBA, 0x3F2B6E7A, 0xBFABEEFA,
    0xBEAAEFFB, 0xBCA8EDF9, 0xB9ADE8FC, 0xB2A6E3F7,
    0xA5B1F4E0, 0x8B9FDACE, 0xD7C38692, 0x6F7B3E2A,
    0x1E0A4F5B, 0xFDE9ACB8, 0x3A2E6B7F, 0xB4A0E5F1,
]

EXPECTED = {
    512: "3C1C2861280A70892B6719B7D338AB329C0B4B45C6B46B6B47950665ED5827FF"
         "9B6821925DE2FB7FDCD8F3F3E4013CF08437C3A3C2720404F03EE8A8EA8BAF39",
    768: "2D535433095A3EB2AE6CEC3C3BE08D69FE1C5436E392A45A2B888BFDDAB2AB6F"
         "9F6702EA9E68A0AB16A04E3F42A986B96AEC8DF56D9B6B1892CFA3A5341D6D30"
         "C071FBA5E309E1EA0B6D9CD1CF3BFFC733B87ECBCB4489021004D29F13124611",
    1024: "71ABEDCA7503D3D6B64A08F9794AE32F4732BC71056EDA9CF0F6912E5595A765"
          "36A414EF078B829CA8B37D13A8834FDDC7B189DDF019812E2E6B2765FA562E1912"
          "0FF593585FBDCF2F4DB33335214EB37C973D8A33218B64578D03AB58FB9F1DD082"
          "EB1DCDBD81512F177BC7CFD3924AFB3BC0D6DB75BF751D8C24E897BADCAA",
}


def rol32(x: int, n: int) -> int:
    n %= 32
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def ror32(x: int, n: int) -> int:
    n %= 32
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def nibbles_to_word(ns: list[int], low_nibble_first: bool = False) -> int:
    if low_nibble_first:
        return sum(x << (4 * i) for i, x in enumerate(ns))
    out = 0
    for x in ns:
        out = (out << 4) | x
    return out


def word_to_nibbles(x: int, low_nibble_first: bool = False) -> list[int]:
    if low_nibble_first:
        return [(x >> (4 * i)) & 0xF for i in range(16)]
    return [(x >> (60 - 4 * i)) & 0xF for i in range(16)]


def nu(state: list[list[int]]) -> list[list[int]]:
    return [[[SBOX[x] for x in word] for word in row] for row in state]


def lam(state: list[list[int]]) -> list[list[int]]:
    """Apply the specified binary 10x10 matrix to every nibble bit slice."""
    out = [[[0] * 16 for _ in range(4)] for _ in range(10)]
    for col in range(4):
        for k in range(16):
            values = [state[i][col][k] for i in range(10)]
            for i, row in enumerate(LAMBDA):
                y = 0
                for j, coefficient in enumerate(row):
                    if coefficient:
                        y ^= values[j]
                out[i][col][k] = y
    return out


def psi(
    state: list[list[int]],
    low_nibble_first: bool = False,
    inverse_perm: bool = False,
    inverse_rotation: bool = False,
) -> list[list[int]]:
    out = [[0] * 4 for _ in range(10)]
    for row in range(10):
        words64 = [nibbles_to_word(word, low_nibble_first) for word in state[row]]
        words32 = []
        for word in words64:
            words32.extend([(word >> 32) & 0xFFFFFFFF, word & 0xFFFFFFFF])
        perm = PSI_WORD_PERM[row]
        if inverse_perm:
            inverse = [0] * 8
            for dst, src in enumerate(perm):
                inverse[src] = dst
            perm = inverse
        rot = PSI_ROT[row]
        fn = ror32 if inverse_rotation else rol32
        moved = [fn(words32[perm[j]], rot) for j in range(8)]
        for j in range(4):
            word = (moved[2 * j] << 32) | moved[2 * j + 1]
            out[row][j] = word_to_nibbles(word, low_nibble_first)
    return out


def omega(
    state: list[list[int]],
    round_index: int,
    low_nibble_first: bool = False,
    rc_low: bool = False,
) -> list[list[int]]:
    out = [[word[:] for word in row] for row in state]
    word = nibbles_to_word(out[0][0], low_nibble_first)
    rc = RC[round_index]
    # "first 8 nibbles" = upper 32 bits in MSB-first words, lower in LSB-first.
    word ^= rc if rc_low == low_nibble_first else rc << 32
    out[0][0] = word_to_nibbles(word, low_nibble_first)
    return out


def permutation(
    state: list[list[int]],
    *,
    low_nibble_first: bool = False,
    inverse_perm: bool = False,
    inverse_rotation: bool = False,
    rc_low: bool = False,
) -> list[list[int]]:
    for r in range(40):
        state = nu(state)
        state = lam(state)
        state = psi(state, low_nibble_first, inverse_perm, inverse_rotation)
        state = omega(state, r, low_nibble_first, rc_low)
    return state


def empty_state() -> list[list[int]]:
    return [[[0] * 16 for _ in range(4)] for _ in range(10)]


def absorb_empty_block(
    state: list[list[int]], rate: int, *, first_bit_low: bool
) -> list[list[int]]:
    # pad10*1 for the empty string in one rate block.
    for pos in (0, rate - 1):
        word = pos // 64
        bit = pos % 64
        i, j = divmod(word, 4)
        if first_bit_low:
            state[i][j][15 - bit // 4] ^= 1 << (bit % 4)
        else:
            state[i][j][bit // 4] ^= 1 << (3 - bit % 4)
    return state


def xor_bitstring_into_rate(
    state: list[list[int]], block: str, *, first_bit_low: bool
) -> list[list[int]]:
    """XOR a hexadecimal rate block in message order into the first |block| bits."""
    for pos, ch in enumerate(block):
        nib = int(ch, 16)
        for off, value in enumerate((8, 4, 2, 1)):
            if not value & nib:
                continue
            bitpos = 4 * pos + off
            word, bit = divmod(bitpos, 64)
            i, j = divmod(word, 4)
            if first_bit_low:
                state[i][j][15 - bit // 4] ^= 1 << (bit % 4)
            else:
                state[i][j][bit // 4] ^= 1 << (3 - bit % 4)
    return state


def pad_hex_message(msg: str, rate: int) -> str:
    bits = "".join(f"{int(ch, 16):04b}" for ch in msg)
    t = (-len(bits) - 2) % rate
    bits += "1" + "0" * t + "1"
    assert len(bits) % rate == 0
    return "".join(f"{int(bits[i:i + 4], 2):X}" for i in range(0, len(bits), 4))


def hash_hex(
    msg: str,
    rate: int,
    digest_bits: int,
    *,
    low_nibble_first: bool,
    first_bit_low: bool,
    inverse_perm: bool = False,
    inverse_rotation: bool = False,
    rc_low: bool = False,
) -> str:
    padded = pad_hex_message(msg, rate)
    blocks = [padded[i:i + rate // 4] for i in range(0, len(padded), rate // 4)]
    state = empty_state()
    for block in blocks:
        state = xor_bitstring_into_rate(state, block, first_bit_low=first_bit_low)
        state = permutation(
            state,
            low_nibble_first=low_nibble_first,
            inverse_perm=inverse_perm,
            inverse_rotation=inverse_rotation,
            rc_low=rc_low,
        )
    nibs: list[int] = []
    while len(nibs) * 4 < digest_bits:
        nibs.extend(state_nibbles(state)[: rate // 4])
        if len(nibs) * 4 < digest_bits:
            state = permutation(
                state,
                low_nibble_first=low_nibble_first,
                inverse_perm=inverse_perm,
                inverse_rotation=inverse_rotation,
                rc_low=rc_low,
            )
    bits = []
    for nib in nibs[:digest_bits // 4]:
        for b in range(3, -1, -1):
            bits.append((nib >> b) & 1)
    if first_bit_low:
        bits = [bits[i] for i in range(0, len(bits), 4)
                for i2 in (i + 3, i + 2, i + 1, i)]
    out = 0
    for bit in bits:
        out = (out << 1) | bit
    return f"{out:0{digest_bits // 4}X}"


def state_nibbles(state: list[list[int]]) -> list[int]:
    return [nib for row in state for word in row for nib in word]


def digest_empty(
    rate: int,
    digest_bits: int,
    *,
    low_nibble_first: bool,
    first_bit_low: bool,
    inverse_perm: bool = False,
    inverse_rotation: bool = False,
    rc_low: bool = False,
) -> str:
    state = absorb_empty_block(empty_state(), rate, first_bit_low=first_bit_low)
    state = permutation(
        state,
        low_nibble_first=low_nibble_first,
        inverse_perm=inverse_perm,
        inverse_rotation=inverse_rotation,
        rc_low=rc_low,
    )
    nibs: list[int] = []
    while len(nibs) * 4 < digest_bits:
        nibs.extend(state_nibbles(state)[: rate // 4])
        if len(nibs) * 4 < digest_bits:
            state = permutation(
                state,
                low_nibble_first=low_nibble_first,
                inverse_perm=inverse_perm,
                inverse_rotation=inverse_rotation,
                rc_low=rc_low,
            )
    bits = []
    for nib in nibs[:digest_bits // 4]:
        for b in range(3, -1, -1):
            bits.append((nib >> b) & 1)
    if first_bit_low:
        bits = [bits[i] for i in range(0, len(bits), 4)
                for i2 in (i + 3, i + 2, i + 1, i)]
    out = 0
    for bit in bits:
        out = (out << 1) | bit
    return f"{out:0{digest_bits // 4}X}"


def try_all() -> list[dict]:
    results = []
    for low_nibble_first in (False, True):
        for inverse_perm in (False, True):
            for inverse_rotation in (False, True):
                for rc_low in (False, True):
                    for first_bit_low in (False, True):
                        row = {
                            "low_nibble_first": low_nibble_first,
                            "inverse_perm": inverse_perm,
                            "inverse_rotation": inverse_rotation,
                            "rc_low": rc_low,
                            "first_bit_low": first_bit_low,
                            "matches": [],
                        }
                        for digest, rate in ((512, 1536), (768, 1024), (1024, 512)):
                            got = digest_empty(
                                rate,
                                digest,
                                low_nibble_first=low_nibble_first,
                                first_bit_low=first_bit_low,
                                inverse_perm=inverse_perm,
                                inverse_rotation=inverse_rotation,
                                rc_low=rc_low,
                            )
                            row[f"vedak_{digest}"] = got
                            row["matches"].append(got == EXPECTED[digest])
                        results.append(row)
    return results


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--test-vectors", action="store_true")
    args = ap.parse_args()
    if args.test_vectors:
        for row in try_all():
            print(json.dumps(row, sort_keys=True))


if __name__ == "__main__":
    main()
