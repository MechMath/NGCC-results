#!/usr/bin/env python3
"""Probe the state/bitstring serialization omitted by the ZC-DM specification.

This is a research note, not execution evidence.  It implements ZC-1280 and
ZC-DM-1280-DM-512 directly from pages 5-14 of hash-30-spec.pdf under two
canonical serializations of the coordinate-based state.
"""

from __future__ import annotations

from dataclasses import dataclass


MASK64 = (1 << 64) - 1

# Table 1.1, with index i in -11,...,0.
ROUND_CONSTANTS = {
    -11: 0x0000000000000058,
    -10: 0x0000000000000038,
    -9: 0x00000000000003C0,
    -8: 0x00000000000000D0,
    -7: 0x0000000000000060,
    -6: 0x0000000000000120,
    -5: 0x0000000000000014,
    -4: 0x000000000000002C,
    -3: 0x00000000000000F0,
    -2: 0x00000000000001A0,
    -1: 0x0000000000000380,
    0: 0x0000000000000012,
}


def rol64(x: int, n: int) -> int:
    n %= 64
    if n == 0:
        return x
    return ((x << n) | (x >> (64 - n))) & MASK64


def rho(planes: list[list[int]]) -> list[list[int]]:
    """Apply the page-7/page-10 plane shift."""
    out = [plane[:] for plane in planes]
    for x in range(4):
        out[1][x] = rol64(planes[1][(x - 1) % 4], 5)
        out[2][x] = rol64(planes[2][(x - 3) % 4], 24)
        out[3][x] = rol64(planes[3][x], 1)
        out[4][x] = rol64(planes[4][(x - 2) % 4], 3)
    return out


def zc1280_permute(state: list[list[int]]) -> list[list[int]]:
    """Apply the 12 rounds of ZC-1280 (page 11, Algorithm 1)."""
    a = [plane[:] for plane in state]
    for round_index in range(-11, 1):
        a[0][0] ^= ROUND_CONSTANTS[round_index]

        old = [plane[:] for plane in a]
        for x in range(4):
            a[0][x] = old[0][x] ^ ((~old[1][x] & MASK64) & old[2][x])
            a[1][x] = old[1][x] ^ ((~old[2][x] & MASK64) & old[3][x])
            a[2][x] = old[2][x] ^ ((~old[3][x] & MASK64) & old[4][x])
            a[3][x] = old[3][x] ^ ((~old[4][x] & MASK64) & old[0][x])
            a[4][x] = old[4][x] ^ ((~old[0][x] & MASK64) & old[1][x])

        a = rho(a)
        parity = [a[0][x] ^ a[1][x] ^ a[2][x] ^ a[3][x] ^ a[4][x]
                  for x in range(4)]
        effect = [
            rol64(parity[(x - 1) % 4], 5) ^ rol64(parity[(x - 1) % 4], 14)
            for x in range(4)
        ]
        for y in range(5):
            for x in range(4):
                a[y][x] ^= effect[x]
        a = rho(a)
    return a


@dataclass(frozen=True)
class Serialization:
    name: str
    coordinate_order: tuple[str, str, str]

    def offset(self, coordinates: dict[str, int]) -> int:
        offset = 0
        for axis in self.coordinate_order:
            offset = offset * ({"x": 4, "y": 5, "z": 64}[axis]) + coordinates[axis]
        return offset


SERIALIZATIONS = (
    Serialization("x-y-z", ("x", "y", "z")),
    Serialization("y-x-z", ("y", "x", "z")),
)


def load_bits(bits: list[int], serialization: Serialization) -> list[list[int]]:
    reverse = {
        serialization.offset({"x": x, "y": y, "z": z}): (y, x, z)
        for y in range(5)
        for x in range(4)
        for z in range(64)
    }
    state = [[0] * 4 for _ in range(5)]
    for bit_index, bit in enumerate(bits):
        if bit:
            y, x, z = reverse[bit_index]
            state[y][x] |= 1 << z
    return state


def state_bits(state: list[list[int]], serialization: Serialization) -> list[int]:
    reverse = {
        serialization.offset({"x": x, "y": y, "z": z}): (y, x, z)
        for y in range(5)
        for x in range(4)
        for z in range(64)
    }
    return [
        (state[y][x] >> z) & 1
        for bit_index in range(1280)
        for y, x, z in (reverse[bit_index],)
    ]


def pad(message: list[int], rate: int = 704) -> list[int]:
    """Append 01||10*1 exactly as on pages 13-14."""
    padded = message + [0, 1]
    j = (-(len(padded) + 2)) % rate
    padded += [1] + [0] * j + [1]
    assert len(padded) % rate == 0
    return padded


def hash_one_block_512(
    message: list[int], serialization: Serialization
) -> list[int]:
    padded = pad(message)
    assert len(padded) == 704
    initial = load_bits(padded, serialization)
    permuted = zc1280_permute(initial)
    fed_forward = [
        [permuted[y][x] ^ initial[y][x] for x in range(4)]
        for y in range(5)
    ]
    return state_bits(fed_forward, serialization)[:512]


def bits_to_hex(bits: list[int]) -> str:
    """Render a serialized bitstring with bit 0 as bit 0 of the first byte."""
    out = bytearray()
    for start in range(0, len(bits), 8):
        value = 0
        for offset, bit in enumerate(bits[start:start + 8]):
            value |= bit << offset
        out.append(value)
    return out.hex()


def main() -> None:
    # A definite bitstring, avoiding any separate byte-to-bit convention.
    message = [int(bit) for bit in "10110011100011110000111101010101" * 4]
    assert len(message) == 128
    digests = [
        hash_one_block_512(message, serialization)
        for serialization in SERIALIZATIONS
    ]
    expected_prefixes = (
        "1111100111100001100011000001011101110111110111110010011001010010",
        "0111001111100100101100000010011011101111001101011100011110100100",
    )
    assert tuple("".join(map(str, digest[:64])) for digest in digests) == expected_prefixes
    for serialization, digest in zip(SERIALIZATIONS, digests):
        print(serialization.name)
        print("first-64-bits", "".join(map(str, digest[:64])))
        print("digest-hex", bits_to_hex(digest))
    print("differing-count", sum(a != b for a, b in zip(*digests)))


if __name__ == "__main__":
    main()
