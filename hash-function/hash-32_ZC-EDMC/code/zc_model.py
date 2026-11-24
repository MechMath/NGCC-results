#!/usr/bin/env python3
"""Bit-exact ZC-EDMC model for the pinned hash-32 specification.

State serialization is x-major within the rectangular state:
bit 64*(y_dim*x + y) + z, with API bits read from least to most significant.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


ROUND_CONSTANTS = [
    0x58,
    0x38,
    0x3C0,
    0xD0,
    0x60,
    0x120,
    0x14,
    0x2C,
    0xF0,
    0x1A0,
    0x380,
    0x12,
]


def rol64(value: int, amount: int) -> int:
    amount %= 64
    return ((value << amount) | (value >> (64 - amount))) & ((1 << 64) - 1)


def xor_all(values: Iterable[int]) -> int:
    out = 0
    for value in values:
        out ^= value
    return out


@dataclass(frozen=True)
class ZC:
    x_dim: int
    y_dim: int
    theta_rotations: tuple[int, int]
    rho_rotations: tuple[tuple[int, int], ...]

    @property
    def m(self) -> int:
        return self.x_dim * self.y_dim * 64

    @classmethod
    def zc1280(cls) -> "ZC":
        return cls(
            x_dim=4,
            y_dim=5,
            theta_rotations=(5, 14),
            rho_rotations=((0, 0), (1, 5), (3, 24), (0, 1), (2, 3)),
        )

    @classmethod
    def zc1536(cls) -> "ZC":
        return cls(
            x_dim=8,
            y_dim=3,
            theta_rotations=(20, 56),
            rho_rotations=((0, 0), (3, 3), (5, 0)),
        )

    def state_from_int(self, value: int) -> list[list[int]]:
        if value < 0 or value >= 1 << self.m:
            raise ValueError("state out of range")
        lanes = [[0] * self.x_dim for _ in range(self.y_dim)]
        for x in range(self.x_dim):
            for y in range(self.y_dim):
                shift = 64 * (self.y_dim * x + y)
                lanes[y][x] = (value >> shift) & ((1 << 64) - 1)
        return lanes

    def int_from_state(self, state: list[list[int]]) -> int:
        value = 0
        for x in range(self.x_dim):
            for y in range(self.y_dim):
                shift = 64 * (self.y_dim * x + y)
                value |= (state[y][x] & ((1 << 64) - 1)) << shift
        return value

    def iota(self, state: list[list[int]], constant: int) -> list[list[int]]:
        out = [row[:] for row in state]
        out[0][0] ^= constant
        return out

    def chi(self, state: list[list[int]]) -> list[list[int]]:
        out = [row[:] for row in state]
        mask = (1 << 64) - 1
        for y in range(self.y_dim):
            y1 = (y + 1) % self.y_dim
            y2 = (y + 2) % self.y_dim
            for x in range(self.x_dim):
                out[y][x] = state[y][x] ^ ((~state[y1][x] & mask) & state[y2][x])
        return out

    def rho(self, state: list[list[int]]) -> list[list[int]]:
        out = [[0] * self.x_dim for _ in range(self.y_dim)]
        for y in range(self.y_dim):
            x_rot, z_rot = self.rho_rotations[y]
            for x in range(self.x_dim):
                x_src = (x - x_rot) % self.x_dim
                out[y][x] = rol64(state[y][x_src], z_rot)
        return out

    def theta(self, state: list[list[int]]) -> list[list[int]]:
        parity = []
        for x in range(self.x_dim):
            parity.append(xor_all(state[y][x] for y in range(self.y_dim)))
        a_rot, b_rot = self.theta_rotations
        effect = [
            rol64(parity[(x - 1) % self.x_dim], a_rot)
            ^ rol64(parity[(x - 1) % self.x_dim], b_rot)
            for x in range(self.x_dim)
        ]
        return [[lane ^ effect[x] for x, lane in enumerate(row)] for row in state]

    def round(self, state: list[list[int]], constant: int) -> list[list[int]]:
        state = self.iota(state, constant)
        state = self.chi(state)
        state = self.rho(state)
        state = self.theta(state)
        return self.rho(state)

    def rounds(
        self,
        state: list[list[int]],
        constants: Iterable[int],
    ) -> list[list[int]]:
        for constant in constants:
            state = self.round(state, constant)
        return state

    def permute_int(self, value: int) -> int:
        state = self.rounds(self.state_from_int(value), ROUND_CONSTANTS)
        return self.int_from_state(state)

    def first_half_int(self, value: int) -> int:
        state = self.rounds(self.state_from_int(value), ROUND_CONSTANTS[:6])
        return self.int_from_state(state)

    def second_half_int(self, value: int) -> int:
        state = self.rounds(self.state_from_int(value), ROUND_CONSTANTS[6:])
        return self.int_from_state(state)

    def digest_bits(self, message: str, n: int, c: int, reading: str) -> str:
        """Hash a bit string using sequential Algorithm 3 semantics.

        reading is "hg" for F=h(g(X) xor 0^r||X_c), or "hh" for
        F=h(h(X) xor 0^r||X_c).
        """
        if reading not in {"hg", "hh"}:
            raise ValueError("reading must be hg or hh")
        r = self.m - c
        padded = message + "01"
        j = (-(len(padded) + 2)) % r
        padded += "1" + "0" * j + "1"
        if len(padded) % r:
            raise AssertionError("padding length")
        if len(padded) == 0:
            raise AssertionError("empty padded message")

        def bits_to_int(bits: str) -> int:
            value = 0
            for index, bit in enumerate(bits):
                if bit == "1":
                    value |= 1 << index
            return value

        mask = (1 << self.m) - 1
        mask_rate = (1 << r) - 1
        mask_cap = mask ^ mask_rate
        blocks = [padded[i : i + r] for i in range(0, len(padded), r)]
        state = bits_to_int(blocks[0])

        for block in blocks[1:]:
            x = state
            if reading == "hg":
                inner = self.first_half_int(x)
            else:
                inner = self.second_half_int(x)
            inner ^= x & mask_cap
            state = self.second_half_int(inner)
            state ^= bits_to_int(block)

        x = state
        if reading == "hg":
            inner = self.first_half_int(x)
        else:
            inner = self.second_half_int(x)
        inner ^= x & mask_cap
        state = self.second_half_int(inner)

        output = ""
        while len(output) < n:
            rate = state & mask_rate
            output += "".join(
                "1" if (rate >> z) & 1 else "0" for z in range(r)
            )
            state = self.permute_int(state)
        return output[:n]

    def digest(self, message: str, n: int, c: int, reading: str) -> str:
        digest_bits = self.digest_bits(message, n, c, reading)
        return "".join(
            f"{sum(int(digest_bits[i + j]) << (7 - j) for j in range(8)):02x}"
            for i in range(0, n, 8)
        )


def expected_vectors() -> list[tuple[str, str, int, int, str, str]]:
    return [
        (
            "ZC-1280-EDMc[576,512] empty",
            "zc1280",
            512,
            576,
            "hh",
            "637db5c645e75ec4b9d8c3e90784597080c63dcd18675ef2a3dcf4cb29603f6c37d2af7b18f717cfbc7e7c6cf2b902f4795b0e1418b48cd4ffe86237b643f43b",
        ),
        (
            "ZC-1280-EDMc[576,512] empty",
            "zc1280",
            512,
            576,
            "hg",
            "8d391dc0a40f9a3b63c8f870f6397708dbc3f76466c7a22f01eb0c88e044429ee4f98e05ac1f7552a17cf4573362c0043577b3d168b2ca0123602658dcf3955c",
        ),
        (
            "ZC-1536-EDMc[576,512] empty",
            "zc1536",
            512,
            576,
            "hh",
            "9f3811afed48b7c7aa59adfcc705b1beacae3746a27f311a5ca68d40410ca705d1462970196ed96ad0986f5bce9ef3a44177a69488312d31518faf95788cb709",
        ),
        (
            "ZC-1536-EDMc[576,512] empty",
            "zc1536",
            512,
            576,
            "hg",
            "6490d308ddb9e33d0dedd09bb87e22b47054282ca2e9a9634fcc06bd40de7781fb35472aff789e22907a81de299c0f76a3e913381291816fec60b600662c5d87",
        ),
    ]


def self_test() -> None:
    failures = []
    for label, variant, n, c, reading, expected in expected_vectors():
        obj = ZC.zc1280() if variant == "zc1280" else ZC.zc1536()
        digest = obj.digest("", n, c, reading)
        ok = digest == expected
        print(f"{label} {reading}: {'OK' if ok else 'FAIL'}")
        print(digest)
        if not ok:
            failures.append((label, reading, digest, expected))
    if failures:
        raise SystemExit(f"{len(failures)} vector failures")


if __name__ == "__main__":
    self_test()
