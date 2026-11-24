#!/usr/bin/env python3
"""Independent literal implementation of Thunder-p and fixed-output Thunder.

The implementation follows the pinned specification only:
thunder-hash-33-spec.pdf, SHA-256
f6fafe152124757787f54db3869bb7ef7d8106e8a7293ee341d511ec279e7d36.

Lane representation: state[x][y] is a Python integer.  Bit z is bit z of
that integer.  The operations are implemented directly from the formulas in
Section 2.3; pi is deliberately applied in the literal coordinate order
D'[y][2*x+3*y+2] = D[x][y], not by assuming Keccak's pi convention.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

MASK64 = (1 << 64) - 1

ROUND_CONSTANTS = (
    0x0000000000000001,
    0x0000000000000003,
    0x000000000000000A,
    0x0000000000000088,
    0x0000000000008081,
    0x0000000000008002,
    0x0000000000000009,
    0x0000000000000083,
    0x000000000000800A,
    0x0000000000000089,
    0x0000000000008083,
    0x000000000000800B,
)

# Table 3, indexed [x][y].  Values are transcribed by columns from the PDF table.
TAU = (
    (45, 40, 34, 48, 6),
    (33, 52, 5, 30, 18),
    (13, 19, 0, 61, 49),
    (1, 47, 2, 8, 17),
    (27, 9, 37, 38, 43),
)

# Table 4.  Column zero is y; the remaining columns are r,s,t_y,u.
THETA_PARAMS = (
    (0, 1, 36, 41, 26),
    (1, 1, 36, 50, 26),
    (2, 1, 36, 6, 26),
    (3, 1, 36, 10, 26),
    (4, 1, 36, 27, 26),
)

FIXED_OUTPUT_PARAMS = {
    "Thunder-512": {
        "h": 512,
        "c": 576,
        "r": 1024,
        "nc": 9,
        "nr": 16,
        "iv": (
            0xBF6F0F35E3B4B690,
            0x8E265B9343C855BE,
            0x246B722CBB56513A,
            0xBC2F395FD06923B4,
            0xDD524527A77295D2,
            0x41E818D4F5A362FC,
            0x694AD1341F066571,
            0x9B04C99DC477B767,
            0x385EC0E6C2C9262C,
        ),
    },
    "Thunder-768": {
        "h": 768,
        "c": 832,
        "r": 768,
        "nc": 13,
        "nr": 12,
        "iv": (
            0x1EE2C8609716E1FD,
            0x9C67610B0EF5484C,
            0x1E6D7FF8F050881C,
            0xCC3FA3279D6371F6,
            0xDB34E00BB8122876,
            0xB9839A4AF0CAE3D5,
            0xDCFA816272A35C8C,
            0x55FBD3148A3A352A,
            0x900E93CA9A4A9953,
            0x9CCCEF7ACDC19758,
            0xA7A16EAC10689E8C,
            0x676B3791EBA6281C,
            0xE1F7C9010E8EC178,
        ),
    },
    "Thunder-1024": {
        "h": 1024,
        "c": 1088,
        "r": 512,
        "nc": 17,
        "nr": 8,
        "iv": (
            0xF40BA520BF2176AF,
            0x6CA062C126D8F82F,
            0xDE0AF08D84B563FD,
            0x9DE9EBB8E116C786,
            0x0E88F98C2AFD6C77,
            0xCC6BB54C5AB31102,
            0x92814BCC238CCEBA,
            0x6AF2AB07A720737F,
            0x95D75D8EE27A1149,
            0x9F76C65C5E81FEAD,
            0xF201204809F567F0,
            0x717EF7874FDF8324,
            0x1E74332499E4122A,
            0xF8935180A66B22D6,
            0x948CDBECC8BAE9D8,
            0x2C44DD200F6D93DE,
            0x24503F60BF3CA4C8,
        ),
    },
}

State = tuple[tuple[int, ...], ...]


def rotl64(x: int, n: int) -> int:
    n %= 64
    return ((x << n) | (x >> (64 - n))) & MASK64 if n else x & MASK64


def rotr64(x: int, n: int) -> int:
    return rotl64(x, -n)


def iota(state: State, round_index: int) -> State:
    out = [list(row) for row in state]  # [x][y]
    out[0][0] ^= ROUND_CONSTANTS[round_index]
    return tuple(tuple(row) for row in out)


def rho(state: State) -> State:
    # D'[x][y][z] = D[x][y][z+tau(x,y)] is a right rotation.
    return tuple(
        tuple(rotr64(state[x][y], TAU[x][y]) for y in range(5))
        for x in range(5)
    )


def theta(state: State) -> State:
    # P[x][z] and Q[x][z] use the post-rho state.
    p = [0] * 5
    q = [0] * 5
    for x in range(5):
        p[x] = state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]
        q[x] = (
            state[x][0]
            ^ rotr64(state[x][1], 50)
            ^ rotr64(state[x][2], 6)
            ^ rotr64(state[x][3], 10)
            ^ rotr64(state[x][4], 27)
        )
    e = [p[x] ^ rotr64(p[(x - 1) % 5], 1) for x in range(5)]
    f = [q[(x + 1) % 5] ^ rotr64(q[(x - 2) % 5], 36) for x in range(5)]
    return tuple(
        tuple(
            state[x][y]
            ^ rotr64(e[x], 26)
            ^ rotr64(f[x], (26 + THETA_PARAMS[y][3]) % 64)
            for y in range(5)
        )
        for x in range(5)
    )


def pi(state: State) -> State:
    # Literal relation D'[y][2x+3y+2][z] = D[x][y][z].
    out = [[0] * 5 for _ in range(5)]
    for x in range(5):
        for y in range(5):
            out[y][(2 * x + 3 * y + 2) % 5] = state[x][y]
    return tuple(tuple(row) for row in out)


def _psi_word(column: tuple[int, int, int, int, int]) -> tuple[int, int, int, int, int]:
    a = column
    return tuple(
        a[(y + 3) % 5]
        ^ ((a[(y + 1) % 5] ^ 1) & a[(y + 2) % 5] & (a[(y + 4) % 5] ^ 1))
        for y in range(5)
    )


def psi(state: State) -> State:
    # For each fixed (x,z), all five y bits pass through the S-box together.
    # Each 64-bit lane computes all z coordinates in parallel.
    return tuple(
        tuple(
            state[x][(y + 3) % 5]
            ^ (
                (state[x][(y + 1) % 5] ^ MASK64)
                & state[x][(y + 2) % 5]
                & (state[x][(y + 4) % 5] ^ MASK64)
            )
            for y in range(5)
        )
        for x in range(5)
    )


def round_function(state: State, round_index: int) -> State:
    return psi(pi(theta(rho(iota(state, round_index)))))


def thunder_p(state: State, rounds: int = 12) -> State:
    for round_index in range(rounds):
        state = round_function(state, round_index)
    return state


def state_from_lanes(lanes: Iterable[int]) -> State:
    flat = tuple(lanes)
    if len(flat) != 25:
        raise ValueError("exactly 25 lanes are required")
    return tuple(tuple(flat[5 * y + x] & MASK64 for y in range(5)) for x in range(5))


def state_to_lanes(state: State) -> tuple[int, ...]:
    return tuple(state[x][y] for y in range(5) for x in range(5))


def lanes_to_state_int(state: State) -> int:
    lanes = state_to_lanes(state)
    return sum((lanes[i] & MASK64) << (64 * i) for i in range(25))


def state_int_to_lanes(value: int) -> State:
    return state_from_lanes((value >> (64 * i)) & MASK64 for i in range(25))


def _rate_words(block: bytes, nr: int) -> tuple[int, ...]:
    if len(block) != 8 * nr:
        raise ValueError(f"block length must be {8 * nr} bytes")
    # M_{nr-1}...M_0 is the block as an integer; each M_i is parsed big-endian.
    return tuple(int.from_bytes(block[(nr - 1 - i) * 8 : (nr - i) * 8], "big") for i in range(nr))


@dataclass(frozen=True)
class Instance:
    name: str
    h: int
    c: int
    r: int
    nc: int
    nr: int
    iv: tuple[int, ...]

    @classmethod
    def get(cls, name: str) -> "Instance":
        p = FIXED_OUTPUT_PARAMS[name]
        return cls(name=name, **p)

    def initial_state(self) -> State:
        lanes = list(self.iv) + [0] * self.nr
        return state_from_lanes(lanes)

    def load_rate(self, state: State, block: bytes) -> State:
        lanes = list(state_to_lanes(state))
        for i, word in enumerate(_rate_words(block, self.nr)):
            lanes[25 - self.nr + i] ^= word
        return state_from_lanes(lanes)

    def forward_step(self, state: State, rounds: int = 12) -> State:
        # S is sampled after injection and before P, then only the capacity is
        # overwritten by the feed-forward.
        old_capacity = state_to_lanes(state)[: self.nc]
        permuted = thunder_p(state, rounds)
        lanes = list(state_to_lanes(permuted))
        for i in range(self.nc):
            lanes[i] ^= old_capacity[i]
        return state_from_lanes(lanes)

    def absorb(self, message: bytes, rounds: int = 12) -> State:
        if len(message) * 8 >= 1 << 64:
            raise ValueError("the specification only claims messages below 2^64 bits")
        rate_bytes = self.r // 8
        complete, remainder_bytes = divmod(len(message), rate_bytes)
        state = self.initial_state()
        for i in range(complete):
            state = self.load_rate(state, message[i * rate_bytes : (i + 1) * rate_bytes])
            state = self.forward_step(state, rounds)

        suffix = message[complete * rate_bytes :]
        # For byte messages, only lengths congruent to rate_bytes-1 need an
        # implicit all-zero final block.
        padded_blocks = []
        if len(suffix) == rate_bytes - 1:
            padded_blocks.append(suffix + b"\x80")
            padded_blocks.append(b"\x00" * rate_bytes)
        else:
            padded_blocks.append(suffix + b"\x80" + b"\x00" * (rate_bytes - len(suffix) - 1))

        for index, block in enumerate(padded_blocks):
            state = self.load_rate(state, block)
            if index == len(padded_blocks) - 1:
                lanes = list(state_to_lanes(state))
                lanes[0] ^= 1  # C = 0^(c-1)||1
                state = state_from_lanes(lanes)
            state = self.forward_step(state, rounds)
        return state

    def digest(self, message: bytes, rounds: int = 12) -> bytes:
        state = self.absorb(message, rounds)
        nd = self.h // 64
        lanes = state_to_lanes(state)[:nd]
        return b"".join(lanes[i].to_bytes(8, "big") for i in range(nd - 1, -1, -1))


def bits_from_mask(mask: int) -> tuple[tuple[int, int, int], ...]:
    return tuple((bit // 64 % 5, bit // 64 // 5, bit % 64) for bit in range(1600) if (mask >> bit) & 1)


def lane_mask(positions: Iterable[tuple[int, int]]) -> int:
    mask = 0
    for x, y in positions:
        mask |= 1 << (64 * (5 * y + x))
    return mask


def print_truth_table() -> None:
    print("input(a0a1a2a3a4) output(b0b1b2b3b4) weight")
    for value in range(32):
        inp = tuple((value >> i) & 1 for i in range(5))
        out = _psi_word(inp)
        print(f"{''.join(map(str, inp))} {''.join(map(str, out))} {sum(out)}")


if __name__ == "__main__":
    print_truth_table()
