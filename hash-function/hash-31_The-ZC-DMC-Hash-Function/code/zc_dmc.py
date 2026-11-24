#!/usr/bin/env python3
"""Reference model for the ZC-1280, ZC-1536, and ZC-DMC specifications.

State convention:
  state[y][x] is a 64-bit lane, y is the plane (0 is bottom), x is the
  horizontal lane index, and bit z of a lane is its bit of weight 2**z.
  Thus z=0 is the least-significant bit, as stated in Table 1.1.

The specification does not define a canonical serialization of the three-
dimensional state. This model uses plane-major, then x, then z, with z
increasing. Round equations and inversion tests do not depend on that choice;
the hash-level helper does.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable, Sequence

MASK64 = (1 << 64) - 1

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


@dataclass(frozen=True)
class Variant:
    name: str
    planes: int
    lanes: int
    rho: tuple[tuple[int, int], ...]
    theta: tuple[int, int]


ZC1280 = Variant(
    name="ZC-1280",
    planes=5,
    lanes=4,
    rho=((0, 0), (1, 5), (3, 24), (0, 1), (2, 3)),
    theta=(5, 14),
)
ZC1536 = Variant(
    name="ZC-1536",
    planes=3,
    lanes=8,
    rho=((0, 0), (3, 3), (5, 0)),
    theta=(20, 56),
)

State = tuple[tuple[int, ...], ...]


def rol64(value: int, amount: int) -> int:
    amount %= 64
    value &= MASK64
    if amount == 0:
        return value
    return ((value << amount) | (value >> (64 - amount))) & MASK64


def ror64(value: int, amount: int) -> int:
    return rol64(value, -amount)


def chi_column(x: int, width: int) -> int:
    """Apply y[i] = x[i] xor ((not x[i+1]) and x[i+2])."""
    y = 0
    for i in range(width):
        bit = ((x >> i) & 1) ^ ((((x >> ((i + 1) % width)) & 1) ^ 1)
                                  & ((x >> ((i + 2) % width)) & 1))
        y |= bit << i
    return y


@lru_cache(maxsize=None)
def _inverse_chi_table(width: int) -> tuple[int, ...]:
    # The familiar Keccak inverse formula is valid for the 3-bit chi used
    # here, but is not its inverse for the 5-bit variant. A table is exact,
    # compact, and avoids silently applying an invalid general formula.
    table = [-1] * (1 << width)
    for x in range(1 << width):
        table[chi_column(x, width)] = x
    if any(x < 0 for x in table):
        raise AssertionError(f"chi is not bijective for width {width}")
    return tuple(table)


def inverse_chi_column(y: int, width: int) -> int:
    return _inverse_chi_table(width)[y]


def zero_state(variant: Variant) -> State:
    return tuple((0,) * variant.lanes for _ in range(variant.planes))


def iota(state: State, round_index: int) -> State:
    planes = [list(p) for p in state]
    planes[0][0] ^= ROUND_CONSTANTS[round_index]
    return tuple(tuple(p) for p in planes)


def chi(state: State, variant: Variant) -> State:
    width = variant.planes
    out = [[0] * variant.lanes for _ in range(width)]
    for x in range(variant.lanes):
        for z in range(64):
            column = sum(((state[y][x] >> z) & 1) << y for y in range(width))
            transformed = chi_column(column, width)
            for y in range(width):
                out[y][x] |= ((transformed >> y) & 1) << z
    return tuple(tuple(p) for p in out)


def inverse_chi(state: State, variant: Variant) -> State:
    width = variant.planes
    out = [[0] * variant.lanes for _ in range(width)]
    for x in range(variant.lanes):
        for z in range(64):
            column = sum(((state[y][x] >> z) & 1) << y for y in range(width))
            restored = inverse_chi_column(column, width)
            for y in range(width):
                out[y][x] |= ((restored >> y) & 1) << z
    return tuple(tuple(p) for p in out)


def rho(state: State, variant: Variant) -> State:
    # S'[x] = rol(S[x-a], b), exactly as in the coordinate-wise formulas.
    return tuple(
        tuple(rol64(state[y][(x - a) % variant.lanes], b)
              for x in range(variant.lanes))
        for y, (a, b) in enumerate(variant.rho)
    )


def inverse_rho(state: State, variant: Variant) -> State:
    return tuple(
        tuple(ror64(state[y][(x + a) % variant.lanes], b)
              for x in range(variant.lanes))
        for y, (a, b) in enumerate(variant.rho)
    )


def theta_effect(parity: Sequence[int], variant: Variant) -> tuple[int, ...]:
    b0, b1 = variant.theta
    return tuple(
        rol64(parity[(x - 1) % variant.lanes], b0)
        ^ rol64(parity[(x - 1) % variant.lanes], b1)
        for x in range(variant.lanes)
    )


def theta(state: State, variant: Variant) -> State:
    parity = tuple(
        state[0][x] ^ state[1][x] ^ state[2][x]
        ^ (state[3][x] if variant.planes == 5 else 0)
        ^ (state[4][x] if variant.planes == 5 else 0)
        for x in range(variant.lanes)
    )
    effect = theta_effect(parity, variant)
    return tuple(
        tuple(state[y][x] ^ effect[x] for x in range(variant.lanes))
        for y in range(variant.planes)
    )


def inverse_theta(state: State, variant: Variant) -> State:
    # Let R(P)[x] = rol(P[x-1],b0) xor rol(P[x-1],b1), and P' = P xor R(P).
    # In the polynomial ring over F2, R is nilpotent: its z polynomial has
    # the factor (z+1), and its x shift wraps after at most 8 applications.
    # Thus (I+R)^-1 = product (I+R^(2^i)); 64*8 applications is a safe bound.
    parity_out = tuple(
        state[0][x] ^ state[1][x] ^ state[2][x]
        ^ (state[3][x] if variant.planes == 5 else 0)
        ^ (state[4][x] if variant.planes == 5 else 0)
        for x in range(variant.lanes)
    )
    parity = parity_out
    power = parity_out
    for _ in range(64):
        power = theta_effect(power, variant)
        parity = tuple(parity[x] ^ power[x] for x in range(variant.lanes))
    effect = theta_effect(parity, variant)
    return tuple(
        tuple(state[y][x] ^ effect[x] for x in range(variant.lanes))
        for y in range(variant.planes)
    )


def round_forward(state: State, variant: Variant, round_index: int) -> State:
    state = iota(state, round_index)
    state = chi(state, variant)
    state = rho(state, variant)
    state = theta(state, variant)
    return rho(state, variant)


def round_inverse(state: State, variant: Variant, round_index: int) -> State:
    state = inverse_rho(state, variant)
    state = inverse_theta(state, variant)
    state = inverse_rho(state, variant)
    state = inverse_chi(state, variant)
    return iota(state, round_index)


def permutation(state: State, variant: Variant, rounds: int = 12) -> State:
    for round_index in range(1 - rounds, 1):
        state = round_forward(state, variant, round_index)
    return state


def inverse_permutation(state: State, variant: Variant, rounds: int = 12) -> State:
    for round_index in range(0, -rounds, -1):
        state = round_inverse(state, variant, round_index)
    return state


def state_to_bits(state: State, variant: Variant) -> list[int]:
    """Model serialization: plane-major, x, then z; 0 is the first bit."""
    return [
        (state[y][x] >> z) & 1
        for y in range(variant.planes)
        for x in range(variant.lanes)
        for z in range(64)
    ]


def bits_to_state(bits: Sequence[int], variant: Variant) -> State:
    need = variant.planes * variant.lanes * 64
    if len(bits) != need:
        raise ValueError(f"need {need} bits, got {len(bits)}")
    planes = [[0] * variant.lanes for _ in range(variant.planes)]
    p = 0
    for y in range(variant.planes):
        for x in range(variant.lanes):
            for z in range(64):
                planes[y][x] |= int(bits[p]) << z
                p += 1
    return tuple(tuple(plane) for plane in planes)


def feed_forward(state: State, variant: Variant, rate: int) -> State:
    original = state_to_bits(state, variant)
    # ZC(state) xor (0^r || X_c)
    perm_state = permutation(state, variant)
    return bits_to_state(
        _xor_bits_partial(state_to_bits(perm_state, variant), original, rate),
        variant,
    )


def _xor_bits_partial(a: Sequence[int], b: Sequence[int], start: int) -> list[int]:
    return list(a[:start]) + [a[i] ^ b[i] for i in range(start, len(a))]


def intended_padding(message_bits: Sequence[int], rate: int) -> list[int]:
    """Text/Table 1.2 interpretation: M || 01 || 1 || 0^j || 1."""
    out = list(message_bits) + [0, 1]
    j = (-(len(out) + 2)) % rate
    out.extend([1] + [0] * j + [1])
    assert len(out) % rate == 0
    return out


def algorithm3_padding(message_bits: Sequence[int], rate: int) -> list[int]:
    """Literal Algorithm 3 model, retaining its stated j criterion."""
    out = list(message_bits) + [0, 1]
    # Algorithm 3's |M| is the current length after appending 01. Its test
    # |M|+2+j therefore equals L+4+j, exactly balancing the final 1||0^j||1.
    j = (-(len(out) + 2)) % rate
    out.extend([1] + [0] * j + [1])
    return out


def zc_dmc_hash(message_bits: Sequence[int], variant: Variant, c: int, n: int,
                squeeze_rate: int, *, literal_padding: bool = False) -> list[int]:
    m = variant.planes * variant.lanes * 64
    rate = m - c
    if not (0 < rate < m and 0 < c < m and 0 < squeeze_rate):
        raise ValueError("invalid rate/capacity/squeeze-rate parameters")
    padded = (algorithm3_padding if literal_padding else intended_padding)(
        message_bits, rate
    )
    if len(padded) % rate:
        raise ValueError("literal Algorithm 3 did not produce rate-aligned blocks")
    blocks = [padded[i:i + rate] for i in range(0, len(padded), rate)]
    state = bits_to_state(blocks[0] + [0] * c, variant)
    for block in blocks[1:]:
        state = feed_forward(state, variant, rate)
        injected = state_to_bits(state, variant)
        injected[:rate] = [a ^ b for a, b in zip(injected[:rate], block)]
        state = bits_to_state(injected, variant)
    state = feed_forward(state, variant, rate)
    output = state_to_bits(state, variant)[:squeeze_rate]
    while len(output) < n:
        state = permutation(state, variant)
        output.extend(state_to_bits(state, variant)[:squeeze_rate])
    return output[:n]
