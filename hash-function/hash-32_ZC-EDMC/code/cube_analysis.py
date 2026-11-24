#!/usr/bin/env python3
"""Checks for ZC final-round zero-sum sets and the EDMc one-block interface."""

from __future__ import annotations

import argparse
import json

MASK64 = (1 << 64) - 1

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


class Perm:
    def __init__(self, planes: int, lanes_x: int, rate_shift: tuple[int, int]):
        self.planes = planes
        self.xdim = lanes_x
        self.rate_shift = rate_shift
        self.rho = [(0, 0), (1, 5), (3, 24), (0, 1), (2, 3)]
        if planes == 3:
            self.rho = [(0, 0), (3, 3), (5, 0)]
        self._theta_parity_inverse = None

    def bit(self, state: list[list[int]], x: int, y: int, z: int) -> int:
        return (state[y][x] >> z) & 1

    def setbit(self, state: list[list[int]], x: int, y: int, z: int, v: int) -> None:
        x %= self.xdim
        z %= 64
        if v:
            state[y][x] |= 1 << z
        else:
            state[y][x] &= MASK64 ^ (1 << z)

    @staticmethod
    def rot(lane: int, dx: int, dz: int, xdim: int) -> int:
        ## x rotation on lane words is performed explicitly for the small xdim here.
        raise NotImplementedError

    def xor_state(self, a: list[list[int]], b: list[list[int]]) -> list[list[int]]:
        return [[a[y][x] ^ b[y][x] for x in range(self.xdim)] for y in range(self.planes)]

    def rho_forward(self, state: list[list[int]]) -> list[list[int]]:
        out = [[0] * self.xdim for _ in range(self.planes)]
        for y in range(self.planes):
            dx, dz = self.rho[y]
            for x in range(self.xdim):
                src_x = (x - dx) % self.xdim
                w = state[y][src_x]
                out[y][x] = ((w >> dz) | ((w << (64 - dz)) & MASK64)) & MASK64 if dz else w
        return out

    def rho_inverse(self, state: list[list[int]]) -> list[list[int]]:
        out = [[0] * self.xdim for _ in range(self.planes)]
        for y in range(self.planes):
            dx, dz = self.rho[y]
            for x in range(self.xdim):
                src_x = (x + dx) % self.xdim
                w = state[y][src_x]
                out[y][x] = ((w << dz) | (w >> (64 - dz))) & MASK64 if dz else w
        return out

    def chi3_forward(self, state: list[list[int]]) -> list[list[int]]:
        out = [[0] * self.xdim for _ in range(self.planes)]
        for x in range(self.xdim):
            for z in range(64):
                a = [self.bit(state, x, y, z) for y in range(3)]
                b = [a[i] ^ ((1 ^ a[(i + 1) % 3]) & a[(i + 2) % 3]) for i in range(3)]
                for y in range(3):
                    if b[y]:
                        out[y][x] |= 1 << z
        return out

    def chi5_forward(self, state: list[list[int]]) -> list[list[int]]:
        out = [[0] * self.xdim for _ in range(self.planes)]
        for x in range(self.xdim):
            for z in range(64):
                a = [self.bit(state, x, y, z) for y in range(5)]
                b = [a[i] ^ ((1 ^ a[(i + 1) % 5]) & a[(i + 2) % 5]) for i in range(5)]
                for y in range(5):
                    if b[y]:
                        out[y][x] |= 1 << z
        return out

    def chi_inverse(self, state: list[list[int]]) -> list[list[int]]:
        k = self.planes
        def sbox(a: int) -> int:
            bits = [(a >> i) & 1 for i in range(k)]
            out = [
                bits[i] ^ ((1 ^ bits[(i + 1) % k]) & bits[(i + 2) % k])
                for i in range(k)
            ]
            return sum(v << i for i, v in enumerate(out))

        inverse = [0] * (1 << k)
        for a in range(1 << k):
            inverse[sbox(a)] = a
        out = [[0] * self.xdim for _ in range(self.planes)]
        for x in range(self.xdim):
            for z in range(64):
                a = sum(self.bit(state, x, y, z) << y for y in range(k))
                b = inverse[a]
                for y in range(k):
                    if (b >> y) & 1:
                        out[y][x] |= 1 << z
        return out

    def theta_forward(self, state: list[list[int]]) -> list[list[int]]:
        parity = [0] * self.xdim
        for y in range(self.planes):
            for x in range(self.xdim):
                parity[x] ^= state[y][x]
        dx, dz1 = self.rate_shift
        _, dz2 = (1, 14) if self.planes == 5 else (1, 56)
        effect = [0] * self.xdim
        for x in range(self.xdim):
            p0 = parity[(x - dx) % self.xdim]
            p1 = p0
            r0 = ((p0 >> dz1) | ((p0 << (64 - dz1)) & MASK64)) & MASK64 if dz1 else p0
            r1 = ((p1 >> dz2) | ((p1 << (64 - dz2)) & MASK64)) & MASK64 if dz2 else p1
            effect[x] = r0 ^ r1
        return [[state[y][x] ^ effect[x] for x in range(self.xdim)] for y in range(self.planes)]

    def theta_inverse(self, state: list[list[int]]) -> list[list[int]]:
        out_parity = [0] * self.xdim
        for y in range(self.planes):
            for x in range(self.xdim):
                out_parity[x] ^= state[y][x]
        if self._theta_parity_inverse is None:
            self._theta_parity_inverse = self._build_theta_parity_inverse()
        bits = 0
        for x in range(self.xdim):
            bits |= out_parity[x] << (64 * x)
        recovered = self._apply_inverse_sparse(bits, self._theta_parity_inverse)
        effect_bits = self._parity_effect_bits(recovered) ^ recovered
        effect = [(effect_bits >> (64 * x)) & MASK64 for x in range(self.xdim)]
        return [[state[y][x] ^ effect[x] for x in range(self.xdim)] for y in range(self.planes)]

    def _parity_effect_bits(self, bits: int) -> int:
        dx, dz1 = self.rate_shift
        _, dz2 = (1, 14) if self.planes == 5 else (1, 56)
        parity = [(bits >> (64 * x)) & MASK64 for x in range(self.xdim)]
        effect = [0] * self.xdim
        for x in range(self.xdim):
            p0 = parity[(x - dx) % self.xdim]
            r0 = ((p0 >> dz1) | ((p0 << (64 - dz1)) & MASK64)) & MASK64 if dz1 else p0
            r1 = ((p0 >> dz2) | ((p0 << (64 - dz2)) & MASK64)) & MASK64 if dz2 else p0
            effect[x] = r0 ^ r1
        out = bits
        for x in range(self.xdim):
            out ^= effect[x] << (64 * x)
        return out

    def _build_theta_parity_inverse(self) -> list[tuple[int, int]]:
        n = 64 * self.xdim
        basis: dict[int, tuple[int, int]] = {}
        for j in range(n):
            vec = self._parity_effect_bits(1 << j)
            combo = 1 << j
            while vec:
                pivot = vec.bit_length() - 1
                if pivot not in basis:
                    basis[pivot] = (vec, combo)
                    break
                bvec, bcombo = basis[pivot]
                vec ^= bvec
                combo ^= bcombo
        inverse = []
        for i in range(n):
            vec = 1 << i
            combo = 0
            while vec:
                pivot = vec.bit_length() - 1
                bvec, bcombo = basis[pivot]
                vec ^= bvec
                combo ^= bcombo
            inverse.append((1 << i, combo))
        return inverse

    @staticmethod
    def _apply_inverse_sparse(bits: int, inverse: list[tuple[int, int]]) -> int:
        out = 0
        while bits:
            i = (bits & -bits).bit_length() - 1
            out ^= inverse[i][1]
            bits &= bits - 1
        return out

    def round_forward(self, state: list[list[int]], constant: int) -> list[list[int]]:
        state = [row[:] for row in state]
        state[0][0] ^= constant
        state = self.chi3_forward(state) if self.planes == 3 else self.chi5_forward(state)
        state = self.rho_forward(state)
        state = self.theta_forward(state)
        return self.rho_forward(state)

    def round_inverse(self, state: list[list[int]], constant: int) -> list[list[int]]:
        state = self.rho_inverse(state)
        state = self.theta_inverse(state)
        state = self.rho_inverse(state)
        state = self.chi_inverse(state)
        state = [row[:] for row in state]
        state[0][0] ^= constant
        return state

    def forward(self, state: list[list[int]], start: int = 0, stop: int = 12) -> list[list[int]]:
        for i in range(start, stop):
            state = self.round_forward(state, ROUND_CONSTANTS[i])
        return state

    def inverse(self, state: list[list[int]], start: int = 12, stop: int = 0) -> list[list[int]]:
        for i in range(start - 1, stop - 1, -1):
            state = self.round_inverse(state, ROUND_CONSTANTS[i])
        return state

    def zero(self) -> list[list[int]]:
        return [[0] * self.xdim for _ in range(self.planes)]

    def known_d(self) -> list[list[int]]:
        d1, d2, d3 = self.zero(), self.zero(), self.zero()
        self.setbit(d2, 0, 0, 4, 1)
        self.setbit(d3, 0, 0, 1, 1)
        return [d1, d2, d3]


def check_profile(m: int) -> dict[str, object]:
    p = Perm(5, 4, (1, 5)) if m == 1280 else Perm(3, 8, (1, 20))
    ds = p.known_d()
    last_outputs = [p.round_forward(d, ROUND_CONSTANTS[-1]) for d in ds]
    last_xor = p.xor_state(p.xor_state(last_outputs[0], last_outputs[1]), last_outputs[2])
    assert all(word == 0 for row in last_xor for word in row)

    xs = [p.inverse(d, start=11, stop=0) for d in ds]
    assert all(p.forward(x, start=0, stop=11) == d for x, d in zip(xs, ds))
    return {
        "m": m,
        "last_round_xor_zero": True,
        "round_constants": ROUND_CONSTANTS,
        "one_block_page15_identity": "F_hg(M||0^c)=P(M||0^c)",
        "_xs": xs,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--m", type=int, choices=(1280, 1536), required=True)
    ap.add_argument("--c", type=int, required=True)
    args = ap.parse_args()
    result = check_profile(args.m)
    xs = result.pop("_xs")
    result["c"] = args.c
    ## Here xdim=4 or 8. Convert serialized bit index (x,y,z).
    xdim = 4 if args.m == 1280 else 8
    planes = 5 if args.m == 1280 else 3
    weights = []
    for state in xs:
        weight = 0
        for bit in range(args.m - args.c, args.m):
            z = bit % 64
            xy = bit // 64
            y = xy % planes
            x = xy // planes
            assert x < xdim
            weight += (state[y][x] >> z) & 1
        weights.append(weight)
    result["capacity_weights"] = weights

    one_block_inputs = []
    for state in xs:
        b = [row[:] for row in state]
        for bit in range(args.m - args.c, args.m):
            z = bit % 64
            xy = bit // 64
            y = xy % planes
            x = xy // planes
            p = Perm(planes, xdim, (1, 5) if planes == 5 else (1, 20))
            p.setbit(b, x, y, z, 0)
        one_block_inputs.append(b)
    one_block_outputs = [Perm(planes, xdim, (1, 5) if planes == 5 else (1, 20)).forward(b) for b in one_block_inputs]
    out_xor = one_block_outputs[0]
    for state in one_block_outputs[1:]:
        out_xor = Perm(planes, xdim, (1, 5) if planes == 5 else (1, 20)).xor_state(out_xor, state)
    result["zero_capacity_input_distinct"] = len({
        tuple(word for row in state for word in row) for state in one_block_inputs
    }) == 3
    result["one_block_output_xor_weight"] = sum(word.bit_count() for row in out_xor for word in row)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
