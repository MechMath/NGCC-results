"""Check the three-query ZC zero-sum states at the two EDM interfaces.

This is a deterministic sanity check, not cryptographic run evidence.  It uses
the explicit state serialization bit t=64*(nx*x+y)+z for S[x][y][z] and reads
t=0,...,m-1 in increasing order.  The allowlisted specification does not itself
fix that API serialization, so the capacity results are conditional on it.
"""

from __future__ import annotations

import json


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


class ZC:
    def __init__(self, width: int) -> None:
        self.width = width
        self.nx = 4 if width == 5 else 8
        self.planes = width
        self.words = self.nx * 64
        self.shifts = (
            [(0, 0), (1, 5), (3, 24), (0, 1), (2, 3)]
            if width == 5
            else [(0, 0), (3, 3), (5, 0)]
        )
        self.theta_shifts = (
            ((1, 5), (1, 14)) if width == 5 else ((1, 20), (1, 56))
        )
        self.chi = []
        self.chi_inverse = [0] * (1 << width)
        for value in range(1 << width):
            result = 0
            for bit in range(width):
                x0 = (value >> bit) & 1
                x1 = (value >> ((bit + 1) % width)) & 1
                x2 = (value >> ((bit + 2) % width)) & 1
                result |= (x0 ^ ((1 ^ x1) & x2)) << bit
            self.chi.append(result)
        for source, target in enumerate(self.chi):
            self.chi_inverse[target] = source

        # The inverse of I+T on the column-parity plane.  T is the theta
        # effect-plane map; Gaussian elimination is done once per instance.
        self.inverse_basis: dict[int, tuple[int, int]] = {}
        for bit in range(self.words):
            vector = (1 << bit) ^ self.theta(1 << bit)
            rhs = 1 << bit
            while vector:
                pivot = vector.bit_length() - 1
                if pivot in self.inverse_basis:
                    basis_vector, basis_rhs = self.inverse_basis[pivot]
                    vector ^= basis_vector
                    rhs ^= basis_rhs
                else:
                    self.inverse_basis[pivot] = (vector, rhs)
                    break
            if not vector:
                raise ValueError("theta inverse matrix is singular")

    def shift(self, value: int, dx: int, dz: int) -> int:
        result = 0
        for x in range(self.nx):
            source_x = (x - dx) % self.nx
            for z in range(64):
                bit = (value >> (source_x * 64 + (z - dz) % 64)) & 1
                result |= bit << (x * 64 + z)
        return result

    def theta(self, value: int) -> int:
        first, second = self.theta_shifts
        return self.shift(value, *first) ^ self.shift(value, *second)

    def apply_chi(self, state: list[int], table: list[int]) -> list[int]:
        result = [0] * self.planes
        for x in range(self.nx):
            for z in range(64):
                column = sum(
                    ((state[y] >> (x * 64 + z)) & 1) << y
                    for y in range(self.planes)
                )
                image = table[column]
                for y in range(self.planes):
                    result[y] |= ((image >> y) & 1) << (x * 64 + z)
        return result

    def apply_theta(self, state: list[int]) -> list[int]:
        parity = 0
        for plane in state:
            parity ^= plane
        effect = self.theta(parity)
        return [plane ^ effect for plane in state]

    def apply_theta_inverse(self, state: list[int]) -> list[int]:
        output_parity = 0
        for plane in state:
            output_parity ^= plane
        vector = output_parity
        parity = 0
        while vector:
            pivot = vector.bit_length() - 1
            basis_vector, basis_rhs = self.inverse_basis[pivot]
            vector ^= basis_vector
            parity ^= basis_rhs
        effect = parity ^ output_parity
        return [plane ^ effect for plane in state]

    def apply_rho(self, state: list[int]) -> list[int]:
        return [
            self.shift(plane, *self.shifts[y]) for y, plane in enumerate(state)
        ]

    def apply_rho_inverse(self, state: list[int]) -> list[int]:
        return [
            self.shift(plane, -self.shifts[y][0], -self.shifts[y][1])
            for y, plane in enumerate(state)
        ]

    def round(self, state: list[int], constant: int) -> list[int]:
        state = list(state)
        state[0] ^= constant
        state = self.apply_chi(state, self.chi)
        state = self.apply_rho(state)
        state = self.apply_theta(state)
        return self.apply_rho(state)

    def inverse_round(self, state: list[int], constant: int) -> list[int]:
        state = self.apply_rho_inverse(state)
        state = self.apply_theta_inverse(state)
        state = self.apply_rho_inverse(state)
        state = self.apply_chi(state, self.chi_inverse)
        state[0] ^= constant
        return state

    def apply_rounds(self, state: list[int], first: int, last: int) -> list[int]:
        state = list(state)
        for constant in ROUND_CONSTANTS[first : last + 1]:
            state = self.round(state, constant)
        return state

    def invert_rounds(self, state: list[int], first: int, last: int) -> list[int]:
        state = list(state)
        for constant in reversed(ROUND_CONSTANTS[first : last + 1]):
            state = self.inverse_round(state, constant)
        return state

    def serialize(self, state: list[int]) -> int:
        value = 0
        for y, plane in enumerate(state):
            for x in range(self.nx):
                for z in range(64):
                    bit = (plane >> (x * 64 + z)) & 1
                    value |= bit << (64 * (self.nx * x + y) + z)
        return value

    def deserialize(self, value: int) -> list[int]:
        state = [0] * self.planes
        for y in range(self.planes):
            for x in range(self.nx):
                for z in range(64):
                    bit = (value >> (64 * (self.nx * x + y) + z)) & 1
                    state[y] |= bit << (x * 64 + z)
        return state

    def xor_states(self, states: list[list[int]]) -> list[int]:
        result = [0] * self.planes
        for state in states:
            for y in range(self.planes):
                result[y] ^= state[y]
        return result

    def capacity(self, value: int, c: int) -> int:
        return value >> (64 * self.planes * self.nx - c)

    def edm(self, state: list[int], c: int, use_g: bool) -> list[int]:
        value = self.serialize(state)
        capacity = value >> (64 * self.planes * self.nx - c)
        if use_g:
            inner = self.apply_rounds(state, 0, 5)
        else:
            inner = self.apply_rounds(state, 6, 11)
        feed_forward = self.deserialize(
            capacity << (64 * self.planes * self.nx - c)
        )
        inner = [plane ^ mask for plane, mask in zip(inner, feed_forward)]
        return self.apply_rounds(inner, 6, 11)


def main() -> None:
    answer = {}
    for width in (5, 3):
        zc = ZC(width)
        m = 64 * width * zc.nx
        d = [
            [0] * width,
            [0] * (width - 1) + [0],
            [0] * (width - 1) + [0],
        ]
        d[1][0] = 1 << 4
        d[2][0] = 1 << 1
        a = [zc.invert_rounds(state, 0, 10) for state in d]
        p = [zc.apply_rounds(state, 0, 11) for state in a]
        expected_zero = zc.xor_states(p)

        for c in (576, 832, 1088):
            g_images = [zc.edm(state, c, True) for state in a]
            h_images = [zc.edm(state, c, False) for state in a]
            g_xor = zc.xor_states(g_images)
            h_xor = zc.xor_states(h_images)
            answer[f"ZC-{m}-c{c}"] = {
                "full_zero_sum": zc.serialize(expected_zero) == 0,
                "input_capacities_distinct": len(
                    {zc.capacity(zc.serialize(state), c) for state in a}
                )
                == 3,
                "input_capacities_all_zero": all(
                    zc.capacity(zc.serialize(state), c) == 0 for state in a
                ),
                "F_g_images_distinct": len(
                    {zc.serialize(state) for state in g_images}
                )
                == 3,
                "F_g_output_capacity_xor_zero": zc.capacity(
                    zc.serialize(g_xor), c
                )
                == 0,
                "F_h_images_distinct": len(
                    {zc.serialize(state) for state in h_images}
                )
                == 3,
                "F_h_output_capacity_xor_zero": zc.capacity(
                    zc.serialize(h_xor), c
                )
                == 0,
            }
    print(json.dumps(answer, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
