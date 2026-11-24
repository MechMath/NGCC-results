#!/usr/bin/env python3
"""Scratch probe of the archived ZC round and DMc feed-forward.

This is native exploratory code, not crypto_run evidence.  It implements both
specified geometries directly from the archived specification.
"""

import argparse
import hashlib
import json
import random

MASK = (1 << 64) - 1
CONSTANTS = [
    0x58, 0x38, 0x3C0, 0xD0, 0x60, 0x120,
    0x14, 0x2C, 0xF0, 0x1A0, 0x380, 0x12,
]


class ZC:
    def __init__(self, width):
        self.width = width
        if width == 1280:
            self.planes = 5
            self.xs = 4
            self.rho_offsets = [(0, 0), (1, 5), (3, 24), (0, 1), (2, 3)]
            self.theta_offsets = [5, 14]
        elif width == 1536:
            self.planes = 3
            self.xs = 8
            self.rho_offsets = [(0, 0), (3, 3), (5, 0)]
            self.theta_offsets = [20, 56]
        else:
            raise ValueError("width must be 1280 or 1536")

    def zero(self):
        return [[0] * self.xs for _ in range(self.planes)]

    def from_int(self, value):
        assert 0 <= value < (1 << self.width)
        out = self.zero()
        # The coordinate order is immaterial to the PDF properties tested here.
        for y in range(self.planes):
            for x in range(self.xs):
                out[y][x] = value & MASK
                value >>= 64
        return out

    def to_int(self, a):
        value = 0
        shift = 0
        for y in range(self.planes):
            for x in range(self.xs):
                value |= a[y][x] << shift
                shift += 64
        return value

    def rho(self, a):
        out = [row[:] for row in a]
        for y, (dx, dz) in enumerate(self.rho_offsets):
            for x in range(self.xs):
                lane = a[y][x]
                out[y][(x + dx) % self.xs] = (
                    ((lane << dz) | (lane >> (64 - dz))) & MASK
                    if dz else lane
                )
        return out

    def round(self, a, rc):
        a = [row[:] for row in a]
        a[0][0] ^= rc
        # Columnwise chi.
        old = [row[:] for row in a]
        for y in range(self.planes):
            y1 = (y + 1) % self.planes
            y2 = (y + 2) % self.planes
            a[y] = [old[y][x] ^ ((~old[y1][x]) & old[y2][x] & MASK)
                    for x in range(self.xs)]
        a = self.rho(a)
        parity = [0] * self.xs
        for y in range(self.planes):
            for x in range(self.xs):
                parity[x] ^= a[y][x]
        effect = [0] * self.xs
        for x in range(self.xs):
            for dz in self.theta_offsets:
                p = parity[(x - 1) % self.xs]
                effect[x] ^= ((p << dz) | (p >> (64 - dz))) & MASK
        for y in range(self.planes):
            for x in range(self.xs):
                a[y][x] ^= effect[x]
        return self.rho(a)

    def permute(self, value):
        a = self.from_int(value)
        for rc in CONSTANTS:
            a = self.round(a, rc)
        return self.to_int(a)

    def f(self, value):
        capacity_mask = (1 << (self.width - (self.width - self.capacity))) - 1
        return self.permute(value) ^ (value & capacity_mask)


def xor_all(values):
    out = 0
    for value in values:
        out ^= value
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--width", type=int, choices=(1280, 1536), default=1280)
    parser.add_argument("--capacity", type=int, default=None)
    parser.add_argument("--samples", type=int, default=1000)
    args = parser.parse_args()

    zc = ZC(args.width)
    zc.capacity = args.capacity or (512 + 64)
    rng = random.Random(115)
    records = {
        "width": args.width,
        "capacity": zc.capacity,
        "P0": zc.permute(0),
        "F0": zc.f(0),
        "P0_is_zero": zc.permute(0) == 0,
        "F0_is_zero": zc.f(0) == 0,
        "round_constants": CONSTANTS,
    }

    # Basic involution check for a possible tiny cycle at the zero state.
    zero_image = zc.f(0)
    records["F2_zero"] = zc.f(zero_image)
    records["zero_2cycle"] = zero_image != 0 and zc.f(zero_image) == 0
    records["zero_fixed"] = zero_image == 0

    # Random compression-collision birthday probe.  Its negative outcome says
    # nothing beyond the sampled size.
    seen = {}
    first_collision = None
    for i in range(args.samples):
        x = rng.getrandbits(args.width)
        y = zc.f(x)
        if y in seen and seen[y] != x:
            first_collision = {"x": seen[y], "x_prime": x, "F": y}
            break
        seen[y] = x
    records["compression_samples"] = args.samples
    records["compression_collision"] = first_collision

    # Test whether F preserves constant XOR differences on random pairs.
    delta = 1
    preserved = 0
    trials = 100
    for _ in range(trials):
        x = rng.getrandbits(args.width)
        if zc.f(x) ^ zc.f(x ^ delta) == delta:
            preserved += 1
    records["delta_one_preserved"] = preserved
    records["delta_one_trials"] = trials

    print(json.dumps(records, indent=2))


if __name__ == "__main__":
    main()
