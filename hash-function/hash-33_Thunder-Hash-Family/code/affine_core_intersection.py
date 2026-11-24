#!/usr/bin/env python3
"""Check whether Thunder's audited one-round affine core composes.

This is a reproducible scratch check for the affine core in proof node
822f21fc18e70d46.  It compares the affine image of the round with each
pre-psi affine core.  The specification order is iota,rho,theta,pi,psi, so
there is no trailing round-constant XOR.  This is not crypto_run evidence.
"""

from __future__ import annotations


TAU = [
    [45, 33, 13, 1, 27],
    [40, 52, 19, 47, 9],
    [34, 5, 0, 2, 37],
    [48, 30, 61, 8, 38],
    [6, 18, 49, 17, 43],
]
TY = [41, 50, 6, 10, 27]
ROUND_CONSTANTS = [
    0x1,
    0x3,
    0xA,
    0x88,
    0x8081,
    0x8002,
    0x9,
    0x83,
    0x800A,
    0x89,
    0x8083,
    0x800B,
]


def index(x: int, y: int, z: int) -> int:
    return 64 * (5 * y + x) + z % 64


# Each entry is the set of post-rho input bits XORed into one theta output bit.
THETA_MASKS: list[int] = []
for x in range(5):
    for y in range(5):
        for z in range(64):
            mask = 1 << index(x, y, z)
            e = (z + 26) % 64
            f = (z + 26 + TY[y]) % 64
            for yy in range(5):
                mask ^= 1 << index(x, yy, e)
                mask ^= 1 << index((x - 1) % 5, yy, (e + 1) % 64)
                mask ^= 1 << index((x + 1) % 5, yy, (f + TY[yy]) % 64)
                mask ^= 1 << index((x - 2) % 5, yy, (f + 36 + TY[yy]) % 64)
            THETA_MASKS.append(mask)


def linear_layer(value: int) -> int:
    """Apply L = pi o theta o rho to one packed GF(2) vector."""
    after_rho = 0
    for x in range(5):
        for y in range(5):
            for z in range(64):
                source = index(x, y, z + TAU[y][x])
                if value >> source & 1:
                    after_rho |= 1 << index(x, y, z)

    after_theta = 0
    for output, mask in enumerate(THETA_MASKS):
        if (after_rho & mask).bit_count() & 1:
            after_theta |= 1 << output

    after_pi = 0
    for x in range(5):
        for y in range(5):
            destination_x = y
            destination_y = (2 * x + 3 * y + 2) % 5
            for z in range(64):
                if after_theta >> index(x, y, z) & 1:
                    after_pi |= 1 << index(destination_x, destination_y, z)
    return after_pi


def build_bases() -> tuple[list[int], list[int]]:
    # A_pre has (a0,a1,a2,a3,a4)=(u,v,0,1,0), so its directions are e0,e1.
    apre_directions: list[int] = []
    # psi(A_pre) has (1,1+u,u,u+v,0).  Its directions are
    # (0,1,1,1,0) for u and (0,0,0,1,0) for v.
    image_directions: list[int] = []
    for x in range(5):
        for z in range(64):
            apre_directions.extend(
                [1 << index(x, 0, z), 1 << index(x, 1, z)]
            )
            image_directions.extend(
                [
                    (1 << index(x, 1, z))
                    | (1 << index(x, 2, z))
                    | (1 << index(x, 3, z)),
                    1 << index(x, 3, z),
                ]
            )
    return apre_directions, image_directions


def rank(rows: list[int]) -> tuple[int, dict[int, int]]:
    basis: dict[int, int] = {}
    for row in rows:
        while row:
            pivot = row.bit_length() - 1
            if pivot in basis:
                row ^= basis[pivot]
            else:
                basis[pivot] = row
                break
    return len(basis), basis


def in_span(value: int, basis: dict[int, int]) -> bool:
    while value:
        pivot = value.bit_length() - 1
        if pivot not in basis:
            return False
        value ^= basis[pivot]
    return True


def main() -> None:
    apre_directions, image_directions = build_bases()
    assert len(apre_directions) == len(image_directions) == 640

    image_after_l = [linear_layer(v) for v in image_directions]
    image_offset = linear_layer(
        sum(
            1 << index(x, y, z)
            for x in range(5)
            for y in (0, 1)
            for z in range(64)
        )
    )
    apre_offset = sum(
        1 << index(x, 3, z) for x in range(5) for z in range(64)
    )
    union_rank, union_basis = rank(image_after_l + apre_directions)
    print(f"direction dimensions: 640 + 640, union rank = {union_rank}")

    rc_vectors = [
        sum(((rc >> z) & 1) << index(0, 0, z) for z in range(64))
        for rc in ROUND_CONSTANTS
    ]
    for i, rc_vector in enumerate(rc_vectors):
        # The rho/theta/pi output is L(R) and the core condition is
        # L(R) xor L(RC_i) in direction(A_pre) + A_pre_offset.
        boundary_offset = (
            image_offset ^ apre_offset ^ linear_layer(rc_vector)
        )
        disjoint = not in_span(boundary_offset, union_basis)
        print(f"next-core {i}: disjoint={disjoint}")
        assert disjoint


if __name__ == "__main__":
    main()
