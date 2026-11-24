#!/usr/bin/env python3
"""Deterministic structured-difference searches for Thunder-512.

This is exploratory scratch evidence.  It is not a crypto_run execution and
therefore is not, by itself, verification-grade evidence for a security claim.
"""

from __future__ import annotations

import hashlib
import json
import random
from statistics import mean

import thunder as t


def deterministic_random(seed_text: str) -> random.Random:
    digest = hashlib.sha256(seed_text.encode("ascii")).digest()
    return random.Random(int.from_bytes(digest, "big"))


def bit(x: int, y: int, z: int) -> int:
    return 1 << (64 * (5 * y + x) + z)


def difference_families() -> dict[str, int]:
    families = {}
    for x in range(5):
        for y in range(5):
            families[f"bit_x{x}_y{y}_z0"] = bit(x, y, 0)
    families["all_bits_x0"] = sum(bit(0, y, z) for y in range(5) for z in range(64))
    families["all_bits_y0"] = sum(bit(x, 0, z) for x in range(5) for z in range(64))
    families["row_pattern_01010"] = sum(
        bit(x, y, z)
        for x in range(5)
        for y in (1, 3)
        for z in range(64)
    )
    families["column_pattern_every_other"] = sum(
        bit(x, y, z)
        for x in (1, 3)
        for y in range(5)
        for z in range(64)
    )
    return families


def apply_rounds(state: int, rounds: int) -> int:
    return t.lanes_to_state_int(t.thunder_p(t.state_int_to_lanes(state), rounds))


def main() -> None:
    profile = t.Instance.get("Thunder-512")
    rate_lane_offset = 25 - profile.nr
    rate_mask = sum(
        t.MASK64 << (64 * (rate_lane_offset + i)) for i in range(profile.nr)
    )
    digest_mask = (1 << profile.h) - 1
    train_rng = deterministic_random("thunder-structured-train-v1")
    holdout_rng = deterministic_random("thunder-structured-holdout-v1")

    def sample_bases(rng: random.Random, count: int) -> list[int]:
        bases = []
        for _ in range(count):
            # Train/test states are full uniform internal states, not messages.
            rate = rng.getrandbits(profile.r) << (64 * rate_lane_offset)
            cap = rng.getrandbits(profile.c)
            bases.append(rate | cap)
        return bases

    train = sample_bases(train_rng, 128)
    holdout = sample_bases(holdout_rng, 128)
    families = {
        name: difference & rate_mask
        for name, difference in difference_families().items()
        if difference & rate_mask
    }
    results = {}
    for name, difference in families.items():
        rounds = {}
        for count in (1, 2, 3, 4, 8, 12):
            train_weights = []
            train_digest_zeros = 0
            for base in train:
                out0 = apply_rounds(base, count)
                out1 = apply_rounds(base ^ difference, count)
                delta = out0 ^ out1
                train_weights.append(delta.bit_count())
                train_digest_zeros += (delta & digest_mask) == 0
            holdout_weights = []
            holdout_digest_zeros = 0
            for base in holdout:
                out0 = apply_rounds(base, count)
                out1 = apply_rounds(base ^ difference, count)
                delta = out0 ^ out1
                holdout_weights.append(delta.bit_count())
                holdout_digest_zeros += (delta & digest_mask) == 0
            rounds[str(count)] = {
                "train_mean_weight": mean(train_weights),
                "train_min_weight": min(train_weights),
                "train_max_weight": max(train_weights),
                "train_digest_zero_count": train_digest_zeros,
                "holdout_mean_weight": mean(holdout_weights),
                "holdout_min_weight": min(holdout_weights),
                "holdout_max_weight": max(holdout_weights),
                "holdout_digest_zero_count": holdout_digest_zeros,
            }
        results[name] = rounds

    # Exact rotation equivariance check at 12 rounds, using the same train frame.
    rotation_mismatches = 0
    for index, base in enumerate(train[:32]):
        other = train[(index + 1) % len(train)]
        for shift in (1, 7, 16, 31, 63):
            rotated_base = sum(
                t.rotl64((base >> (64 * i)) & t.MASK64, shift) << (64 * i)
                for i in range(25)
            )
            rotated_other = sum(
                t.rotl64((other >> (64 * i)) & t.MASK64, shift) << (64 * i)
                for i in range(25)
            )
            rotated_difference = sum(
                t.rotl64(
                    (
                        (apply_rounds(base, 12) >> (64 * i))
                        ^ (apply_rounds(other, 12) >> (64 * i))
                    )
                    & t.MASK64,
                    shift,
                )
                << (64 * i)
                for i in range(25)
            )
            if apply_rounds(rotated_base, 12) ^ apply_rounds(rotated_other, 12) != rotated_difference:
                rotation_mismatches += 1

    # Exact intersection of the 640-dimensional one-round affine core direction
    # with the direction needed for a second affine round.
    core_direction = []
    for x in range(5):
        for z in range(64):
            for y in (0, 1):
                core_direction.append(1 << (64 * (5 * y + x) + z))
    linear_core_images = [
        t.lanes_to_state_int(
            t.pi(t.theta(t.rho(t.state_int_to_lanes(value))))
        )
        for value in core_direction
    ]

    def gf2_rank(rows: list[int]) -> int:
        basis: dict[int, int] = {}
        for row in rows:
            while row:
                pivot = row.bit_length() - 1
                if pivot not in basis:
                    basis[pivot] = row
                    break
                row ^= basis[pivot]
        return len(basis)

    core_rank = gf2_rank(core_direction)
    image_rank = gf2_rank(linear_core_images)
    sum_rank = gf2_rank(core_direction + linear_core_images)
    output = {
        "source_spec_sha256": "f6fafe152124757787f54db3869bb7ef7d8106e8a7293ee341d511ec279e7d36",
        "sampling_frame": {
            "profile": "Thunder-512",
            "initial_frame": "128 deterministic independent full internal states per split",
            "holdout_frame": "128 independently seeded deterministic full internal states",
            "difference_families": len(families),
            "measurement": "Hamming weight of P^r(x) xor P^r(x xor d), and whether digest projection agrees",
        },
        "structured_rounds": results,
        "rotation_equivariance": {
            "tested_pairs": 32 * 5,
            "mismatches": rotation_mismatches,
        },
        "one_round_affine_core": {
            "direction_dimension": core_rank,
            "L_image_dimension": image_rank,
            "sum_dimension": sum_rank,
            "intersection_dimension": core_rank + image_rank - sum_rank,
        },
    }
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
