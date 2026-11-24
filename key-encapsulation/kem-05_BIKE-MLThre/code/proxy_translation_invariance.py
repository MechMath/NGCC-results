#!/usr/bin/env python3
"""Exact invariance proxy for the scalar syndrome-weight timing observable.

This script does not claim to execute BIKE.  It checks the group-theoretic
identity that underlies every timing model whose only secret-dependent input is
wt(c*h_S), and reports the repetition scale implied by the prior measured
linear timing fit.
"""

import json
import random
import statistics


R = 12323
W = 71
N_MASKS = 256
SEED = 0xB1CE12323


def syndrome_weight(mask, support):
    parity = {}
    for cpos in mask:
        for spos in support:
            pos = (cpos + spos) % R
            parity[pos] = parity.get(pos, 0) ^ 1
    return sum(parity.values())


def main():
    rng = random.Random(SEED)
    support = set(rng.sample(range(R), W))
    shift = rng.randrange(1, R)
    rotated = {(s + shift) % R for s in support}
    assert len(rotated) == W
    assert rotated != support

    masks = []
    for _ in range(N_MASKS):
        density = rng.randrange(1, 251) / 1000.0
        masks.append({j for j in range(R) if rng.random() < density})

    pairs = [(syndrome_weight(c, support), syndrome_weight(c, rotated))
             for c in masks]
    singleton_weights = [syndrome_weight({a}, support) for a in range(R)]

    # Conditional noise calculation from the prior 128-bit timing run:
    # cycles = intercept + beta*syndrome_weight + residual.
    beta = 555.0546800646321
    residual_sd = 1461311.006927799
    repetitions_for_one_weight = 25.0 * (residual_sd / beta) ** 2

    print(json.dumps({
        "schema": "mmat.proxy-translation-invariance/v1",
        "parameters": {
            "r": R,
            "support_weight": W,
            "random_masks": N_MASKS,
            "shift": shift,
        },
        "invariance": {
            "all_random_mask_weights_equal": all(a == b for a, b in pairs),
            "number_equal": sum(a == b for a, b in pairs),
            "distinct_rotated_support": rotated != support,
            "all_singleton_weights_equal_to_71": all(x == W for x in singleton_weights),
        },
        "conditional_timing_resolution": {
            "measured_beta_cycles_per_weight": beta,
            "measured_residual_sd_cycles": residual_sd,
            "repetitions_per_mask_for_5sigma_one_weight_separation":
                repetitions_for_one_weight,
            "caveat": (
                "This is an extrapolation from a single-key, one-host linear fit, "
                "not a verified timing law or an executed recovery experiment."
            ),
        },
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
