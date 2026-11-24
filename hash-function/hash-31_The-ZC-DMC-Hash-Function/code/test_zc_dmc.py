#!/usr/bin/env python3
"""Deterministic checks for the native ZC-DMC reference model."""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path

from zc_dmc import (
    ZC1280,
    ZC1536,
    algorithm3_padding,
    bits_to_state,
    chi_column,
    feed_forward,
    intended_padding,
    inverse_chi_column,
    inverse_permutation,
    inverse_permutation as inv_perm,
    inverse_rho,
    inverse_theta,
    permutation,
    rho,
    round_forward,
    round_inverse,
    state_to_bits,
    theta,
    zero_state,
    zc_dmc_hash,
)


def random_state(variant, rng):
    return tuple(tuple(rng.getrandbits(64) for _ in range(variant.lanes))
                 for _ in range(variant.planes))


def gf2_rank_theta(variant):
    """Rank of theta's 1280- or 1536-bit linear map by exact GF(2) rows."""
    def token(x, y, z):
        return (y * variant.lanes + x) * 64 + z

    rows = []
    for y0 in range(variant.planes):
        for x0 in range(variant.lanes):
            for z0 in range(64):
                basis = [[0] * variant.lanes for _ in range(variant.planes)]
                basis[y0][x0] = 1 << z0
                out = theta(tuple(tuple(p) for p in basis), variant)
                row = 0
                for y in range(variant.planes):
                    for x in range(variant.lanes):
                        word = out[y][x]
                        while word:
                            low = word & -word
                            z = low.bit_length() - 1
                            row |= 1 << token(x, y, z)
                            word ^= low
                rows.append(row)

    pivots = {}
    for row in rows:
        while row:
            p = row.bit_length() - 1
            if p in pivots:
                row ^= pivots[p]
            else:
                pivots[p] = row
                break
    return len(pivots)


def profile_tables():
    standard = [
        (1280, 512, 576, 704, 64, 512),
        (1536, 512, 576, 960, 64, 512),
        (1280, 768, 832, 448, 64, 768),
        (1536, 768, 832, 704, 64, 768),
        (1280, 1024, 1088, 192, 64, 1024),
        (1536, 1024, 1088, 448, 64, 1024),
    ]
    checked = []
    for m, n, c, shown_r, sq, sec in standard:
        checked.append({
            "m": m, "n": n, "c": c, "r": m - c,
            "c_equals_n_plus_64": c == n + 64,
            "shown_r_correct": shown_r == m - c,
            "security_equals_n": sec == n,
            "squeeze_calls": (n + sq - 1) // sq,
            "ok": c == n + 64 and shown_r == m - c and sec == n,
        })
    short = [
        (0, 380, 896, 512), (381, 508, 768, 256),
        (509, 764, 896, 512), (765, 1020, 768, 256),
        (1021, 1148, 896, 512), (1149, 1190, 683, 171),
        (1191, 1532, 768, 256), (1533, 1787, 683, 171),
        (1788, 2044, 768, 256), (2045, 2384, 683, 171),
        (2385, 2556, 768, 256), (2557, 2981, 683, 171),
        (2982, 3068, 768, 256), (48573, 48576, 586, 74),
    ]
    short_checked = []
    for lo, hi, c, sq in short:
        r = 1280 - c
        # For each interval endpoint, enumerate the number of permutation
        # calls under the specified intended padding.
        rows = []
        for length in (lo, hi):
            alpha = (length + 4 + r - 1) // r
            calls = alpha + (512 + sq - 1) // sq - 1
            rows.append((length, alpha, calls))
        short_checked.append({
            "lo": lo, "hi": hi, "c": c, "r": r, "squeeze_rate": sq,
            "endpoints": rows, "ok": r > 0 and c > 512,
        })
    return standard, checked, short, short_checked


def main():
    results = {
        "chi": {},
        "rounds": {},
        "permutations": {},
        "linear_stages": {},
        "padding": {},
        "tables": {},
    }

    for variant, width in ((ZC1280, 5), (ZC1536, 3)):
        universe = 1 << width
        image = {chi_column(x, width) for x in range(universe)}
        results["chi"][variant.name] = {
            "width": width,
            "universe": universe,
            "bijective": image == set(range(universe)),
            "inverse_formula_matches_all_inputs": all(
                inverse_chi_column(chi_column(x, width), width) == x
                for x in range(universe)
            ),
        }

        rng = random.Random(0x5A17 + variant.planes)
        round_cases = 32
        rounds_ok = 0
        rho_ok = 0
        theta_ok = 0
        for _ in range(round_cases):
            state = random_state(variant, rng)
            idx = rng.randrange(-11, 1)
            rounds_ok += round_inverse(round_forward(state, variant, idx), variant, idx) == state
            rho_ok += inverse_rho(rho(state, variant), variant) == state
            theta_ok += inverse_theta(theta(state, variant), variant) == state
        results["rounds"][variant.name] = {
            "seed": f"0x{0x5A17 + variant.planes:x}",
            "random_round_cases": round_cases,
            "round_inverse_successes": rounds_ok,
            "rho_inverse_successes": rho_ok,
            "theta_inverse_successes": theta_ok,
        }

        perm_ok = 0
        perm_cases = 8
        for _ in range(perm_cases):
            state = random_state(variant, rng)
            perm_ok += inverse_permutation(permutation(state, variant), variant) == state
        results["permutations"][variant.name] = {
            "random_12_round_cases": perm_cases,
            "inverse_successes": perm_ok,
        }

        rank = gf2_rank_theta(variant)
        results["linear_stages"][variant.name] = {
            "theta_rank": rank,
            "state_bits": variant.planes * variant.lanes * 64,
            "theta_full_rank": rank == variant.planes * variant.lanes * 64,
        }

        # One exact feed-forward identity and a few deterministic hash-mode
        # smoke tests. These are implementation checks, not security evidence.
        state = random_state(variant, rng)
        rate = variant.planes * variant.lanes * 64 - 576
        original_bits = state_to_bits(state, variant)
        perm_bits = state_to_bits(permutation(state, variant), variant)
        ff_bits = state_to_bits(feed_forward(state, variant, rate), variant)
        results["linear_stages"][variant.name]["feed_forward_capacity_identity"] = (
            ff_bits[:rate] == perm_bits[:rate]
            and ff_bits[rate:] == [
                a ^ b for a, b in zip(perm_bits[rate:], original_bits[rate:])
            ]
        )

    for variant, m in ((ZC1280, 1280), (ZC1536, 1536)):
        for c in (576, 832, 1088, 896):
            r = m - c
            if r <= 0:
                continue
            tested = []
            for length in (0, 1, max(0, r - 5), max(0, r - 4), r, 2 * r - 5):
                intended = intended_padding([0] * length, r)
                literal = algorithm3_padding([0] * length, r)
                tested.append({
                    "message_bits": length,
                    "intended_length": len(intended),
                    "intended_aligned": len(intended) % r == 0,
                    "literal_length": len(literal),
                    "literal_remainder": len(literal) % r,
                    "literal_aligned": len(literal) % r == 0,
                    "literal_equals_intended": literal == intended,
                })
            key = f"{variant.name}/c={c}"
            results["padding"][key] = {
                "rate": r,
                "cases": tested,
                "literal_always_aligned_and_equal": all(
                    row["literal_aligned"] and row["literal_equals_intended"]
                    for row in tested
                ),
            }

    standard, standard_checked, short, short_checked = profile_tables()
    results["tables"] = {
        "table_1_2_rows": len(standard),
        "table_1_2_checks": standard_checked,
        "table_1_2_all_ok": all(x["ok"] for x in standard_checked),
        "table_1_3_rows": len(short),
        "table_1_3_checks": short_checked,
        "table_1_3_all_well_formed": all(x["ok"] for x in short_checked),
    }

    mode_checks = []
    for variant in (ZC1280, ZC1536):
        for n in (512, 768, 1024):
            c = n + 64
            for length in (0, 1, 13):
                msg = [(i * 17 + length) & 1 for i in range(length)]
                digest = zc_dmc_hash(msg, variant, c, n, 64)
                other = zc_dmc_hash(msg + [1], variant, c, n, 64)
                mode_checks.append({
                    "variant": variant.name,
                    "n": n,
                    "c": c,
                    "message_bits": length,
                    "digest_bits": len(digest),
                    "digest_hex": f"{sum(b << i for i, b in enumerate(digest)):0{n // 4}x}",
                    "differs_from_one_bit_longer": digest != other,
                })
    short_digest = zc_dmc_hash([1, 0, 1], ZC1280, 896, 512, 512)
    literal_digest = zc_dmc_hash([], ZC1280, 576, 512, 64, literal_padding=True)
    intended_digest = zc_dmc_hash([], ZC1280, 576, 512, 64)
    results["mode_checks"] = {
        "standard_profiles": mode_checks,
        "all_digest_lengths_correct": all(x["digest_bits"] == x["n"] for x in mode_checks),
        "all_one_bit_extensions_differ": all(
            x["differs_from_one_bit_longer"] for x in mode_checks
        ),
        "short_profile_digest_bits": len(short_digest),
        "literal_algorithm3_equals_intended_padding": literal_digest == intended_digest,
    }

    ok = (
        all(x["bijective"] and x["inverse_formula_matches_all_inputs"]
            for x in results["chi"].values())
        and all(x["round_inverse_successes"] == x["random_round_cases"]
                and x["rho_inverse_successes"] == x["random_round_cases"]
                and x["theta_inverse_successes"] == x["random_round_cases"]
                for x in results["rounds"].values())
        and all(x["inverse_successes"] == x["random_12_round_cases"]
                for x in results["permutations"].values())
        and all(x["theta_full_rank"] for x in results["linear_stages"].values())
        and all(x["feed_forward_capacity_identity"]
                for x in results["linear_stages"].values())
        and results["mode_checks"]["all_digest_lengths_correct"]
        and results["mode_checks"]["all_one_bit_extensions_differ"]
        and results["mode_checks"]["short_profile_digest_bits"] == 512
        and results["mode_checks"]["literal_algorithm3_equals_intended_padding"]
        and all(row["intended_aligned"]
                and x["literal_always_aligned_and_equal"]
                for x in results["padding"].values()
                for row in x["cases"])
    )
    results["overall_model_correctness_checks"] = ok

    out = Path("artifacts/test-results.json")
    out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(results, indent=2))
    print(f"result_json={out}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
