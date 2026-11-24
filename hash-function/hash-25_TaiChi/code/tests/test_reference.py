#!/usr/bin/env python3
"""Reproducible checks for the independent TaiChi reference model."""

from __future__ import annotations

import hashlib
import json
import platform
import random
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import taichi_ref as tc


def gf2_rank(rows: list[int], ncols: int) -> int:
    pivots: dict[int, int] = {}
    for value in rows:
        while value:
            p = value.bit_length() - 1
            if p not in pivots:
                pivots[p] = value
                break
            value ^= pivots[p]
    return len(pivots)


def inverse_lane_mapping() -> dict[int, int]:
    return {dst: src for src, dst in enumerate(tc.PI)}


def cycles(perm: list[int]) -> list[list[int]]:
    seen: set[int] = set()
    result: list[list[int]] = []
    for start in range(len(perm)):
        if start in seen:
            continue
        cyc = []
        x = start
        while x not in seen:
            seen.add(x)
            cyc.append(x)
            x = perm[x]
        result.append(cyc)
    return sorted(result, key=lambda c: c[0])


def hexword(x: int) -> str:
    return f"0x{x:016x}"


def main() -> None:
    rng = random.Random(0x546169436869)
    out: dict = {
        "python": platform.python_version(),
        "platform": platform.platform(),
    }

    # Q: bijection, cycles, scalar and bitsliced consistency, DDT.
    out["q"] = {
        "table": [tc.SBOX[x] for x in range(32)],
        "bijective": len(set(tc.SBOX)) == 32,
        "cycles": cycles(list(tc.SBOX)),
        "fixed_points": [x for x in range(32) if tc.SBOX[x] == x],
    }
    ddt = [[0] * 32 for _ in range(32)]
    for a in range(32):
        for x in range(32):
            ddt[a][tc.SBOX[x] ^ tc.SBOX[x ^ a]] += 1
    out["q"]["ddt_max_nontrivial"] = max(ddt[a][b] for a in range(1, 32) for b in range(32))
    # Check the bitsliced equations lane by lane on a nonuniform vector.
    vecs = [rng.getrandbits(64) for _ in range(5)]
    got = tc.q_layer(vecs + [0] * 25)[:5]
    expected = [0] * 5
    for k in range(64):
        y = tc.SBOX[sum(((v >> k) & 1) << i for i, v in enumerate(vecs))]
        for z in range(5):
            expected[z] |= ((y >> z) & 1) << k
    out["q"]["bitsliced_matches_scalar"] = got == expected

    # L: binary rank of each 384-bit core and of the full 1920-bit layer.
    core_columns = []
    zero = [0] * 30
    for bit in range(384):
        x = zero[:]
        x[bit // 64] = 1 << (bit % 64)
        y = tc.mrm6(x[:6])
        value = sum(v << (64 * i) for i, v in enumerate(y))
        core_columns.append(value)
    full_columns = []
    for bit in range(1920):
        x = zero[:]
        x[bit // 64] = 1 << (bit % 64)
        y = tc.l_layer(x)
        value = sum(v << (64 * i) for i, v in enumerate(y))
        full_columns.append(value)
    out["l"] = {
        "core_rank": gf2_rank(core_columns, 384),
        "full_rank": gf2_rank(full_columns, 1920),
        "zero_maps_to_zero": all(v == 0 for v in tc.l_layer(zero)),
        "output_rotations": tc.OUT_ROT,
    }
    # Demonstrate branch behavior at the word level over random samples.
    branch_min = 1000
    branch_hist = Counter()
    for _ in range(10000):
        total_in = total_out = 0
        for j in range(5):
            x6 = [rng.getrandbits(64) for _ in range(6)]
            y6 = tc.mrm6(x6)
            wi = sum(v.bit_count() for v in x6)
            wo = sum(v.bit_count() for v in y6)
            total_in += wi
            total_out += wo
        if total_in and total_out:
            both = min(total_in, total_out)
            branch_min = min(branch_min, both)
            branch_hist[min(total_in, total_out)] += 1
    out["l"]["sampled_min_nonzero_side_bitcount"] = branch_min
    out["l"]["sampled_branch_hist_low"] = dict(sorted(branch_hist.items())[:12])

    # Pi10 and constants.
    out["pi"] = {
        "map": tc.PI,
        "bijective": sorted(tc.PI) == list(range(30)),
        "cycles": cycles(tc.PI),
        "ten_order_mod31": next(k for k in range(1, 31) if pow(10, k, 31) == 1),
        "inverse_map": [inverse_lane_mapping()[i] for i in range(30)],
    }
    out["rc"] = {
        "first_ten": [hexword(c) for c in tc.RC[:10]],
        "disjoint_streams": set(tc.RC[:60]).isdisjoint(tc.RC[60:120]),
        "nonzero_all_120": all(tc.RC),
    }

    # Round-order sensitivity: all four adjacent swaps change a fixed vector.
    x = int.from_bytes(hashlib.shake_128(b"TaiChi round order").digest(240), "little")
    lanes = [(x >> (64 * n)) & tc.MASK64 for n in range(30)]

    def rnd1(a: list[int], order: str) -> list[int]:
        for op in order:
            if op == "L":
                a = tc.l_layer(a)
            elif op == "Q":
                a = tc.q_layer(a)
            elif op == "P":
                a = tc.pi_layer(a)
            elif op == "A":
                a = a[:]
                for j in range(5):
                    a[j] ^= tc.RC[j]
        return a

    baseline = rnd1(lanes, "LQPA")
    out["round_order"] = {
        "specified_L_Q_Pi_A_differs_from_adjacent_swap": {
            f"{s[0]}{s[1]}": rnd1(lanes, "LQPA") != rnd1(
                lanes, "".join(c if i not in (k, k + 1) else s[1 - (i - k)] for i, c in enumerate("LQPA"))
            )
            for k, s in enumerate(["LQ", "QP", "PA"])
        },
        "fixed_input_sha256": hashlib.sha256(x.to_bytes(240, "little")).hexdigest(),
        "fixed_output_sha256": hashlib.sha256(
            sum(v << (64 * n) for n, v in enumerate(baseline)).to_bytes(240, "little")
        ).hexdigest(),
    }

    # Padding and tags.
    pad_checks = {}
    for d, p in tc.PROFILES.items():
        e, elen, j = tc.pad_bits(0, 0, p.r)
        e2, e2len, j2 = tc.pad_bits(e, elen, p.r)
        pad_checks[str(d)] = {
            "empty_encoding_hex": f"{e:0{2 * (elen // 8)}x}",
            "empty_length": elen,
            "empty_j": j,
            "empty_encoding_is_prefix_of_encode_of_empty_encoding": (e2 & ((1 << elen) - 1)) == e,
            "double_encoding_length": e2len,
            "double_encoding_j": j2,
        }
    out["padding"] = pad_checks

    # Step/domain distinctions and transcript/squeeze schedules.
    domains = {}
    for d, p in tc.PROFILES.items():
        state0 = (0, 0, 0)
        st = {tag: tc.step(state0, 0, tag, p) for tag in ("Ab", "Fin", "Sq")}
        domains[str(d)] = {
            "step_outputs_pairwise_distinct": len(set(st.values())) == 3,
            "step_output_sha256": {
                tag: hashlib.sha256(
                    sum(v << (64 * n) for n, v in enumerate(vals)).to_bytes((p.r + 2 * p.c) // 8, "little")
                ).hexdigest()
                for tag, vals in st.items()
            },
        }
    out["domains"] = domains

    # P1/P2 concrete-call checks.
    p12 = {}
    for label, x0 in [("zero", 0), ("structured", int.from_bytes(bytes(range(240)), "little"))]:
        p12[label] = {
            "equal": tc.permutation(x0, 1) == tc.permutation(x0, 2),
            "xor_sha256": hashlib.sha256(
                (tc.permutation(x0, 1) ^ tc.permutation(x0, 2)).to_bytes(240, "little")
            ).hexdigest(),
        }
    out["p1_p2"] = p12

    # Deterministic hash vectors and transcript schedule.
    messages = [b"", b"\x00", b"\x01", b"abc", bytes(range(32)), bytes(range(179))]
    vectors = {}
    for d, p in tc.PROFILES.items():
        vectors[str(d)] = []
        for msg in messages:
            h = tc.hash_bytes(msg, d)
            _, tr = tc.hash_bits(int.from_bytes(msg, "little"), 8 * len(msg), d, trace=True)
            vectors[str(d)].append(
                {
                    "message_hex": msg.hex(),
                    "message_bits": 8 * len(msg),
                    "digest_hex": h.hex(),
                    "padded_bits": tr["padded_length"],
                    "tags": tr["tags"],
                    "squeezes": tr["squeezes"],
                }
            )
        # Length/schedule invariants for a dense family of lengths.
        checks = []
        for nbytes in list(range(0, 40)) + [p.r // 8 - 1, p.r // 8, p.r // 8 + 1, 179, 180, 181]:
            msg = bytes((i * 131 + nbytes) & 255 for i in range(nbytes))
            h = tc.hash_bytes(msg, d)
            _, tr = tc.hash_bits(int.from_bytes(msg, "little"), 8 * len(msg), d, trace=True)
            expected_blocks = (8 * nbytes + 2 + p.r - 1) // p.r
            expected_sq = max(0, (d - p.r + p.r - 1) // p.r)
            checks.append(
                len(h) * 8 == d
                and len(tr["blocks"]) == expected_blocks
                and tr["squeezes"] == expected_sq
                and tr["tags"][-1 - expected_sq] == "Fin"
                and all(t == "Sq" for t in tr["tags"][len(tr["tags"]) - expected_sq :])
            )
        vectors[str(d) + "_schedule_checks"] = {
            "count": len(checks),
            "all_pass": all(checks),
        }
    out["hash_vectors"] = vectors

    # Input-byte convention ambiguity: the same abstract bitstring under the
    # other conventional byte-bit order generally gives another digest.
    serial = {}
    for d in tc.PROFILES:
        msg = b"abc"
        lsb = tc.hash_bytes(msg, d)
        # reverse bits inside each byte, calling the same bitstring hash
        m = int.from_bytes(bytes(int(f"{b:08b}"[::-1], 2) for b in msg), "little")
        rev = tc.bits_to_bytes_lsb(tc.hash_bits(m, 24, d), d)
        serial[str(d)] = {
            "lsb_first_digest": lsb.hex(),
            "msb_first_per_byte_digest": rev.hex(),
            "differ": lsb != rev,
        }
    out["byte_bit_order"] = serial

    # Reduced-round single-bit avalanche.  This is sampling, not a proof.
    avalanche = {}
    for d in (512,):
        p = tc.PROFILES[d]
        for rounds in (1, 2, 3, 12):
            counts = []
            active_lanes = []
            for sample in range(8):
                base = rng.getrandbits(p.r)
                bit = rng.randrange(p.r)
                h0 = tc.hash_bits(base, p.r - 2, d, rounds=rounds)
                h1 = tc.hash_bits(base ^ (1 << bit), p.r - 2, d, rounds=rounds)
                counts.append((h0 ^ h1).bit_count())
                # Permutation avalanche, fixedFin capacities.
                y0 = tc.permutation(base, 1, rounds)
                y1 = tc.permutation(base ^ (1 << bit), 1, rounds)
                z = y0 ^ y1
                active_lanes.append(sum(bool((z >> (64 * n)) & tc.MASK64) for n in range(30)))
            avalanche[str(rounds)] = {
                "samples": 8,
                "hash_output_bit_diffs": counts,
                "perm_active_lanes": active_lanes,
            }
    out["reduced_avalanche"] = avalanche

    # Structured exact checks, not a full-round collision search.
    structured = {}
    for d, p in tc.PROFILES.items():
        vals = []
        for byte in (0, 1, 2, 0xFF):
            msg = bytes([byte]) * (p.r // 8 - 2)
            vals.append(tc.hash_bytes(msg, d).hex())
        structured[str(d)] = {"uniform_block_digests": vals, "distinct": len(vals) == len(set(vals))}
    out["structured_one_block"] = structured

    print(json.dumps(out, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
