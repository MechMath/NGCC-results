#!/usr/bin/env python3
"""Structural and implementation cross-checks for thunder.py."""

from __future__ import annotations

import hashlib
import itertools
import json
from collections import Counter

import thunder as t


def parity(x: int) -> int:
    return x.bit_count() & 1


def linearity(outputs: list[int]) -> int:
    maximum = 0
    for mask in range(32):
        s = sum(1 if parity(mask & y) else -1 for y in outputs)
        maximum = max(maximum, abs(s))
    return maximum


def report_basic() -> dict:
    ddt = [[0] * 32 for _ in range(32)]
    for a in range(32):
        for x in range(32):
            out_x = 0
            out_x_delta = 0
            xp = tuple((x >> i) & 1 for i in range(5))
            ap = tuple((a >> i) & 1 for i in range(5))
            for i, bit in enumerate(t._psi_word(xp)):
                out_x |= bit << i
            for i, bit in enumerate(t._psi_word(tuple(xp[j] ^ ap[j] for j in range(5)))):
                out_x_delta |= bit << i
            ddt[a][out_x ^ out_x_delta] += 1
    alphabet = ["".join(str(t._psi_word(tuple((x >> i) & 1 for i in range(5)))[j]) for j in range(5)) for x in range(32)]
    result = {
        "bijective": len(set(alphabet)) == 32,
        "differential_uniformity": max(max(row) for row in ddt[1:]),
        "vectorial_linearity": max(
            abs(
                sum(
                    1 if parity(input_mask & x) ^ parity(output_mask & int(s, 2)) else -1
                    for x, s in enumerate(alphabet)
                )
            )
            for input_mask in range(32)
            for output_mask in range(1, 32)
        ),
        "output_weight_counts": dict(Counter(sum(t._psi_word(tuple((x >> i) & 1 for i in range(5)))) for x in range(32))),
        "fixed_points": sum(t._psi_word(tuple((x >> i) & 1 for i in range(5))) == tuple((x >> i) & 1 for i in range(5)) for x in range(32)),
    }
    # Algebraic degree by ANF of each output bit.
    degrees = []
    for j in range(5):
        coeff = [t._psi_word(tuple((v >> i) & 1 for i in range(5)))[j] for v in range(32)]
        for bit in range(5):
            for v in range(32):
                if (v >> bit) & 1:
                    coeff[v] ^= coeff[v ^ (1 << bit)]
        degrees.append(max(v.bit_count() for v, c in enumerate(coeff) if c))
    result["algebraic_degree"] = degrees
    return result


def report_trail() -> dict:
    # Appendix Table 21, two-round differential trail.
    before0 = [(2, 0, 41), (2, 0, 55), (2, 2, 26), (2, 2, 61), (2, 3, 4), (2, 3, 25)]
    after0 = [(2, 0, 4), (2, 0, 25), (2, 2, 41), (2, 2, 55), (2, 4, 26), (2, 4, 61)]
    before1 = [(0, 1, 12), (0, 1, 55), (2, 2, 41), (2, 2, 55), (4, 3, 12), (4, 3, 41)]
    after1 = [(0, 3, 12), (0, 3, 55), (2, 4, 41), (2, 4, 55), (4, 0, 12), (4, 0, 41)]

    def diff_at(state: t.State, positions):
        return {pos: (state[pos[0]][pos[1]] >> pos[2]) & 1 for pos in positions}

    # Check the S-box transitions by direct derivative counts.
    rounds = []
    for inp, out in ((before0, after0), (before1, after1)):
        by_column = {}
        for pos in inp:
            by_column.setdefault((pos[0], pos[2]), set()).add(pos[1])
        transitions = []
        for pos in out:
            by_column.setdefault((pos[0], pos[2]), set()).add(pos[1])
        for x, z in sorted(by_column):
            din = sum(1 << y for y in range(5) if (x, y, z) in inp)
            dout = sum(1 << y for y in range(5) if (x, y, z) in out)
            count = 0
            for value in range(32):
                a = tuple((value >> i) & 1 for i in range(5))
                ap = tuple(a[i] ^ ((din >> i) & 1) for i in range(5))
                y = t._psi_word(a)
                bp = t._psi_word(ap)
                actual = sum((y[i] ^ bp[i]) << i for i in range(5))
                count += actual == dout
            transitions.append({"x": x, "z": z, "din": din, "dout": dout, "count": count})
        rounds.append(transitions)

    # Linear layer maps the first output difference to the second input exactly.
    first_mid = t.state_from_lanes(0 for _ in range(25))
    # Reconstruct a lane state from bit deltas for L = pi(theta(rho(.))).
    def state_from_bits(positions):
        lanes = [0] * 25
        for x, y, z in positions:
            lanes[5 * y + x] |= 1 << z
        return t.state_from_lanes(lanes)

    mapped = t.pi(t.theta(t.rho(state_from_bits(after0))))
    mapped_bits = {(x, y, z) for x in range(5) for y in range(5) for z in range(64) if (mapped[x][y] >> z) & 1}
    expected = set(before1)
    return {
        "round_transitions": rounds,
        "linear_mapping_exact": mapped_bits == expected,
        "mapped_bits": sorted(mapped_bits),
        "expected_bits": sorted(expected),
        "weight": sum(r["count"].bit_length() - 1 for r in rounds[0]) + sum(r["count"].bit_length() - 1 for r in rounds[1]),
    }


def cross_check_permutation() -> dict:
    # Independent packed-state implementation in one integer.  This is not
    # evidence binding, but it catches coordinate/lane serialization mistakes.
    def rotl_state_word(word: int, n: int) -> int:
        lanes = [(word >> (64 * i)) & t.MASK64 for i in range(25)]
        return sum(t.rotl64(v, n) << (64 * i) for i, v in enumerate(lanes))

    def alt_p(state_int: int, rounds: int) -> int:
        for r in range(rounds):
            lanes = [(state_int >> (64 * i)) & t.MASK64 for i in range(25)]

            def get(x, y):
                return lanes[5 * y + x]

            lanes[0] ^= t.ROUND_CONSTANTS[r]
            lanes = [t.rotl64(lanes[5 * y + x], -t.TAU[x][y]) for y in range(5) for x in range(5)]
            p = [get(x, 0) ^ get(x, 1) ^ get(x, 2) ^ get(x, 3) ^ get(x, 4) for x in range(5)]
            q = [get(x, 0) ^ t.rotr64(get(x, 1), 50) ^ t.rotr64(get(x, 2), 6) ^ t.rotr64(get(x, 3), 10) ^ t.rotr64(get(x, 4), 27) for x in range(5)]
            e = [p[x] ^ t.rotr64(p[(x - 1) % 5], 1) for x in range(5)]
            f = [q[(x + 1) % 5] ^ t.rotr64(q[(x - 2) % 5], 36) for x in range(5)]
            old = [get(x, y) for y in range(5) for x in range(5)]
            lanes = [old[5 * y + x] ^ t.rotr64(e[x], 26) ^ t.rotr64(f[x], 26 + t.THETA_PARAMS[y][3]) for y in range(5) for x in range(5)]
            pi_lanes = [0] * 25
            for y in range(5):
                for x in range(5):
                    pi_lanes[5 * ((2 * x + 3 * y + 2) % 5) + y] = lanes[5 * y + x]

            def get_pi(x, y):
                return pi_lanes[5 * y + x]

            psi_lanes = [0] * 25
            for x in range(5):
                for z in range(64):
                    bits = tuple((get_pi(x, y) >> z) & 1 for y in range(5))
                    outbits = t._psi_word(bits)
                    for y in range(5):
                        psi_lanes[5 * y + x] |= outbits[y] << z
            state_int = sum(v << (64 * i) for i, v in enumerate(psi_lanes))
        return state_int

    seed = int.from_bytes(hashlib.sha256(b"Thunder permutation cross-check").digest(), "big")
    lanes = []
    for i in range(25):
        seed = int.from_bytes(hashlib.sha256(seed.to_bytes(32, "big") + bytes([i])).digest(), "big")
        lanes.append(seed & t.MASK64)
    state = t.state_from_lanes(lanes)
    mismatches = []
    for rounds in range(1, 13):
        direct = t.lanes_to_state_int(t.thunder_p(state, rounds))
        independent = alt_p(t.lanes_to_state_int(state), rounds)
        if direct != independent:
            mismatches.append(rounds)
    return {"input_lanes": lanes, "mismatched_round_counts": mismatches}


def digest_vectors() -> dict:
    messages = [b"", b"a", b"abc", bytes(range(256))]
    nonce = int.from_bytes(hashlib.sha256(b"Thunder deterministic messages").digest(), "big")
    for length in (0, 1, 7, 8, 31, 32, 63, 64, 95, 96, 97, 127, 128, 129, 255, 256, 1023):
        nonce = int.from_bytes(hashlib.sha256(nonce.to_bytes(32, "big") + length.to_bytes(8, "big")).digest(), "big")
        messages.append(nonce.to_bytes(32, "big")[: (length + 31) // 32][:length] if length <= 256 else bytes(((nonce >> (8 * (i % 32))) & 255) for i in range(length)))
    result = {}
    for name in t.FIXED_OUTPUT_PARAMS:
        inst = t.Instance.get(name)
        result[name] = [
            {
                "message_hex": message.hex(),
                "message_bits": len(message) * 8,
                "digest_hex": inst.digest(message).hex(),
            }
            for message in messages
        ]
    return result


def main() -> None:
    out = {
        "source_spec_sha256": "f6fafe152124757787f54db3869bb7ef7d8106e8a7293ee341d511ec279e7d36",
        "psi": report_basic(),
        "appendix_trail": report_trail(),
        "permutation_cross_check": cross_check_permutation(),
        "digest_vectors": digest_vectors(),
    }
    print(json.dumps(out, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
