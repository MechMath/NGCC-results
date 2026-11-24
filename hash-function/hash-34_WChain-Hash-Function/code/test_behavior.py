#!/usr/bin/env python3
"""Boundary/API tests scoped to the exact implementation in this workspace."""

from __future__ import annotations

import hashlib
import json
import time

from wchain import hash_bits, hash_bytes, pad_bits


def bits_to_bytes(bits):
    return bytes(sum(bits[i + j] << (7 - j) for j in range(8))
                 for i in range(0, len(bits), 8))


def main():
    started = time.time()
    out = {
        "source_model_sha256": hashlib.sha256(open("wchain.py", "rb").read()).hexdigest(),
        "padding": {},
        "byte_bit_api": {},
        "short_message_collision_scan": {},
        "tail_ignored_by_bit_api": {},
    }
    for version, block_bits, digest_bits in ((1, 1152, 512), (2, 2304, 1024)):
        padded_lengths = set()
        for length in list(range(block_bits + 1)) + [
            block_bits + 1, block_bits + 2, 2 * block_bits - 1,
            2 * block_bits, 2 * block_bits + 1,
        ]:
            bits = [0] * length
            padded = pad_bits(bits, block_bits)
            assert len(padded) == (length + 1 + block_bits - 1) // block_bits
            assert all(len(block) == block_bits for block in padded)
            # The last one is uniquely the first delimiter not followed by one.
            flat = sum(padded, [])
            delimiter = max(i for i, bit in enumerate(flat) if bit)
            assert flat[delimiter:] == [1] + [0] * (len(flat) - delimiter - 1)
            padded_lengths.add((length, len(padded)))
        out["padding"][f"v{version}"] = {
            "tested_raw_lengths": len(padded_lengths),
            "all_follow_10star": True,
            "block_bits": block_bits,
        }

        api_pairs = []
        for n in (0, 1, 7, 8, 63, 64, 71, 72, 143, 144, 145, 287, 288,
                  289, 575, 576, 1151, 1152, 2303, 2304):
            data = bytes(i & 255 for i in range(n))
            a = hash_bytes(version, data)
            digest_bits_model = hash_bits(
                version, [(x >> (7 - j)) & 1 for x in data for j in range(8)])
            assert a == bits_to_bytes(digest_bits_model)
            api_pairs.append(n)
        out["byte_bit_api"][f"v{version}"] = {
            "tested_byte_lengths": api_pairs,
            "digest_bits": digest_bits,
            "agrees": True,
        }

        # Exhaust all bitstrings of lengths <= 10.  This is finite evidence only.
        seen = {}
        tested = 0
        for n in range(11):
            for value in range(1 << n):
                bits = [(value >> (n - 1 - i)) & 1 for i in range(n)]
                digest = bits_to_bytes(hash_bits(version, bits))
                assert digest not in seen, (version, n, value, seen[digest])
                seen[digest] = (n, value)
                tested += 1
        out["short_message_collision_scan"][f"v{version}"] = {
            "lengths": [0, 10],
            "messages_tested": tested,
            "collisions": 0,
            "scope": "finite evidence only; not a collision-resistance proof",
        }

        a = hash_bits(version, ([1, 0, 1]))
        b = hash_bits(version, [(0xa0 >> (7 - i)) & 1 for i in range(8)][:3])
        c = hash_bits(version, [(0xbf >> (7 - i)) & 1 for i in range(8)][:3])
        assert a == b == c
        out["tail_ignored_by_bit_api"][f"v{version}"] = True

    out["elapsed_seconds"] = time.time() - started
    print(json.dumps(out, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
