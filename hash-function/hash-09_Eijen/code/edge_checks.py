#!/usr/bin/env python3
"""Boundary and invariant checks for the Eijen finalization discrepancy.

The theorem is proved in the PDF text. This script tests that the local model
realises the proved final-state invariant on deterministic inputs not used to
discover the mismatch: lengths around one- and two-block boundaries, including
the 768-bit profile.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import eijen_ref as e


def pattern(seed: int, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(
            hashlib.sha256(f"eijen-boundary:{seed}:{counter}".encode()).digest()
        )
        counter += 1
    return bytes(out[:length])


def main() -> None:
    cases = []
    for h, (rate, _) in e.PROFILES.items():
        rate_bytes = rate // 8
        lengths = sorted(
            {
                0,
                1,
                rate_bytes - 1,
                rate_bytes,
                rate_bytes + 1,
                2 * rate_bytes - 1,
                2 * rate_bytes,
                2 * rate_bytes + 1,
            }
        )
        for seed, length in enumerate(lengths):
            message = pattern(1000 * h + seed, length)
            literal, _ = e.hash_message(message, h)
            alternate, _ = e.hash_message(
                message, h, feedforward_before_final_constant=True
            )
            literal_numeric = int.from_bytes(literal, "little")
            alternate_numeric = int.from_bytes(alternate, "little")
            difference = literal_numeric ^ alternate_numeric
            cases.append(
                {
                    "profile": h,
                    "message_bytes": length,
                    "message_sha256": hashlib.sha256(message).hexdigest(),
                    "padding_blocks": (length + 1 + rate_bytes - 1) // rate_bytes,
                    "literal_digest": e.digest_hex(literal),
                    "preconstant_feedforward_digest": e.digest_hex(alternate),
                    "xor_numeric": f"{difference:0{h // 4}X}",
                    "difference_is_final_digest_integer_msb": difference == 1 << (h - 1),
                }
            )
    Path("edge-checks.json").write_text(
        json.dumps(
            {
                "sampling_frame": (
                    "For each profile, deterministic SHA-256-derived byte strings "
                    "at lengths 0, 1, r/8-1, r/8, r/8+1, 2r/8-1, 2r/8, "
                    "2r/8+1. These lengths test padding and multi-block boundaries."
                ),
                "cases": cases,
                "all_cases_follow_proved_invariant": all(
                    case["difference_is_final_digest_integer_msb"] for case in cases
                ),
            },
            indent=2,
        )
        + "\n"
    )
    print(
        json.dumps(
            {
                "cases": len(cases),
                "all_cases_follow_proved_invariant": all(
                    case["difference_is_final_digest_integer_msb"] for case in cases
                ),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
