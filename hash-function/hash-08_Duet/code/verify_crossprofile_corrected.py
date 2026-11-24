#!/usr/bin/env python3
"""Exhaustive symbolic audit of the corrected Duet-768/1024 one-block split.

For every message length 0..767, this checks which padded source or common
f1-output word occupies each of the 30 f2-input coordinates.  Symbolic equality
of the complete inputs is then decided by checking the reported constraints at
each padding position (there are only eight possible forced-zero words).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

SIGMA12 = (8, 2, 11, 0, 5, 9, 3, 10, 1, 7, 4, 6)
SIGMA17 = (9, 2, 15, 0, 6, 12, 4, 16, 1, 10, 7, 14, 3, 11, 5, 13, 8)


def main() -> None:
    u768 = [("p17", SIGMA17[i]) for i in range(17)] + [
        ("X", i) for i in range(17, 30)
    ]
    u1024 = [("p12", SIGMA12[i]) for i in range(12)] + [
        ("X", i) for i in range(12, 30)
    ]
    equality_constraints = []
    mismatch_positions = []
    capacity_mismatch_positions = []
    first_rate_constraints = []
    for pos, (a, b) in enumerate(zip(u768, u1024)):
        if a == b:
            continue
        mismatch_positions.append(pos)
        if a[0] in {"p12", "p17"} and b[0] == "X":
            capacity_mismatch_positions.append(pos)
            if b[1] in (12, 13, 14, 15, 16):
                pass
            else:
                first_rate_constraints.append((a, b))
        elif b[0] in {"p12", "p17"} and a[0] == "X":
            capacity_mismatch_positions.append(pos)
            if a[1] in (12, 13, 14, 15, 16):
                pass
            else:
                first_rate_constraints.append((a, b))
        else:
            first_rate_constraints.append((a, b))

    # The nontrivial source constraints all force x3..x11 to zero.
    forced_zero = {3, 4, 5, 6, 7, 8, 9, 10, 11}
    lower = []
    upper = []
    for length in range(768):
        pad_word, pad_bit = divmod(length, 64)
        if length < 192:
            assert pad_word in (0, 1, 2)
            lower.append(length)
        else:
            assert pad_word in forced_zero
            upper.append(length)

    assert capacity_mismatch_positions == list(range(12, 17))
    assert len(lower) == 192 and len(upper) == 576
    pdf = Path(
        "/home/mmat/mmat-preview/campaigns/rebuild-20261119/runs/"
        "rebuild-092-hash-08-ds02/insights/213c50d7893bafb6/authors/"
        "7601703a4aad43e2/native/duet-gcore.pdf"
    )
    result = {
        "u768": u768,
        "u1024": u1024,
        "nontrivial_source_equalities": first_rate_constraints,
        "forced_padded_zero_words": sorted(forced_zero),
        "mismatch_positions": mismatch_positions,
        "capacity_mismatch_positions": capacity_mismatch_positions,
        "capacity_words_that_must_be_zero_for_lower_range": list(range(12, 17)),
        "lower_range_lengths_checked": [min(lower), max(lower), len(lower)],
        "upper_range_lengths_checked": [min(upper), max(upper), len(upper)],
        "pdf_sha256": hashlib.sha256(pdf.read_bytes()).hexdigest(),
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
