#!/usr/bin/env python3
"""Probe explicit serialization conventions against the three empty vectors.

This is a debugging artifact, not execution evidence for the reference hash.
Failure does not establish that the PDF implementation is wrong, because the PDF
does not define every serialization convention needed by the pseudocode.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import platform
from pathlib import Path

from uhash_ref import Convention, uhash


ROOT = Path(__file__).resolve().parents[1]
PDF = ROOT / "source" / "hash-05-spec.pdf"
OUT = ROOT / "artifacts" / "convention_probe.json"
EXPECTED = {
    512: "54DEDA01CFFC8ECA07114698A114CA828DD3873462F36274DC196CAB000CF4EAFD109D7AE9D70BDF59D9F71CCD5AD8E506215D5D8AD1F546ECFFE9FC1866DAAA",
    768: "1702A336338922CFE6CEE74B1799782C4586776D803E40A3525BE337CC1DF08158C9634D5CAA19843544ED0C7DFD81F398478F2884871A6DCC6FF063439EE133456EB3A6CB23E8E5022B5A888B7B19EEDDC59446A102773FED92795E2B6DFF87",
    1024: "5BAD7ACAC904DB05EAC79A24C20A71F7B08D4F4742826B0A88C8A92B1B11F5326ADF0AE60417BA2900CCDBFA50CB38BA49B0C96AB8CEB9180A44E0743C633033DC8E67BE2327691C801384FBB4FE2831681B8A5A9D8967CB34D6C398FA9AC6808872BFDCD3D4686048AC9215D8AD1210F04403EDC01DC30B90A1B41B96DE06A7",
}


def main() -> None:
    rc_modes = [("single", 0), ("single", 32), ("single", 64), ("single", 96),
                ("high", 0), ("repeat", 0)]
    records = {}
    for bits, expected in EXPECTED.items():
        tested = 0
        matches = []
        for nibble, word, perm, byte_order, swap_state, swap_keys, (rc_mode, rc_shift) in itertools.product(
                (False, True), (False, True), (False, True), ("big", "little"),
                (False, True), (False, True), rc_modes):
            conv = Convention(
                nibble_msb_first=nibble,
                word_msb_first=word,
                permutation_output_index=perm,
                rc_placement=rc_mode,
                rc_shift=rc_shift,
                byte_order=byte_order,
                swap_state_halves=swap_state,
                swap_round_keys=swap_keys,
            )
            got = uhash(b"", bits, conv)["digest_hex"]
            tested += 1
            if got == expected:
                matches.append(conv.__dict__)
        records[str(bits)] = {
            "tested_conventions": tested,
            "match_count": len(matches),
            "matches": matches,
        }
    result = {
        "input_pdf": {"path": str(PDF.relative_to(ROOT)),
                      "sha256": hashlib.sha256(PDF.read_bytes()).hexdigest()},
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "sampling_frame": (
            "2 nibble orders x 2 word orders x 2 permutation-map directions x "
            "2 byte orders x 2 state-half swaps x 2 round-key swaps x 6 RC placements"
        ),
        "results": records,
        "interpretation_limits": (
            "No match means only that this explicit 384-point convention family does "
            "not reproduce the empty vectors. The PDF omits normalization details, "
            "and the local implementation is not crypto_run evidence."
        ),
    }
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
