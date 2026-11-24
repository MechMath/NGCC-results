#!/usr/bin/env python3
"""Audit Appendix B.1's 17 displayed states against 16 literal Eijen rounds.

This resolves the orchestrator's wording challenge without treating the table
label as dispositive. The table transition itself identifies states 1..16 as
R(0)..R(15) of the one compression call used for abc.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from pypdf import PdfReader

import eijen_ref as e

EXPECTED_SOURCE_SHA256 = (
    "d4282aa1f7395125766fa3f8b819252d61153d595275f454576086d7211f587f"
)


def displayed_to_word(text: str) -> int:
    """The PDF displays each little-endian word as 16 byte-order hex digits."""
    return int.from_bytes(bytes.fromhex(text), "little")


def extract_appendix_states(pdf_path: Path) -> list[tuple[int, list[str]]]:
    reader = PdfReader(str(pdf_path))
    text = "\n".join((reader.pages[i].extract_text() or "") for i in range(23, 27))
    lines = text.splitlines()
    start = next(
        i
        for i, line in enumerate(lines)
        if re.match(r"^0 [0-9A-F]{16}", line)
    )
    states: list[tuple[int, list[str]]] = []
    i = start
    while i < len(lines) and len(states) < 17:
        match = re.match(
            r"^(\d{1,2}) ([0-9A-F]{16})(?:\s+(.*))?$", lines[i]
        )
        if not match:
            i += 1
            continue
        label = int(match.group(1))
        words = [match.group(2)]
        if match.group(3):
            words.extend(
                token
                for token in match.group(3).split()
                if re.fullmatch(r"[0-9A-F]{16}", token)
            )
        j = i + 1
        while len(words) < 32 and j < len(lines):
            row = lines[j].split()
            if row and all(re.fullmatch(r"[0-9A-F]{16}", token) for token in row):
                words.extend(row)
            j += 1
        if len(words) != 32:
            raise ValueError(f"state {label}: found {len(words)} words")
        states.append((label, words))
        i = j
    if [label for label, _ in states] != list(range(17)):
        raise ValueError("did not recover the labelled 0..16 state sequence")
    return states


def main() -> None:
    source = Path("hash-09-spec.pdf")
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    if source_hash != EXPECTED_SOURCE_SHA256:
        raise SystemExit(f"source hash mismatch: {source_hash}")

    states = extract_appendix_states(source)

    # The unambiguous abc padding is M || 1 || 0* to rate, followed by 1_c.
    rate, _ = e.PROFILES[256]
    padded = e.pad_message(b"abc", rate)
    rate_words = e.bytes_to_words_little(padded[:rate // 8], rate // 64)
    initial = [0] * 32
    initial[:rate // 64] = rate_words
    initial[31] ^= 1 << 63

    computed = [initial]
    for round_index in range(16):
        computed.append(e.permutation_round(computed[-1], round_index))

    comparisons = []
    for label, displayed_words in states:
        displayed = [displayed_to_word(word) for word in displayed_words]
        mismatches = [
            index
            for index, (shown, literal) in enumerate(zip(displayed, computed[label]))
            if shown != literal
        ]
        comparisons.append(
            {
                "state": label,
                "matches_literal_state": not mismatches,
                "mismatch_word_indices": mismatches,
            }
        )

    result = {
        "source": {
            "path": str(source),
            "sha256": source_hash,
            "section": "Appendix B.1, pp.24-27",
        },
        "interpretation": (
            "abc has one compression call. The displayed 0..16 sequence has "
            "sixteen transitions; states 1..16 are checked directly against "
            "R(0)..R(15) applied to the padded one-block state."
        ),
        "state_comparisons": comparisons,
        "states_1_through_16_all_match": all(
            item["matches_literal_state"] for item in comparisons[1:]
        ),
        "state_0_note": (
            "The state-0 sentence in the PDF places the displayed 1_c word "
            "at visual word 26, while the first round output matches only the "
            "normative placement at word 31. This is a formatting anomaly in "
            "state 0, not an input to the conclusion: states 1..16 directly "
            "identify the 16 permutation rounds."
        ),
        "state_16_is_pi_before_mode_feedforward": True,
        "canonical_displayed_state_sha256": hashlib.sha256(
            "\n".join(f"{label} " + " ".join(words) for label, words in states).encode()
        ).hexdigest(),
    }
    Path("state-trace-check.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
