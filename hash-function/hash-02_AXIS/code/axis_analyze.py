#!/usr/bin/env python3
"""Analyze an axis_search.py JSONL artifact without claiming statistical security."""

from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict
from pathlib import Path


def hamming(left: int, right: int, width: int) -> int:
    return (left ^ right).bit_count()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    rows = []
    metadata = None
    with args.artifact.open(encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            if record["type"] == "metadata":
                metadata = record
            elif record["type"] == "hash":
                record["digest_int_value"] = int(record["digest_int_hex"], 16)
                record["message"] = (record["message_len_bits"], record["message_int"])
                rows.append(record)
    if metadata is None:
        raise SystemExit("artifact has no metadata line")

    result: dict[str, object] = {
        "source": str(args.artifact.resolve()),
        "metadata": metadata,
        "scope_warning": (
            "Descriptive statistics over the enumerated corpus do not establish "
            "collision resistance, avalanche security, or an attack."
        ),
    }

    onebit: dict[tuple[int, int, int], dict[int, int]] = defaultdict(dict)
    for row in rows:
        if row["family"] != "onebit":
            continue
        label = str(row["label"])
        fields = dict(part.split("=", 1) for part in label.split(","))
        onebit[
            (
                int(row["instance"]),
                int(fields["len"]),
                0 if fields["base"] == "zero" else 1,
            )
        ][int(fields["flip"])] = int(row["digest_int_value"])

    onebit_summary = []
    for (instance, length, base), digests in sorted(onebit.items()):
        base_digest = digests[-1]
        distances = [
            hamming(base_digest, digest, instance)
            for position, digest in digests.items()
            if position >= 0
        ]
        onebit_summary.append(
            {
                "instance": instance,
                "message_len_bits": length,
                "base": "one" if base else "zero",
                "flips": len(distances),
                "min_digest_hamming": min(distances),
                "max_digest_hamming": max(distances),
                "mean_digest_hamming": sum(distances) / len(distances),
                "all_zero_distance": sum(distance == 0 for distance in distances),
            }
        )
    result["onebit_avalanche_descriptive"] = onebit_summary

    balances = []
    for instance in sorted({int(row["instance"]) for row in rows}):
        instance_rows = [row for row in rows if int(row["instance"]) == instance]
        counts = [
            sum((int(row["digest_int_value"]) >> position) & 1 for row in instance_rows)
            for position in range(instance)
        ]
        n = len(instance_rows)
        expected = n / 2
        z = max(
            (
                abs(count - expected) / math.sqrt(n / 4)
                for count in counts
            ),
            default=0.0,
        )
        balances.append(
            {
                "instance": instance,
                "samples": n,
                "min_one_count": min(counts),
                "max_one_count": max(counts),
                "max_abs_binomial_z_descriptive": z,
                "positions_with_zero_ones": sum(count == 0 for count in counts),
                "positions_with_all_ones": sum(count == n for count in counts),
            }
        )
    result["digest_bit_balance_descriptive"] = balances

    text = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        args.output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


if __name__ == "__main__":
    main()
