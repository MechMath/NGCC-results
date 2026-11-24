#!/usr/bin/env python3
"""Deduplicate a completed cross-family AXIS search artifact."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from axis_search import analyze


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()

    raw_records = []
    metadata = None
    with args.input.open(encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            if record["type"] == "metadata":
                metadata = {key: value for key, value in record.items() if key != "type"}
            elif record["type"] == "hash":
                raw_records.append(record)
    if metadata is None:
        raise SystemExit("no metadata")

    unique = {}
    for record in raw_records:
        key = (int(record["instance"]), int(record["message_len_bits"]), int(record["message_int"]))
        unique.setdefault(key, record)
    records = list(unique.values())
    instances = sorted({int(record["instance"]) for record in records})
    result = {
        instance: analyze(
            [record for record in records if int(record["instance"]) == instance],
            sum(int(record["instance"]) == instance for record in records),
        )
        for instance in instances
    }
    corrected = {
        "type": "metadata",
        **metadata,
        "raw_cross_family_records": len(raw_records),
        "deduplicated_candidates": len(records) // len(instances),
        "deduplication": (
            "identical (message_len_bits,message_int) values represented in multiple "
            "families are one message, not a collision"
        ),
        "corrected_result": result,
    }
    args.summary.write_text(json.dumps(corrected, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(corrected, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
