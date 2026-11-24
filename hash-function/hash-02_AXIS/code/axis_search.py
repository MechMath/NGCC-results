#!/usr/bin/env python3
"""Deterministic structured-family search in the independent AXIS simulator.

The search covers an explicitly enumerated finite corpus.  A reported collision
is an exact witness; failure is only a statement about this corpus.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing
import platform
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from axis_sim import AXIS


@dataclass(frozen=True)
class Candidate:
    family: str
    label: str
    message_int: int
    message_len_bits: int

    @property
    def key(self) -> tuple[int, int]:
        return self.message_len_bits, self.message_int


def periodic_message(period: int, pattern: int, length: int) -> int:
    value = 0
    for position in range(length):
        value |= ((pattern >> (position % period)) & 1) << position
    return value


def constant_family() -> list[Candidate]:
    lengths = (
        0,
        1,
        7,
        8,
        15,
        16,
        31,
        32,
        63,
        64,
        65,
        95,
        96,
        127,
        128,
        129,
        191,
        192,
        193,
        255,
        256,
        257,
        511,
        512,
        1023,
        1024,
    )
    patterns = (0x00, 0xFF, 0x55, 0xAA, 0x01, 0x80, 0x7F, 0xFE)
    by_key: dict[tuple[int, int], Candidate] = {}
    for length in lengths:
        for pattern in patterns:
            value = sum(pattern << (8 * i) for i in range((length + 7) // 8))
            value &= (1 << length) - 1
            candidate = Candidate(
                "constant", f"len={length},byte={pattern:02x}", value, length
            )
            by_key.setdefault(candidate.key, candidate)
    return list(by_key.values())


def periodic_family() -> list[Candidate]:
    lengths = (63, 64, 65, 95, 96, 127, 128, 129, 191, 192, 193, 255, 256, 511, 512)
    by_key: dict[tuple[int, int], Candidate] = {}
    for period in range(1, 7):
        for pattern in range(1 << period):
            for length in (period,) + lengths:
                value = periodic_message(period, pattern, length)
                candidate = Candidate(
                    "periodic",
                    f"period={period},pattern={pattern:0{period}b},len={length}",
                    value,
                    length,
                )
                by_key.setdefault(candidate.key, candidate)
    return list(by_key.values())


def onebit_family() -> list[Candidate]:
    lengths = (1, 63, 64, 65, 128, 192, 256, 512)
    by_key: dict[tuple[int, int], Candidate] = {}
    for length in lengths:
        full = (1 << length) - 1
        for base_name, base in (("zero", 0), ("one", full)):
            candidate = Candidate(
                "onebit", f"base={base_name},len={length},flip=-1", base, length
            )
            by_key.setdefault(candidate.key, candidate)
            for position in range(length):
                value = base ^ (1 << position)
                candidate = Candidate(
                    "onebit",
                    f"base={base_name},len={length},flip={position}",
                    value,
                    length,
                )
                by_key.setdefault(candidate.key, candidate)
    return list(by_key.values())


def lowweight_family() -> list[Candidate]:
    by_key: dict[tuple[int, int], Candidate] = {}

    def add(label: str, positions: tuple[int, ...], length: int) -> None:
        value = sum(1 << position for position in positions)
        candidate = Candidate("lowweight", f"len={length},positions={positions}", value, length)
        by_key.setdefault(candidate.key, candidate)

    # Exhaustive weights 1 and 2 for 16- and 32-bit messages.
    for length in (16, 32):
        for first in range(length):
            add("", (first,), length)
            for second in range(first + 1, length):
                add("", (first, second), length)

    # For larger lengths, enumerate all single one-bits and a fixed low-position
    # slice of pairs.  This is a declared sample, not a claim of exhaustive
    # coverage of all low-weight messages at those lengths.
    for length in (64, 128, 192, 256):
        for first in range(length):
            add("", (first,), length)
        for first in range(min(16, length)):
            for second in range(first + 1, min(32, length)):
                add("", (first, second), length)
    return list(by_key.values())


FAMILIES = {
    "constant": constant_family,
    "periodic": periodic_family,
    "onebit": onebit_family,
    "lowweight": lowweight_family,
}


def _hash_one(task: tuple[int, Candidate]) -> dict[str, object]:
    instance, candidate = task
    result, _ = AXIS(instance, upfull_order="sequential")._hash(
        candidate.message_int, candidate.message_len_bits
    )
    return {
        **asdict(candidate),
        "instance": instance,
        "digest_hex": result.digest_hex_low_bit_first,
        "digest_int_hex": hex(result.digest_int),
        "padded_len_bits": result.padded_len_bits,
        "message_beats": result.message_beats,
    }


def analyze(records: list[dict[str, object]], candidates: int) -> dict[str, object]:
    by_digest: dict[str, list[dict[str, object]]] = {}
    by_message_end: dict[str, list[dict[str, object]]] = {}
    for record in records:
        by_digest.setdefault(str(record["digest_hex"]), []).append(record)
        by_message_end.setdefault(str(record["digest_int_hex"]), []).append(record)
    collisions = [group for group in by_digest.values() if len(group) > 1]

    # Prefix statistics are descriptive only.  A collision in a short prefix has
    # the usual birthday expectation and is not an AXIS defect.
    prefix_max = 0
    for width_bits in (8, 16, 24, 32, 40, 48, 64):
        groups: dict[str, int] = {}
        bytes_wide = width_bits // 8
        for record in records:
            prefix = str(record["digest_hex"])[: 2 * bytes_wide]
            groups[prefix] = groups.get(prefix, 0) + 1
        if max(groups.values(), default=0) > 1:
            prefix_max = width_bits

    return {
        "candidates_hashed": candidates,
        "distinct_digests": len(by_digest),
        "exact_digest_collisions": collisions,
        "exact_collision_count": len(collisions),
        "largest_equal_prefix_bits": prefix_max,
        "prefix_note": (
            "prefix coincidences are descriptive; only equal full digests are exact "
            "collision witnesses"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--families",
        nargs="+",
        choices=sorted(FAMILIES),
        default=sorted(FAMILIES),
    )
    parser.add_argument("--instances", nargs="+", type=int, choices=(512, 768, 1024), default=(512, 768, 1024))
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--record-all", action="store_true")
    args = parser.parse_args()

    all_candidates: list[Candidate] = []
    seen: set[tuple[int, int]] = set()
    for family in args.families:
        generated = FAMILIES[family]()
        for candidate in generated:
            key = (candidate.message_len_bits, candidate.message_int)
            if key not in seen:
                seen.add(key)
                all_candidates.append(candidate)

    tasks = [(instance, candidate) for instance in args.instances for candidate in all_candidates]
    with multiprocessing.Pool(processes=args.jobs) as pool:
        records = list(pool.imap_unordered(_hash_one, tasks, chunksize=8))

    records.sort(key=lambda r: (int(r["instance"]), str(r["family"]), str(r["label"])))
    by_instance = {
        instance: analyze(
            [record for record in records if int(record["instance"]) == instance],
            len(all_candidates),
        )
        for instance in args.instances
    }
    metadata = {
        "schema": "axis-structured-search-v1",
        "python": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "families": args.families,
        "instances": args.instances,
        "candidate_universe": {
            family: len(FAMILIES[family]()) for family in args.families
        },
        "deduplicated_candidates": len(all_candidates),
        "upfull_order": "sequential",
        "conformance_status": "unresolved: no digest KAT in allowlisted PDF",
        "reproduce": " ".join(sys.argv),
        "result": by_instance,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        handle.write(json.dumps({"type": "metadata", **metadata}, sort_keys=True) + "\n")
        if args.record_all:
            for record in records:
                handle.write(json.dumps({"type": "hash", **record}, sort_keys=True) + "\n")
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    metadata["output_sha256"] = digest
    metadata["output"] = str(args.output.resolve())
    print(json.dumps(metadata, indent=2, sort_keys=True))
    return 0 if all(item["exact_collision_count"] == 0 for item in by_instance.values()) else 2


if __name__ == "__main__":
    raise SystemExit(main())
