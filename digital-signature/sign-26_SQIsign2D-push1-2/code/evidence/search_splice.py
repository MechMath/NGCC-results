#!/usr/bin/env python3
"""Bounded test of a profile-splice explanation for the Level-3 KAT hash.

The search uses only the two KATs regenerated from the fixed implementation.
It checks possible mixtures of their deterministic records against the manifest.
Failure is not evidence that a splice did not occur: the submitted file is absent.
"""

from __future__ import annotations

import hashlib
import itertools
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent
TARGET = "e720265768c4e14868f1a660b631c77a763c3474173c09997f81125afa392018"


def records(path: Path) -> list[list[str]]:
    groups: list[list[str]] = []
    current: list[str] = []
    for line in path.read_text().splitlines():
        if line.startswith("Count = ") and current:
            groups.append(current)
            current = []
        if line:
            current.append(line.rstrip())
    if current:
        groups.append(current)
    return groups


def digest(lines: list[str]) -> str:
    return hashlib.sha256(("\n".join(lines) + "\n").encode()).hexdigest()


def renumber(record: list[str], index: int) -> list[str]:
    return [f"Count = {index}" if line.startswith("Count = ") else line for line in record]


def search(l2: list[list[str]], l3: list[list[str]], total: int) -> dict[str, object]:
    n2 = total - 2
    checked = 0
    for l2_indices in itertools.combinations(range(len(l2)), n2):
        for l3_indices in itertools.combinations(range(len(l3)), 2):
            records_a = [l2[i] for i in l2_indices]
            records_b = [l3[i] for i in l3_indices]
            for positions in itertools.combinations(range(total), 2):
                for swapped in (False, True):
                    selected = list(records_a)
                    extra = list(reversed(records_b)) if swapped else records_b
                    for position, record in zip(positions, extra):
                        selected.insert(position, record)
                    flat = [line for record in selected for line in record]
                    checked += 1
                    if digest(flat) == TARGET:
                        return {"match": True, "total": total, "records": selected,
                                "checks": checked}
                    flat_renumbered = [
                        line
                        for index, record in enumerate(selected)
                        for line in renumber(record, index)
                    ]
                    checked += 1
                    if digest(flat_renumbered) == TARGET:
                        return {"match": True, "total": total,
                                "records": [renumber(r, i) for i, r in enumerate(selected)],
                                "checks": checked}
    return {"match": False, "total": total, "checks": checked}


def main() -> None:
    l2 = records(ROOT / "generated/lvl2-control.txt")
    l3 = records(ROOT / "generated/lvl3-run1.txt")
    print(f"l2_records={len(l2)} l3_records={len(l3)}")
    print(search(l2, l3, 12))
    print(search(l2, l3, 10))


if __name__ == "__main__":
    main()
