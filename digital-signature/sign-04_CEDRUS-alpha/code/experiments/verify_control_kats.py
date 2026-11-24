#!/usr/bin/env python3
"""Check that the four-byte-chain control differs only in generated signatures."""

from pathlib import Path


def parse_kat(path: Path):
    entries = []
    current = {}
    for line in path.read_text().splitlines():
        if " = " not in line:
            continue
        key, value = line.split(" = ", 1)
        if key == "Count" and current:
            entries.append(current)
            current = {}
        current[key] = value
    if current:
        entries.append(current)
    return entries


submitted = parse_kat(Path("KAT_160f_archive.txt"))
control = parse_kat(
    Path("control_chain32_160f/output/KAT_SIG_CEDRUSALPHA-160f.txt")
)

assert len(submitted) == len(control) == 10
for index, (left, right) in enumerate(zip(submitted, control)):
    for field in ("Seed", "PK", "SK", "M"):
        assert left[field] == right[field], (index, field)

    left_signature = bytes.fromhex(left["Sn"])
    right_signature = bytes.fromhex(right["Sn"])
    differing = sum(a != b for a, b in zip(left_signature, right_signature))
    assert differing > 0, index
    print(
        f"entry={index} seed=equal pk=equal sk=equal message=equal "
        f"signature_differing_bytes={differing}"
    )

print("summary entries=10 shared_inputs=yes all_signatures_differ=yes")
