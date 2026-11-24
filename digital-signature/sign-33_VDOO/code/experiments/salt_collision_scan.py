#!/usr/bin/env python3
"""Measure cross-message salt reuse in the unmodified VDOO-128 signing CLI."""

import hashlib
import json
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "experiments" / "salt_collision_scan"
SK = ROOT / "experiments" / "vdoo128_matrix" / "sk.txt"


def main() -> None:
    OUT.mkdir(exist_ok=True)
    rows = []
    for i in range(100):
        message = OUT / f"m{i:03d}.bin"
        message.write_bytes(f"cross-message-salt-test-{i:03d}\n".encode())
        completed = subprocess.run(
            [str(ROOT / "builds" / "ref" / "vdoo-sign"), str(SK), str(message)],
            capture_output=True,
            text=True,
        )
        match = re.search(r"^VDOO-128 signature = ([0-9a-f]+)\s*$", completed.stdout, re.MULTILINE)
        signature = bytes.fromhex(match.group(1)) if match else b""
        rows.append({
            "i": i,
            "exit": completed.returncode,
            "signature_sha256": hashlib.sha256(signature).hexdigest() if signature else None,
            "salt_hex": signature[69:].hex() if signature else None,
        })

    groups: dict[str, list[int]] = {}
    for row in rows:
        groups.setdefault(row["salt_hex"], []).append(row["i"])
    report = {
        "messages": len(rows),
        "distinct_salts": len(groups),
        "salt_count_groups": groups,
        "rows": rows,
    }
    (OUT / "scan.json").write_text(json.dumps(report, indent=2) + "\n")
    print("messages", report["messages"], "distinct_salts", report["distinct_salts"])
    print("maximum_multiplicity", max(map(len, groups.values())))


if __name__ == "__main__":
    main()
