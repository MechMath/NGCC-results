#!/usr/bin/env python3
"""Reproduce the fixed-weight two-phase forgery estimate on Qing Luan tuples.

The submitted estimator implements the optimized two-phase formula.  The
published CROSS control (p,t,w)=(127,252,212) checks the implementation against
the independent paper value before Qing Luan's tuples are evaluated.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ESTIMATOR = (
    ROOT
    / "extracted"
    / "QingLuan"
    / "Implementations and Test_Vectors"
    / "Supporting_Documentation"
    / "rsdp_estimator.py"
)


def load_estimator():
    spec = importlib.util.spec_from_file_location("qingluan_estimator", ESTIMATOR)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {ESTIMATOR}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    estimator = load_estimator()
    forgery = estimator.Forgery(127)
    tuples = [
        ("published-control", 252, 212),
        ("QingLuan-128", 256, 212),
        ("QingLuan-256", 512, 424),
        ("QingLuan-384", 763, 631),
        ("QingLuan-512", 1018, 842),
    ]
    rows = []
    for name, t, w in tuples:
        bits = forgery.prop7_bits(t, w)
        rows.append(
            {
                "name": name,
                "p": 127,
                "q": 126,
                "t": t,
                "w": w,
                "two_phase_log2_attempts": bits,
            }
        )

    control = rows[0]["two_phase_log2_attempts"]
    assert abs(control - 120.46) < 0.01, control
    assert all(
        row["two_phase_log2_attempts"] >= int(row["name"].split("-")[-1])
        for row in rows[1:]
    )
    print(json.dumps({"rows": rows}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
