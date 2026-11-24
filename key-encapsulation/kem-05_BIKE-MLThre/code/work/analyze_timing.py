#!/usr/bin/env python3
import csv
from collections import defaultdict
from pathlib import Path

import numpy as np


ROOT = Path(__file__).resolve().parent / "multikey"


def median_times(path):
    values = defaultdict(list)
    prefixes = defaultdict(set)
    with path.open(newline="") as handle:
        for row in csv.DictReader(handle):
            case = int(row["sample"])
            values[case].append(int(row["nanoseconds"]))
            prefixes[case].add(row["ss_prefix"])
    for case, observed in prefixes.items():
        if len(observed) != 1:
            raise RuntimeError(f"non-deterministic prefix for {path} case {case}")
    return (
        np.array([np.median(values[i]) for i in sorted(values)]),
        {i: next(iter(prefixes[i])) for i in sorted(prefixes)},
    )


def rank_correlation(a, b):
    ra = np.argsort(np.argsort(a))
    rb = np.argsort(np.argsort(b))
    return float(np.corrcoef(ra, rb)[0, 1])


def main():
    all_reference = []
    all_noml = []
    all_optimized = []
    for key in range(4):
        paths = {
            name: ROOT / f"key{key}" / f"{name}_repeat.csv"
            for name in ("reference", "noml", "optimized")
        }
        measured = {name: median_times(path) for name, path in paths.items()}
        for name, (times, _) in measured.items():
            target = {
                "reference": all_reference,
                "noml": all_noml,
                "optimized": all_optimized,
            }[name]
            target.extend(times)

            first, _ = median_times(
                ROOT / f"key{key}" / f"{name}.csv"
            )
            print(
                f"key={key} decoder={name} "
                f"median_ms={np.median(times) / 1e6:.3f} "
                f"iqr_ms={np.quantile(times, 0.25) / 1e6:.3f},"
                f"{np.quantile(times, 0.75) / 1e6:.3f} "
                f"repeat_rank_rho={rank_correlation(first, times):+.3f}"
            )

        reference_prefixes = measured["reference"][1]
        for name in ("noml", "optimized"):
            mismatches = sum(
                reference_prefixes[i] != measured[name][1][i]
                for i in reference_prefixes
            )
            print(f"key={key} ss_prefix_mismatches_vs_{name}={mismatches}")

    for name, values in (
        ("reference", all_reference),
        ("noml", all_noml),
        ("optimized", all_optimized),
    ):
        values = np.asarray(values)
        print(
            f"aggregate decoder={name} median_ms={np.median(values) / 1e6:.3f} "
            f"iqr_ms={np.quantile(values, 0.25) / 1e6:.3f},"
            f"{np.quantile(values, 0.75) / 1e6:.3f} "
            f"cv={np.std(values) / np.mean(values):.4f}"
        )


if __name__ == "__main__":
    main()
