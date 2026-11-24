#!/usr/bin/env python3
import hashlib
import json
import pathlib
import sys


def read_tsv(path):
    rows = []
    with path.open(encoding="utf-8") as f:
        header = f.readline().rstrip("\n").split("\t")
        for line in f:
            values = line.rstrip("\n").split("\t")
            if values:
                rows.append(dict(zip(header, values)))
    return rows


def main(root):
    root = pathlib.Path(root)
    report = {"schema": "ngcc.bike-mlthre.decoder-mutations/v1", "widths": {}}
    failures = []

    for width in (128, 256, 512):
        by_impl = {}
        for impl in ("reference", "optimized"):
            path = root / f"{impl}-{width}" / "mutations.tsv"
            if not path.exists():
                failures.append(f"missing {path}")
                continue
            rows = read_tsv(path)
            by_impl[impl] = rows
            baseline = next((r for r in rows if r["probe"] == "baseline"), None)
            if baseline is None:
                failures.append(f"{impl}-{width}: no baseline")
                continue
            if baseline["decaps_rc"] != "0" or baseline["equals_expected"] != "1":
                failures.append(f"{impl}-{width}: baseline control failed")
            negative = next(
                (r for r in rows if r["probe"] in ("c0_mid_bit", "c0_first_bit")),
                None,
            )
            if negative is None or negative["equals_expected"] != "0":
                failures.append(f"{impl}-{width}: c0 mutation negative control failed")

        if len(by_impl) == 2:
            ref = {r["probe"]: r for r in by_impl["reference"]}
            opt = {r["probe"]: r for r in by_impl["optimized"]}
            common = sorted(ref.keys() & opt.keys())
            mismatches = [
                name for name in common
                if (ref[name]["decaps_rc"], ref[name]["ss_sha256"])
                != (opt[name]["decaps_rc"], opt[name]["ss_sha256"])
            ]
            if mismatches:
                failures.extend(
                    f"{width}: reference/optimized mismatch at {name}"
                    for name in mismatches
                )
            report["widths"][str(width)] = {
                "common_probes": common,
                "reference_probe_count": len(ref),
                "optimized_probe_count": len(opt),
                "all_common_outputs_equal": not mismatches,
                "mutants_retaining_expected_ss": sorted(
                    r["probe"]
                    for rows in by_impl.values()
                    for r in rows
                    if r["probe"] != "baseline" and r["equals_expected"] == "1"
                ),
            }

    report["status"] = "PASS" if not failures else "FAIL"
    report["failures"] = failures
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    (root / "verdict.json").write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
