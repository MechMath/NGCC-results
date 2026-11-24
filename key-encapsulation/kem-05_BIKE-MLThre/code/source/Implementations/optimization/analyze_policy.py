#!/usr/bin/env python3
import hashlib
import json
import pathlib
import re
import statistics

ROOT = pathlib.Path(__file__).resolve().parent
BUILDS = ("ref", "opt")
CASES = tuple(f"{i:02d}" for i in range(4))
VARIANTS = ("valid", "c1_bit0", "c0_bit0", "c0_last", "c0_mask32")

THRESHOLD_RES = (
    re.compile(r"L7 ref threshold: base=(\d+) delta=(-?\d+) applied=(\d+)"),
    re.compile(r"ML threshold: base=(\d+) delta=(-?\d+) applied=(\d+)"),
)
ITERATION_RE = re.compile(r"(?:L7 reference iteration|Iteration): (\d+)")
WEIGHT_RE = re.compile(r"Weight of syndrome: (\d+)")
FINAL_RE = re.compile(r"Final syndrome weight: (\d+)")
FINAL_ERROR_RE = re.compile(r"Final error weight: (\d+)")
SUCCESS_RE = re.compile(r"KEM decoder success condition: (\d+)")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def trajectory(log_path):
    lines = log_path.read_text(errors="replace").splitlines()
    thresholds = []
    initial_weights = []
    final_weight = None
    final_error_weight = None
    decoder_success = None
    current_iteration = None
    seen_weight_for_iteration = set()
    for line in lines:
        match = re.search(r"Final syndrome weight: (\d+)", line)
        if match:
            final_weight = int(match.group(1))
        match = FINAL_ERROR_RE.search(line)
        if match:
            final_error_weight = int(match.group(1))
        match = SUCCESS_RE.search(line)
        if match:
            decoder_success = int(match.group(1))
        match = ITERATION_RE.search(line)
        if match:
            current_iteration = int(match.group(1))
        for pattern in THRESHOLD_RES:
            match = pattern.search(line)
            if match:
                thresholds.append(
                    {
                        "base": int(match.group(1)),
                        "delta": int(match.group(2)),
                        "applied": int(match.group(3)),
                    }
                )
        match = WEIGHT_RE.search(line)
        if match and current_iteration is not None:
            if current_iteration not in seen_weight_for_iteration:
                initial_weights.append(int(match.group(1)))
                seen_weight_for_iteration.add(current_iteration)
    return {
        "thresholds": thresholds,
        "iteration_input_syndrome_weights": initial_weights,
        "final_syndrome_weight": final_weight,
        "final_error_weight": final_error_weight,
        "decoder_success": decoder_success,
    }


def main():
    records = []
    for case in CASES:
        seed_ss = (ROOT / "corpus" / f"case_{case}.ss").read_bytes()
        for variant in VARIANTS:
            entry = {
                "case": f"case_{case}",
                "variant": variant,
                "input_sha256": {
                    "sk": sha256(ROOT / "corpus" / f"case_{case}.sk"),
                    "ct": sha256(
                        ROOT / "corpus" / f"case_{case}_{variant}.ct"
                    ),
                },
                "builds": {},
            }
            for build in BUILDS:
                stem = (
                    ROOT
                    / "outputs"
                    / build
                    / f"case_{case}_{variant}.repeat1"
                )
                output = pathlib.Path(f"{stem}.ss").read_bytes()
                entry["builds"][build] = {
                    "ss_sha256": hashlib.sha256(output).hexdigest(),
                    "ss_equals_encapsulation_reference": output == seed_ss,
                    "trajectory": trajectory(pathlib.Path(f"{stem}.log")),
                }
            entry["terminal_shared_secret_equal"] = (
                entry["builds"]["ref"]["ss_sha256"]
                == entry["builds"]["opt"]["ss_sha256"]
            )
            entry["threshold_delta_trajectory_equal"] = (
                entry["builds"]["ref"]["trajectory"]["thresholds"]
                == entry["builds"]["opt"]["trajectory"]["thresholds"]
            )
            entry["iteration_input_syndrome_equal"] = (
                entry["builds"]["ref"]["trajectory"][
                    "iteration_input_syndrome_weights"
                ]
                == entry["builds"]["opt"]["trajectory"][
                    "iteration_input_syndrome_weights"
                ]
            )
            entry["final_error_weight_equal"] = (
                entry["builds"]["ref"]["trajectory"]["final_error_weight"]
                == entry["builds"]["opt"]["trajectory"]["final_error_weight"]
            )
            entry["decoder_success_equal"] = (
                entry["builds"]["ref"]["trajectory"]["decoder_success"]
                == entry["builds"]["opt"]["trajectory"]["decoder_success"]
            )
            records.append(entry)

    repeat_records = []
    for build in BUILDS:
        for case in CASES:
            first = ROOT / "outputs" / build / f"case_{case}_valid.repeat1.ss"
            second = ROOT / "outputs" / build / f"case_{case}_valid.repeat2.ss"
            seed_ss = ROOT / "corpus" / f"case_{case}.ss"
            repeat_records.append(
                {
                    "build": build,
                    "case": f"case_{case}",
                    "repeat_equal": first.read_bytes() == second.read_bytes(),
                    "repeat_equals_encapsulation": (
                        first.read_bytes() == seed_ss.read_bytes()
                        and second.read_bytes() == seed_ss.read_bytes()
                    ),
                    "repeat1_sha256": sha256(first),
                    "repeat2_sha256": sha256(second),
                    "encapsulation_sha256": sha256(seed_ss),
                }
            )

    meta_rows = []
    for line in (ROOT / "run_meta.tsv").read_text().splitlines()[1:]:
        fields = line.split("\t")
        if len(fields) != 9:
            continue
        meta_rows.append(
            {
                "build": fields[0],
                "case": fields[1],
                "variant": fields[2],
                "repeat": int(fields[3]),
                "returncode": int(fields[4]),
                "wall_seconds": float(fields[5]),
            }
        )

    wall_by_build = {
        build: statistics.median(
            row["wall_seconds"] for row in meta_rows if row["build"] == build
        )
        for build in BUILDS
    }
    result = {
        "schema": "bike-mlthre-l7-policy-comparison/v1",
        "status": "finite empirical paired comparison; not a general equivalence proof",
        "profile": {
            "security_bits": 512,
            "r_bits": 150001,
            "d": 273,
            "t": 524,
            "max_iterations": 5,
            "dynamic_threshold": 1,
            "empirical_threshold": 0,
            "reference_decoder": 1,
            "optimized_decoder_selector": 0,
        },
        "sampling_frame": {
            "independent_keys": 4,
            "cases_per_key": 5,
            "paired_cases": 20,
            "valid_repetitions_per_build": 2,
            "generator": "NIST AES-256 CTR DRBG with four fixed entropy inputs",
            "mutation_categories": list(VARIANTS),
            "deterministic_seed_indices": [0, 1, 2, 3],
        },
        "totals": {
            "decapsulation_processes": len(meta_rows),
            "nonzero_process_exits": sum(
                row["returncode"] != 0 for row in meta_rows
            ),
            "paired_terminal_shared_secret_equal": sum(
                record["terminal_shared_secret_equal"] for record in records
            ),
            "paired_threshold_delta_trajectory_equal": sum(
                record["threshold_delta_trajectory_equal"] for record in records
            ),
            "paired_iteration_input_syndrome_equal": sum(
                record["iteration_input_syndrome_equal"] for record in records
            ),
            "paired_final_error_weight_equal": sum(
                record["final_error_weight_equal"] for record in records
            ),
            "paired_decoder_success_equal": sum(
                record["decoder_success_equal"] for record in records
            ),
            "decoder_success_by_variant": {
                variant: sum(
                    record["builds"]["ref"]["trajectory"]["decoder_success"]
                    == 1
                    for record in records
                    if record["variant"] == variant
                )
                for variant in VARIANTS
            },
            "same_build_repeat_equal": sum(
                record["repeat_equal"] for record in repeat_records
            ),
            "same_build_repeat_equals_encapsulation": sum(
                record["repeat_equals_encapsulation"]
                for record in repeat_records
            ),
            "median_wall_seconds_by_build": wall_by_build,
        },
        "cases": records,
        "repeat_controls": repeat_records,
        "interpretation_limits": [
            "The four fixed keys and twenty ciphertexts are a finite sample, not exhaustive parameter-set coverage.",
            "Equality of KEM shared secrets proves identical final KEM output for these exact inputs; it does not by itself expose decoder success before implicit rejection.",
            "Decoder success is the original constant-time comparison H(m') == (e0', e1') before implicit-rejection selection.",
            "Wall time is descriptive only; no speedup claim is made.",
            "The 512-bit profile is explicitly marked experimental in the original submission.",
        ],
    }
    (ROOT / "results.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps(result["totals"], indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
