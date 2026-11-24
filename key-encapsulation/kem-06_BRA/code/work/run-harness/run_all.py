#!/usr/bin/env python3
"""Build and exercise the supplied BRA reference and optimized harnesses.

All commands execute against the copied input tree below this harness.  The
script never writes to the shared original-material directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


HERE = Path(__file__).resolve().parent
INPUT = HERE / "input"
IMPLEMENTATIONS = INPUT / "Implementations"
VECTORS = INPUT / "Test_Vectors"
LOGS = HERE / "logs"
RESULTS = HERE / "results"
ARTIFACTS = HERE / "artifacts"
CONTROL = HERE / "control"

IMPLEMENTATION_KINDS = ("Reference_Implementation", "Optimized_Implementation")
PARAMETER_SETS = ("BRA-128", "BRA-256", "BRA-512")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in {"bin", "output"} for part in relative.parts):
            continue
        files.append(path)
    return sorted(files, key=lambda p: p.relative_to(root).as_posix())


def tree_manifest(root: Path) -> list[dict[str, str]]:
    return [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": sha256_file(path),
            "bytes": str(path.stat().st_size),
        }
        for path in source_files(root)
    ]


def run_command(
    command: list[str],
    cwd: Path,
    log_prefix: Path,
    timeout: int,
) -> dict[str, object]:
    started_at = utc_now()
    started = time.monotonic_ns()
    timed_out = False
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            env=os.environ.copy(),
        )
        returncode = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        returncode = None
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        stderr += f"\nTIMEOUT after {timeout}s\n"
    elapsed_ms = (time.monotonic_ns() - started) // 1_000_000
    finished_at = utc_now()
    stdout_path = log_prefix.with_suffix(log_prefix.suffix + ".stdout.txt")
    stderr_path = log_prefix.with_suffix(log_prefix.suffix + ".stderr.txt")
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    record: dict[str, object] = {
        "command": command,
        "cwd": str(cwd),
        "started_at_utc": started_at,
        "finished_at_utc": finished_at,
        "elapsed_ms": elapsed_ms,
        "timeout_seconds": timeout,
        "timed_out": timed_out,
        "returncode": returncode,
        "stdout_path": str(stdout_path.relative_to(HERE)),
        "stderr_path": str(stderr_path.relative_to(HERE)),
        "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr.encode()).hexdigest(),
    }
    return record


def compare_files(observed: Path, expected: Path) -> dict[str, object]:
    observed_bytes = observed.read_bytes()
    expected_bytes = expected.read_bytes()
    mismatch_offset = None
    limit = min(len(observed_bytes), len(expected_bytes))
    for index in range(limit):
        if observed_bytes[index] != expected_bytes[index]:
            mismatch_offset = index
            break
    if mismatch_offset is None and len(observed_bytes) != len(expected_bytes):
        mismatch_offset = limit
    return {
        "equal": observed_bytes == expected_bytes,
        "observed_bytes": len(observed_bytes),
        "expected_bytes": len(expected_bytes),
        "observed_sha256": hashlib.sha256(observed_bytes).hexdigest(),
        "expected_sha256": hashlib.sha256(expected_bytes).hexdigest(),
        "first_difference_offset": mismatch_offset,
    }


def corrupt_first_shared_secret(data: bytes) -> tuple[bytes, int]:
    marker = b"\nSS = "
    marker_offset = data.find(marker)
    if marker_offset < 0:
        raise ValueError("no SS digest line found")
    char_offset = marker_offset + len(marker)
    if char_offset >= len(data):
        raise ValueError("SS digest line has no payload")
    replacement = b"0" if data[char_offset : char_offset + 1] != b"0" else b"1"
    return data[:char_offset] + replacement + data[char_offset + 1 :], char_offset


def command_output(command: list[str]) -> dict[str, object]:
    try:
        completed = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        return {
            "command": command,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {
            "command": command,
            "returncode": None,
            "stdout": "",
            "stderr": repr(exc),
        }


def collect_environment() -> dict[str, object]:
    commands = {
        "uname": ["uname", "-a"],
        "os_release": ["bash", "-lc", "cat /etc/os-release"],
        "gcc_version": ["gcc", "--version"],
        "gcc_path": ["bash", "-lc", "command -v gcc"],
        "make_version": ["make", "--version"],
        "ld_version": ["ld", "--version"],
        "python_version": [sys.executable, "--version"],
        "cpu_model": ["bash", "-lc", "lscpu | grep -E '^(Architecture|Model name|CPU\\(s\\)):'"],
        "logical_cpus": ["nproc"],
    }
    selected_environment = {
        key: os.environ.get(key)
        for key in (
            "PATH",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "SOURCE_DATE_EPOCH",
            "CFLAGS",
            "LDFLAGS",
            "MAKEFLAGS",
        )
    }
    return {
        "collected_at_utc": utc_now(),
        "hostname": platform.node(),
        "selected_environment": selected_environment,
        "commands": {
            name: command_output(command) for name, command in commands.items()
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--sets",
        nargs="+",
        choices=PARAMETER_SETS,
        default=list(PARAMETER_SETS),
    )
    parser.add_argument(
        "--implementations",
        nargs="+",
        choices=IMPLEMENTATION_KINDS,
        default=list(IMPLEMENTATION_KINDS),
    )
    parser.add_argument("--build-timeout", type=int, default=900)
    parser.add_argument("--run-timeout", type=int, default=900)
    args = parser.parse_args()

    for directory in (LOGS, RESULTS, ARTIFACTS, CONTROL):
        directory.mkdir(parents=True, exist_ok=True)

    environment = collect_environment()
    (RESULTS / "environment.json").write_text(
        json.dumps(environment, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    initial_manifest = tree_manifest(IMPLEMENTATIONS)
    (RESULTS / "source_manifest_before.json").write_text(
        json.dumps(initial_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    vector_manifest = tree_manifest(VECTORS)
    (RESULTS / "test_vector_manifest.json").write_text(
        json.dumps(vector_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    records: list[dict[str, object]] = []
    all_commands_succeeded = True
    for implementation in args.implementations:
        for parameter_set in args.sets:
            variant_key = f"{implementation}__{parameter_set}"
            source_dir = IMPLEMENTATIONS / implementation / parameter_set
            official = VECTORS / f"KAT_KEM_{parameter_set}.txt"
            output = source_dir / "output" / f"KAT_KEM_{parameter_set}.txt"
            binary_dir = ARTIFACTS / implementation / parameter_set
            binary_dir.mkdir(parents=True, exist_ok=True)

            record: dict[str, object] = {
                "implementation": implementation,
                "parameter_set": parameter_set,
                "source_directory": str(source_dir),
                "official_vector": str(official),
                "commands": [],
            }

            demo_build = run_command(
                ["make", f"{parameter_set}"],
                source_dir,
                LOGS / f"{variant_key}.demo-build",
                args.build_timeout,
            )
            demo_run = run_command(
                [str(source_dir / "bin" / parameter_set)],
                source_dir,
                LOGS / f"{variant_key}.demo-run",
                args.run_timeout,
            )
            kat_build = run_command(
                ["make", f"{parameter_set}-kat"],
                source_dir,
                LOGS / f"{variant_key}.kat-build",
                args.build_timeout,
            )

            if output.exists():
                output.unlink()
            kat_run = run_command(
                [str(source_dir / "bin" / f"{parameter_set}-kat")],
                source_dir,
                LOGS / f"{variant_key}.kat-run",
                args.run_timeout,
            )
            record["commands"].extend([demo_build, demo_run, kat_build, kat_run])

            demo_binary = source_dir / "bin" / parameter_set
            kat_binary = source_dir / "bin" / f"{parameter_set}-kat"
            if demo_binary.exists():
                shutil.copy2(demo_binary, binary_dir / demo_binary.name)
            if kat_binary.exists():
                shutil.copy2(kat_binary, binary_dir / kat_binary.name)

            if output.exists():
                retained_output = binary_dir / output.name
                shutil.copy2(output, retained_output)
                comparison = compare_files(output, official)
                record["kat_comparison"] = comparison
                record["retained_kat"] = str(retained_output)

                corrupted, changed_offset = corrupt_first_shared_secret(
                    official.read_bytes()
                )
                corrupted_path = (
                    CONTROL
                    / f"KAT_KEM_{parameter_set}.{implementation}.corrupt-first-SS.txt"
                )
                corrupted_path.write_bytes(corrupted)
                corruption_comparison = compare_files(output, corrupted_path)
                malformed_path = (
                    CONTROL
                    / f"KAT_KEM_{parameter_set}.{implementation}.truncated.txt"
                )
                malformed_path.write_bytes(official.read_bytes()[: max(1, len(official.read_bytes()) // 2)])
                malformed_comparison = compare_files(output, malformed_path)
                record["negative_controls"] = {
                    "corrupt_first_ss_digest": {
                        "changed_byte_offset": changed_offset,
                        "copy_path": str(corrupted_path.relative_to(HERE)),
                        "comparison": corruption_comparison,
                        "expected_control_result": "not_equal",
                    },
                    "truncated_expected_file": {
                        "copy_path": str(malformed_path.relative_to(HERE)),
                        "comparison": malformed_comparison,
                        "expected_control_result": "not_equal",
                    },
                }
            else:
                record["kat_comparison"] = None
                record["kat_output_missing"] = True

            demo_ok = (
                demo_build["returncode"] == 0
                and demo_run["returncode"] == 0
                and demo_run["stdout_path"]
                and "[PASS] Shared secrets match!" in demo_run["stdout_path"]
            )
            # stdout_path is relative; read the retained command log directly.
            demo_stdout = (
                HERE / str(demo_run["stdout_path"])
            ).read_text(encoding="utf-8")
            demo_ok = (
                demo_build["returncode"] == 0
                and demo_run["returncode"] == 0
                and "[PASS] Shared secrets match!" in demo_stdout
            )
            kat_ok = (
                kat_build["returncode"] == 0
                and kat_run["returncode"] == 0
                and record.get("kat_comparison") is not None
                and bool(record["kat_comparison"]["equal"])
            )
            negative_ok = False
            if "negative_controls" in record:
                negative_ok = (
                    not record["negative_controls"]["corrupt_first_ss_digest"][
                        "comparison"
                    ]["equal"]
                    and not record["negative_controls"]["truncated_expected_file"][
                        "comparison"
                    ]["equal"]
                )
            record["demo_internal_consistency_pass"] = demo_ok
            record["kat_exact_match_pass"] = kat_ok
            record["negative_control_pass"] = negative_ok
            record["interpretation_limit"] = (
                "Build, API behavior, and KAT equality only; no security claim."
            )
            all_commands_succeeded &= demo_ok and kat_ok and negative_ok
            records.append(record)
            (RESULTS / "results.partial.json").write_text(
                json.dumps(records, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

    final_manifest = tree_manifest(IMPLEMENTATIONS)
    source_unchanged = initial_manifest == final_manifest
    result = {
        "schema": "bra-local-harness/v1",
        "generated_at_utc": utc_now(),
        "input_root": str(INPUT),
        "source_tree_unchanged_by_harness": source_unchanged,
        "all_selected_variants_pass_build_and_kat": all_commands_succeeded,
        "scope_note": (
            "These are local functional/KAT checks. They do not establish "
            "cryptographic security, attack resistance, or correctness outside "
            "the supplied test corpus."
        ),
        "variants": records,
    }
    (RESULTS / "results.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "variants": len(records),
                "source_tree_unchanged_by_harness": source_unchanged,
                "all_selected_variants_pass_build_and_kat": all_commands_succeeded,
                "results": str(RESULTS / "results.json"),
            },
            sort_keys=True,
        )
    )
    return 0 if source_unchanged else 1


if __name__ == "__main__":
    raise SystemExit(main())
