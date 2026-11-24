#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
ZIP = ROOT / "source" / "Facto-DSA.zip"
SUBMISSION = ROOT / "submission"
IMPL = SUBMISSION / "Implementations and Test_Vectors" / "Implementations"
HERE = Path(__file__).resolve().parent
BUILDS = HERE / "builds"
FIXED = HERE / "fixed_inputs"
RESULTS = HERE / "runs"

FAMILIES = {
    "Reference": {
        "dir": "Reference_Implementation",
        "flags": ["-std=c99", "-O2", "-Wall", "-Wextra", "-Wpedantic"],
        "so_target": "ref",
    },
    "Optimized": {
        "dir": "Optimized_Implementation",
        "flags": [
            "-std=c99", "-O3", "-flto", "-fomit-frame-pointer", "-Wpedantic",
            "-Wall", "-Wextra", "-DFACTO_SIMD_AVX2=1", "-march=x86-64",
            "-mavx2", "-mtune=native",
        ],
        "so_target": "opti",
    },
    "Resource": {
        "dir": "Resource_Implementation",
        "flags": [
            "-std=c99", "-Os", "-flto", "-fomit-frame-pointer", "-Wpedantic",
            "-Wall", "-Wextra", "-DFACTO_SIMD_AVX2=1", "-march=x86-64",
            "-mavx2",
        ],
        "so_target": "res",
    },
}
INSTANCES = ["Facto-DSA-128", "Facto-DSA-256", "Facto-DSA-512"]
SOURCE_FILES = [
    "SIG_AlgorithmInstance.c", "SIG_AlgorithmInstance.h", "auxfunc.c",
    "auxfunc.h", "drng.c", "drng.h", "KAT_SIG.c", "Makefile", "README.txt",
]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd, cwd, log_path, env=None, check=True):
    proc = subprocess.run(
        [str(x) for x in cmd], cwd=cwd, env=env, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True,
    )
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(
        f"$ (cd {cwd} && {' '.join(str(x) for x in cmd)})\n"
        f"{proc.stdout}\nexit_code={proc.returncode}\n",
        encoding="utf-8",
    )
    if check and proc.returncode != 0:
        raise RuntimeError(f"command failed; see {log_path}")
    return proc.returncode, proc.stdout


def exact_label_suffix(instance):
    return "FDSA-H-" + instance.rsplit("-", 1)[1]


def prepare_copy(family, instance, variant):
    src = IMPL / FAMILIES[family]["dir"] / instance
    dst = BUILDS / family / instance / variant
    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(parents=True)
    for name in SOURCE_FILES:
        shutil.copy2(src / name, dst / name)
    shutil.copy2(HERE / "probe.c", dst / "probe.c")
    if variant == "spec":
        p = dst / "SIG_AlgorithmInstance.c"
        text = p.read_text(encoding="utf-8")
        old = f'const unsigned char label[] = "{exact_label_suffix(instance)}";'
        new = 'const unsigned char label[] = "FDSA-H";'
        count = text.count(old)
        if count != 1:
            raise RuntimeError(f"{p}: expected one label assignment, got {count}")
        p.write_text(text.replace(old, new), encoding="utf-8")
        if p.read_text(encoding="utf-8").count(new) != 1:
            raise RuntimeError(f"{p}: replacement assertion failed")
    return src, dst


def compile_variant(family, instance, variant, dst):
    flags = FAMILIES[family]["flags"]
    env = os.environ.copy()
    env.update({
        "LC_ALL": "C",
        "SOURCE_DATE_EPOCH": "1782432000",
    })
    compile_cmd = [
        "gcc", *flags, "-o", "probe", "probe.c", "SIG_AlgorithmInstance.c",
        "auxfunc.c", "drng.c",
    ]
    compile_rc, _ = run(
        ["flock", "/tmp/factodsa-audit-lock", *compile_cmd],
        dst, RESULTS / family / instance / variant / "compile.log", env=env,
    )
    if compile_rc != 0:
        raise RuntimeError(f"compile failed for {family}/{instance}/{variant}")
    # Independently exercise the submitted Makefile as an additional build control.
    make_rc, make_out = run(
        ["make", "-B", "kat_sig"], dst,
        RESULTS / family / instance / variant / "make.log", env=env,
        check=False,
    )
    if make_rc != 0:
        raise RuntimeError(f"submitted Makefile failed for {family}/{instance}/{variant}")
    return compile_cmd, make_out


def invoke(dst, args, log_rel):
    return run([dst / "probe", *args], dst, RESULTS / log_rel, check=False)


def logical_rc(process_rc):
    return process_rc - 256 if process_rc >= 128 else process_rc


def main():
    HERE.mkdir(parents=True, exist_ok=True)
    if BUILDS.exists():
        shutil.rmtree(BUILDS)
    if RESULTS.exists():
        shutil.rmtree(RESULTS)
    FIXED.mkdir(parents=True, exist_ok=True)

    seed = b"seed" * 16
    msg = bytes((0x30 + (i & 0x3f)) for i in range(56))
    (FIXED / "seed.bin").write_bytes(seed)
    (FIXED / "message.bin").write_bytes(msg)

    report = {
        "schema": "factodsa-label-interoperability-audit/v1",
        "environment": {
            "python": sys.version,
            "gcc": subprocess.run(
                ["gcc", "--version"], capture_output=True, text=True
            ).stdout.splitlines()[0],
            "make": subprocess.run(
                ["make", "--version"], capture_output=True, text=True
            ).stdout.splitlines()[0],
            "platform": os.uname()._asdict() if hasattr(os.uname(), "_asdict") else list(os.uname()),
            "source_date_epoch": 1782432000,
            "seed_sha256": hashlib.sha256(seed).hexdigest(),
            "message_sha256": hashlib.sha256(msg).hexdigest(),
        },
        "targets": [],
    }
    for family in FAMILIES:
        for instance in INSTANCES:
            print(f"[audit] {family}/{instance}", flush=True)
            sub_src, sub_dir = prepare_copy(family, instance, "submitted")
            spec_src, spec_dir = prepare_copy(family, instance, "spec")
            compile_cmd, _ = compile_variant(family, instance, "submitted", sub_dir)
            compile_variant(family, instance, "spec", spec_dir)

            # Prove the only source difference is the exact one-line label replacement.
            diff_cmd = [
                "diff", "-u",
                str(sub_dir / "SIG_AlgorithmInstance.c"),
                str(spec_dir / "SIG_AlgorithmInstance.c"),
            ]
            diff_rc, diff_out = run(
                diff_cmd, HERE,
                RESULTS / family / instance / "label_build_source.diff",
                check=False,
            )
            if diff_rc != 1:
                raise RuntimeError("label comparison diff was not exactly nonempty")
            changed = [
                ln[1:] for ln in diff_out.splitlines()
                if ln.startswith("+") and not ln.startswith("+++")
            ]
            removed = [
                ln[1:] for ln in diff_out.splitlines()
                if ln.startswith("-") and not ln.startswith("---")
            ]
            if len(changed) != 1 or len(removed) != 1:
                raise RuntimeError("source difference exceeded one added/removed line")
            if "FDSA-H" not in changed[0] or exact_label_suffix(instance) not in removed[0]:
                raise RuntimeError("source difference was not the expected label")

            key_dir = RESULTS / family / instance / "material"
            key_dir.mkdir(parents=True, exist_ok=True)
            pk, sk = key_dir / "public_key.bin", key_dir / "secret_key.bin"
            sub_pk, sub_sk = key_dir / "submitted_public_key.bin", key_dir / "submitted_secret_key.bin"
            spec_pk, spec_sk = key_dir / "spec_public_key.bin", key_dir / "spec_secret_key.bin"
            sub_sig = key_dir / "submitted_signature.bin"
            spec_sig = key_dir / "spec_signature.bin"

            rck, _ = invoke(
                sub_dir, ["keygen", HERE / "fixed_inputs" / "seed.bin", pk, sk],
                f"{family}/{instance}/submitted/keygen.log",
            )
            rck = logical_rc(rck)
            if rck != 0:
                raise RuntimeError("submitted keygen failed")
            rck, _ = invoke(
                spec_dir, ["keygen", HERE / "fixed_inputs" / "seed.bin", spec_pk, spec_sk],
                f"{family}/{instance}/spec/keygen.log",
            )
            rck = logical_rc(rck)
            if rck != 0:
                raise RuntimeError("spec-label keygen failed")
            if sha256(pk) != sha256(spec_pk) or sha256(sk) != sha256(spec_sk):
                raise RuntimeError("label-only change unexpectedly affected deterministic keygen")

            for variant, d, sig in [
                ("submitted", sub_dir, sub_sig), ("spec", spec_dir, spec_sig)
            ]:
                rc, _ = invoke(
                    d, ["sign", HERE / "fixed_inputs" / "seed.bin", pk, sk,
                        HERE / "fixed_inputs" / "message.bin", sig],
                    f"{family}/{instance}/{variant}/sign.log",
                )
                rc = logical_rc(rc)
                if rc != 0:
                    raise RuntimeError(f"{variant} signing failed")

            matrix = {}
            for verifier, d in [("submitted", sub_dir), ("spec", spec_dir)]:
                for signer, sig in [("submitted", sub_sig), ("spec", spec_sig)]:
                    rc, out = invoke(
                        d, ["verify", pk, HERE / "fixed_inputs" / "message.bin", sig],
                        f"{family}/{instance}/{verifier}_verifies_{signer}.log",
                    )
                    matrix[f"{verifier}_verifies_{signer}"] = logical_rc(rc)

            # Negative controls: a changed signature and a malformed short signature.
            bad = key_dir / "submitted_signature_bitflip.bin"
            b = bytearray(sub_sig.read_bytes())
            b[0] ^= 0x01
            bad.write_bytes(bytes(b))
            short = key_dir / "submitted_signature_truncated.bin"
            short.write_bytes(sub_sig.read_bytes()[:-1])
            short_matrix = {}
            for verifier, d in [("submitted", sub_dir), ("spec", spec_dir)]:
                rc, _ = invoke(
                    d, ["verify", pk, HERE / "fixed_inputs" / "message.bin", bad],
                    f"{family}/{instance}/{verifier}_rejects_bitflip.log",
                )
                short_matrix[f"{verifier}_rejects_bitflip"] = logical_rc(rc)
                rc, _ = invoke(
                    d, ["verify", pk, HERE / "fixed_inputs" / "message.bin", short],
                    f"{family}/{instance}/{verifier}_rejects_truncated.log",
                )
                short_matrix[f"{verifier}_rejects_truncated"] = logical_rc(rc)

            expected = {
                "submitted_verifies_submitted": 0,
                "spec_verifies_spec": 0,
                "submitted_verifies_spec": -1,
                "spec_verifies_submitted": -1,
            }
            expected_short = {
                "submitted_rejects_bitflip": -1,
                "spec_rejects_bitflip": -1,
                "submitted_rejects_truncated": -2,
                "spec_rejects_truncated": -2,
            }
            if matrix != expected:
                raise RuntimeError(f"{family}/{instance}: unexpected cross-verification matrix {matrix}")
            if short_matrix != expected_short:
                raise RuntimeError(f"{family}/{instance}: unexpected malformed matrix {short_matrix}")

            source_c = sub_dir / "SIG_AlgorithmInstance.c"
            spec_c = spec_dir / "SIG_AlgorithmInstance.c"
            line = next(
                (i, ln.strip()) for i, ln in enumerate(source_c.read_text().splitlines(), 1)
                if exact_label_suffix(instance) in ln
            )
            target = {
                "family": family,
                "instance": instance,
                "source_member": str(sub_src.relative_to(SUBMISSION) / "SIG_AlgorithmInstance.c"),
                "source_line": line[0],
                "submitted_label_assignment": line[1],
                "spec_label_assignment": 'const unsigned char label[] = "FDSA-H";',
                "source_diff": {
                    "removed_lines": removed,
                    "added_lines": changed,
                    "changed_added_count": len(changed),
                    "changed_removed_count": len(removed),
                },
                "compile_command": compile_cmd,
                "source_sha256": sha256(source_c),
                "spec_source_sha256": sha256(spec_c),
                "submitted_probe_sha256": sha256(sub_dir / "probe"),
                "spec_probe_sha256": sha256(spec_dir / "probe"),
                "pk_sha256": sha256(pk),
                "sk_sha256": sha256(sk),
                "message_sha256": sha256(HERE / "fixed_inputs" / "message.bin"),
                "submitted_signature_sha256": sha256(sub_sig),
                "spec_signature_sha256": sha256(spec_sig),
                "verification_matrix": matrix,
                "negative_controls": short_matrix,
                "executed": True,
            }
            report["targets"].append(target)
            with open(HERE / "results.partial.json", "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
                f.write("\n")

    report["summary"] = {
        "target_count": len(report["targets"]),
        "all_targets_executed": len(report["targets"]) == 9,
        "families": sorted({t["family"] for t in report["targets"]}),
        "instances": sorted({t["instance"] for t in report["targets"]}),
        "all_self_accept": all(
            t["verification_matrix"]["submitted_verifies_submitted"] == 0 and
            t["verification_matrix"]["spec_verifies_spec"] == 0
            for t in report["targets"]
        ),
        "all_cross_reject": all(
            t["verification_matrix"]["submitted_verifies_spec"] == -1 and
            t["verification_matrix"]["spec_verifies_submitted"] == -1
            for t in report["targets"]
        ),
        "all_negative_controls_pass": all(
            all(v in (-1, -2) for v in t["negative_controls"].values())
            for t in report["targets"]
        ),
    }
    out = HERE / "results.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report["summary"], indent=2))


if __name__ == "__main__":
    main()
