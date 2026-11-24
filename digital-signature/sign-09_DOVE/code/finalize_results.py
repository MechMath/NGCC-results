#!/usr/bin/env python3
import hashlib
import json
import os
import platform
import subprocess
from pathlib import Path

work = Path("/home/mmat/mmat-preview/runs/ngcc-sign-09-ds01/run/slots/67c5eb5e760a43c9")
root = Path("/home/mmat/mmat-preview/runs/ngcc-sign-09-ds01/run/slots/b977949983924d87/refsrc/Digital_Signature-DOVE-x86-reference_implementation")
art = work / "envelope_artifacts"
logs = art / "logs"

def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()

variants = [
    "DOVE_classic_ref", "DOVE_pkc_skc_ref",
    "DOVE_classic_avx2", "DOVE_pkc_skc_avx2",
]
records = []
for variant in variants:
    impl = "Reference_Implementation" if variant.endswith("_ref") else "Optimized_Implementation"
    for profile in (128, 256, 512):
        tag = f"{variant}_{profile}"
        stdout = logs / f"{tag}.run.stdout"
        stderr = logs / f"{tag}.run.stderr"
        exitp = logs / f"{tag}.run.exit"
        rec = {
            "implementation": impl,
            "variant": variant,
            "profile": f"DOVE_{profile}",
            "buildable": False,
            "executed": False,
        }
        if stdout.exists() and stdout.stat().st_size:
            rec.update(json.loads(stdout.read_text()))
            rec["executed"] = True
        rec["buildable"] = (art / "bin" / tag).exists()
        rec["run_exit"] = int(exitp.read_text().strip()) if exitp.exists() else None
        rec["stdout_path"] = str(stdout)
        rec["stdout_sha256"] = sha(stdout) if stdout.exists() else None
        rec["stderr_path"] = str(stderr)
        rec["stderr_sha256"] = sha(stderr) if stderr.exists() else None
        rec["binary_path"] = str(art / "bin" / tag)
        rec["binary_sha256"] = sha(art / "bin" / tag) if (art / "bin" / tag).exists() else None
        records.append(rec)

source_files = {}
for variant in variants:
    impl = "Reference_Implementation" if variant.endswith("_ref") else "Optimized_Implementation"
    d = root / "API_PKC" / "Implementations" / impl / variant
    for name in ("SIG_AlgorithmInstance.c", "SIG_AlgorithmInstance.h", "Makefile", "uov/config.h"):
        p = d / name
        source_files[f"{variant}/{name}"] = {"path": str(p), "sha256": sha(p)}

compile_command = {}
sources_by_impl = {
    "Reference_Implementation": ["gf256.c", "matrix.c", "uov/blas_matrix_ref.c", "auxfunc.c", "drng.c", "SIG_AlgorithmInstance.c"],
    "Optimized_Implementation": ["gf256.c", "matrix.c", "uov/blas_matrix_avx2.c", "uov/blas_matrix_ref.c", "uov/gf16_tabs.c", "uov/gf256_tabs.c", "auxfunc.c", "drng.c", "SIG_AlgorithmInstance.c"],
}
for variant in variants:
    impl = "Reference_Implementation" if variant.endswith("_ref") else "Optimized_Implementation"
    d = root / "API_PKC" / "Implementations" / impl / variant
    for profile in (128, 256, 512):
        cmd = ["gcc", "-std=c99", "-O2", "-Wall", "-Wextra", "-Wno-unused-parameter",
               f"-DDOVE_PARAM_SET=DOVE{profile}"]
        if impl == "Optimized_Implementation":
            cmd.append("-mavx2")
        cmd += [f"-I{d}", f"-I{d/'uov'}", "-o", str(art/"bin"/f"{variant}_{profile}")]
        cmd += [str(d/s) for s in sources_by_impl[impl]]
        cmd += [str(work/"dove_envelope_harness.c")]
        compile_command[f"{variant}_{profile}"] = cmd

gcc = subprocess.run(["gcc", "--version"], text=True, capture_output=True).stdout.splitlines()[0]
environment = {
    "date_utc": subprocess.run(["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"], text=True, capture_output=True).stdout.strip(),
    "kernel": platform.release(),
    "machine": platform.machine(),
    "gcc": gcc,
    "cpu": next((line.split(":",1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name")), "unknown"),
    "avx2_available": " avx2 " in f" {' '.join(next((line.split(':',1)[1] for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('flags')), '').split())} ",
}

statement = (
    "For each of the twelve built configurations (two original implementation families "
    "(reference and AVX2-optimized), two variants (DOVE_classic and DOVE_pkc_skc), and three "
    "supported profiles (128, 256, 512)), the original exported sig_verify returned success "
    "(0) on a genuine signed buffer when either every one of the DOVE_SALT_BYTES was changed "
    "or only the valid N-byte prefix was backed by an oversized buffer containing poison bytes; "
    "this held for every declared sn_len_bytes from 0 through N+DOVE_SALT_BYTES inclusive. "
    "The source inspection explains this: each sig_verify ignores sn_len_bytes, reads exactly "
    "v=sn[0..DOVE_V-1] and z=sn[DOVE_V..DOVE_N-1], and never reads or authenticates the salt."
)

all_expected = all(r.get("all_expected") is True and r.get("run_exit") == 0 for r in records)
results = {
    "schema": "dove-signature-envelope-evidence/v1",
    "status": "complete" if all_expected and len(records) == 12 else "incomplete",
    "scope": "Direct exported sig_keygen/sig_sign/sig_verify calls on the original admitted reference source tree; no online system.",
    "fixed_inputs": {
        "seed_hex": "444f56452d656e76656c6f70652d746573742d32303236313131332d66697831",
        "message_construction": "m[i] = 0x31 + (i mod 47), i=0..95",
        "keygen_and_sign_calls_per_configuration": 1,
        "buffer_safety": "pk, sk, sn and poison-prefix buffers overallocated by 4096 bytes; declared lengths retain implementation-reported values.",
    },
    "statement": statement,
    "source_finding": "In all four SIG_AlgorithmInstance.c variants, the sig_verify body never references sn_len_bytes for bounds, length equality, salt parsing, or authentication.",
    "environment": environment,
    "source_hashes": source_files,
    "compile_commands": compile_command,
    "records": records,
    "controls": {
        "positive": "genuine returned signature with declared full length",
        "salt_byte_mutations": "each salt byte individually XOR 0x01, then all salt bytes XOR 0xff",
        "short_declared_length": "valid N-byte prefix retained, bytes after N set to 0xa5, every declared length 0..N+SALT tested",
        "negative": "state byte, public-key byte, and message byte each individually XOR 0x01",
    },
    "impact_assessment": {
        "direct_fact": "The exported verifier accepts noncanonical signature encodings: salt modifications and declared lengths shorter than the claimed N+SALT length.",
        "qualifying_ngcc_low": "not established by these API calls alone",
        "unresolved": [
            "Whether an original supported higher-level consumer treats successful sig_verify as canonical byte acceptance or exposes distinct-signature behavior.",
            "Whether any deployment relies on the salt for domain separation, replay resistance, signature identity, or uniqueness.",
            "No EUF-CMA forgery for a new public key/message is claimed."
        ]
    },
}
(work/"results.json").write_text(json.dumps(results, indent=2)+"\n")
(work/"sources.jsonl").write_text("\n".join(json.dumps({"path": v["path"], "sha256": v["sha256"]}) for v in source_files.values())+"\n")
(work/"contamination.json").write_text(json.dumps({"encountered": False, "note": "No prohibited attack/evaluation material was searched or read during this execution."}, indent=2)+"\n")

rows = []
for r in records:
    rows.append(
        f"| {r['implementation']} | {r['variant']} | {r['profile']} | {r.get('sn_len','-')} | "
        f"{r.get('salt_single_byte_accepts','-')}/{r.get('declared_salt_len','-')} | "
        f"{r.get('absent_salt_declared_length_accepts','-')}/{r.get('absent_salt_declared_length_calls','-')} | "
        f"{r.get('all_expected','-')} | {r.get('run_exit','-')} |"
    )
report = f"""# DOVE signature-envelope robustness evidence

## Finding

{statement}

This is direct evidence about the original exported API and its supported
profiles. It is not an EUF-CMA forgery and does not by itself establish
NGCC-Low consumer impact.

## Exact experimental design

The harness calls the original `sig_keygen`, `sig_sign`, and `sig_verify` from
each variant. Every required API allocation has 4096 bytes of safety padding.
The signature buffer is not read by the harness beyond its declared allocation.
After genuine signing, the tests are:

1. Verify the genuine `N+SALT` signature.
2. Flip each salt byte separately, then all salt bytes.
3. Pass a buffer with the genuine first `N` bytes and poison (`0xa5`) where the
   salt would be, while declaring every length from 0 through `N+SALT`.
4. Negative controls flip a state byte, public-key byte, and message byte.

Source inspection in all four distinct `SIG_AlgorithmInstance.c` files shows
that `sig_verify` never uses `sn_len_bytes` and accesses only `sn[0..N-1]`.

## Results

| implementation | variant | profile | sn_len | salt mutations accepted | absent-salt declared lengths accepted | expected | exit |
|---|---|---|---:|---:|---:|---|---:|
{os.linesep.join(rows)}

Raw JSON observations, compile diagnostics, binaries, source hashes, exact
compile commands, environment metadata, and control results are under
`envelope_artifacts/` and `results.json`.

## Interpretation limit

The verified accepted bytes are noncanonical envelope encodings: the verifier
does not bind the supplied signature length and does not authenticate the
declared salt. Whether this creates a qualifying interoperability, robustness,
availability, or security impact depends on an original supported consumer's
treatment of verification success and signature identity. Those obligations
remain unresolved. No online system was attacked.

## Reproduction

Run `./run_optimized_parallel.sh` for the optimized variants. The reference
variants were run by `./build_and_run.sh`; that script also includes optimized
variants and can be rerun serially. The exact GCC command for every binary is
recorded in `results.json`.
"""
(work/"research-report.md").write_text(report)

if results["status"] != "complete":
    raise SystemExit(3)
