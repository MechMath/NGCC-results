#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FILES = [
    "experiments/oom_wrong_message.c",
    "experiments/malloc_fault_wrap.c",
    "experiments/reproduce_bit512.sh",
    "results/environment.txt",
    "results/source-hashes.txt",
    "results/output-hashes.txt",
    "results/failures.txt",
    "results/reference-build.log",
    "results/avx2-build.log",
    "results/reference.log",
    "results/avx2.log",
    "results/initial-link-failure.log",
    "results/all-failures.jsonl",
    "results/evidence-review-insufficient.json",
    "results/spec-integrity.txt",
    "results/repetitions/reference-1.log",
    "results/repetitions/reference-2.log",
    "results/repetitions/reference-3.log",
    "results/repetitions/avx2-1.log",
    "results/repetitions/avx2-2.log",
    "results/repetitions/avx2-3.log",
    "extracted/Implementations/Reference_Implementation/BiT-512/SIG_AlgorithmInstance.h",
    "extracted/Implementations/Reference_Implementation/BiT-512/sign.c",
    "extracted/Implementations/Reference_Implementation/BiT-512/symmetric.c",
    "extracted/Implementations/Optimized_Implementation/BiT-512-avx2/sign.c",
    "extracted/Implementations/Optimized_Implementation/BiT-512-avx2/symmetric.c",
    "research-report.md",
    "results.json",
    "sources.jsonl",
    "contamination.json",
    "failed-attempts.md",
]

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def fence(path, text):
    suffix = Path(path).suffix.lstrip(".") or "text"
    return f"### `{path}`\n\n```{suffix}\n{text.rstrip()}\n```\n"

lines = [
    "# BiT-512 independent source-integrity evidence bundle",
    "",
    "Status: source-integrity reproduction evidence, not an independent evidence-review verdict.",
    "",
    "## Subject identity",
    "",
    "- Submission URL: https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/BiT.zip",
    "- ZIP SHA-256: `698fbe834279a4100a66c20f3e0b634c738e1150936acf74b55efc6db6975e8d`",
    "- Specification URL: https://cdn.jsdelivr.net/gh/ngcc-dev/ngcc-harness@dc66c6cb3c06e75bdea0048e21fa4e13c63f00af/sign-02/sign-02-spec.pdf",
    "- Specification SHA-256: `28e942ee1baa7b686271420d56bea370c65891b4b57ef4045424f8a52dd0ccca`; size 624928 bytes. Extraction failed only because `mutool` is unavailable.",
    "- Supported objects: BiT-512 `Reference_Implementation` and `Optimized_Implementation` AVX2.",
    "- Spec URL (not read in this reproduction because the graph extractor lacked `mutool`): https://cdn.jsdelivr.net/gh/ngcc-dev/ngcc-harness@dc66c6cb3c06e75bdea0048e21fa4e13c63f00af/sign-02/sign-02-spec.pdf",
    "",
    "## Complete process relationship",
    "",
    "1. Download the exact ZIP and require SHA-256 above.",
    "2. Extract with Python's `zipfile`.",
    "3. Hash the submitted header, signers, and hash helpers.",
    "4. Compile each unmodified implementation with the driver and one-shot malloc interposer.",
    "5. Run the driver with both the previous-message fault and the unarmed requested-message control.",
    "6. Repeat both implementations three times and hash all six logs.",
    "7. Check the public header promise: `sig_sign` returns 0 only on success and a negative code otherwise.",
    "",
    "## Result",
    "",
    "For each reference and AVX2 build: one qualifying allocation failed; the faulted second",
    "signature call returned 0 with length 6695; verification succeeded for the prior message",
    "m1 and failed for requested message m2; the unarmed control returned 0 with length 6695,",
    "failed for m1, and verified for m2.",
    "",
    "The all-six repetition logs share SHA-256 `23bfbde9cc554bee5caabf5a9f8093c8c57ba26c4c0008ece8ce2d43d2645aae`.",
    "",
    "## Failed attempts and blockers",
    "",
    "- The first linker attempt failed before execution because control symbols were not linked; exact linker output is retained in `results/initial-link-failure.log`; fixed by runtime `dlsym` lookup without changing subject sources.",
    "- `research_api_return_publish` failed with `AttributeError: module 'mmat.insight' has no attribute 'publish'`; the underlying official MMAT publication function is used directly below and this tool-surface failure is retained.",
    "- Capturing the 44 MiB ZIP as a source document failed as empty/over-cap.",
    "- Capturing the permitted PDF failed because the graph environment has no `mutool` text extractor.",
    "- No prohibited attack/evaluation material was intentionally accessed. `contamination.json` records no accidental encounter.",
    "- The first submitted bundle review returned `insufficient`; its exact verdict is retained in `results/evidence-review-insufficient.json` and motivated this complete v2 bundle.",
    "",
    "## Exact file manifest",
    "",
]

for rel in FILES:
    path = ROOT / rel
    lines.append(f"- `{rel}`: SHA-256 `{sha(path)}`, {path.stat().st_size} bytes")

lines += ["", "## Complete retained files", ""]
for rel in FILES:
    path = ROOT / rel
    lines.append(fence(rel, path.read_text(errors="replace")))

out = ROOT / "source-integrity-bundle.md"
out.write_text("\n".join(lines) + "\n")
print(json.dumps({"path": str(out), "sha256": sha(out), "size": out.stat().st_size}, sort_keys=True))
