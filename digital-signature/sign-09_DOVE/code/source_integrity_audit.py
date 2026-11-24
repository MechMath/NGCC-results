#!/usr/bin/env python3
"""Check the retained DOVE source registry and local-only experiment boundary."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parent
EXPECTED_SOURCES = {
    "original_request",
    "dove_zip",
    "algorithm_spec",
    "basic_information",
    "self_assessment",
    "reference_implementation",
}
ALLOWED_NETWORK_URLS = {
    "https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/DOVE.zip",
    "https://cdn.jsdelivr.net/gh/ngcc-dev/ngcc-harness@dc66c6cb3c06e75bdea0048e21fa4e13c63f00af/sign-09/sign-09-spec.pdf",
}
PROHIBITED_MARKERS = {
    "eprint_review": "eprint.iacr.org/2024/609",
    "eprint_2026_2266": "eprint.iacr.org/2026/2266",
    "harness_issue": "github.com/ngcc-dev/ngcc-harness/issues/9",
    "forum_j34": "J34BWSBLHSX2VOX5MNUTW6KQ6W26APU3",
    "forum_plf": "PLF54PXYLAT2LQFQLJWN5LMKWSWWSM7O",
}
EXPECTED_HASHES = {
    "DOVE.zip": "19169e545f6a6fd90b844b0deb72db81b5eb73c136873d1dae113c2c39d1c6e0",
    "sign-09-spec.pdf": "c76b7b8263ef94e17b9c1821b6d8087cb3125b493ce655b4eddbabfa5f19e729",
}


def sha256(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def main() -> int:
    sources = [
        json.loads(line)
        for line in (ROOT / "sources.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    source_ids = {item["id"] for item in sources}
    network_sources = {
        item["source"] for item in sources if urlparse(item.get("source", "")).scheme in {"http", "https"}
    }
    contamination = json.loads((ROOT / "contamination.json").read_text(encoding="utf-8"))
    joined_sources = json.dumps(sources, sort_keys=True)
    prohibited_seen = {
        name: marker in joined_sources for name, marker in PROHIBITED_MARKERS.items()
    }
    local_harness = (ROOT / "dove_length_guard_test.c").read_text(encoding="utf-8")
    local_script = (ROOT / "reproduce_dove_pkc_skc_128_oob.sh").read_text(encoding="utf-8")
    experiment_text = local_harness + "\n" + local_script
    network_tokens = sorted(
        token
        for token in ("curl", "wget", "socket(", "connect(", "send(", "recv(", "http://", "https://")
        if token in experiment_text
    )
    checks = {
        "source_registry_exact": source_ids == EXPECTED_SOURCES,
        "network_sources_exact": network_sources == ALLOWED_NETWORK_URLS,
        "submission_hash_matches": sha256(ROOT / "DOVE.zip") == EXPECTED_HASHES["DOVE.zip"],
        "spec_hash_matches": sha256(ROOT / "sign-09-spec.pdf") == EXPECTED_HASHES["sign-09-spec.pdf"],
        "no_prohibited_marker_in_registry": not any(prohibited_seen.values()),
        "contamination_status_none": contamination.get("status") == "none",
        "contamination_records_empty": contamination.get("records") == [],
        "experiment_has_no_network_operations": not network_tokens,
    }
    report = {
        "schema": "mmat.source-integrity-audit/v1",
        "checked_at_utc": "2026-11-13T15:30:17Z",
        "checks": checks,
        "all_pass": all(checks.values()),
        "source_ids": sorted(source_ids),
        "network_sources": sorted(network_sources),
        "prohibited_markers_seen": prohibited_seen,
        "experiment_network_tokens_seen": network_tokens,
        "source_registry_sha256": sha256(ROOT / "sources.jsonl"),
        "contamination_sha256": sha256(ROOT / "contamination.json"),
        "limitations": (
            "This audit checks the retained registry, hashes, contamination record, and "
            "local experiment files. It does not prove unrecorded activity from process "
            "telemetry that was not retained."
        ),
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
