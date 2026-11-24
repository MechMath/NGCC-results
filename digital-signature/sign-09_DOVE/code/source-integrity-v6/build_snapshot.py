#!/usr/bin/env python3
"""Build the immutable 99->111 and answer-closure manifests from retained bytes."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path


ROOT = Path("/home/mmat/mmat-preview/runs/ngcc-sign-09-ds01")
HERE = ROOT / "run/slots/91fd3ed4f80c46e3/source-integrity-v6"
V5 = ROOT / "run/slots/e0543252e02944b6/source-integrity-v5/audit.json"


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main() -> None:
    audit = json.loads(V5.read_text())
    rows = []
    for item in audit["transcript_scan"]["native_file_summaries"]:
        path = Path(item["path"])
        rows.append((path.stat().st_mtime, item))
    rows.sort(key=lambda pair: pair[0])

    # At the v5 snapshot 115 JSONLs were already present.  The last four were
    # created after the 111-file count used by the admitted 03b... transition.
    rows111 = rows[:111]
    delta = rows111[99:111]
    assert len(delta) == 12

    with (HERE / "session-files-111.tsv").open("w") as out:
        out.write("index\tmtime_utc\tsha256\tbytes\tpath\n")
        for index, (mtime, item) in enumerate(rows111, 1):
            stamp = dt.datetime.fromtimestamp(mtime, dt.timezone.utc).isoformat()
            out.write(
                f"{index}\t{stamp}\t{item['sha256']}\t{item['bytes']}\t"
                f"{item['path']}\n"
            )

    with (HERE / "delta-99-to-111.jsonl").open("w") as out:
        for prior_index, (mtime, item) in enumerate(delta, 100):
            row = {
                "prior_index": prior_index,
                "mtime_utc": dt.datetime.fromtimestamp(
                    mtime, dt.timezone.utc
                ).isoformat(),
                "path": item["path"],
                "sha256": item["sha256"],
                "bytes": item["bytes"],
                "session_ids": item["session_ids"],
                "function_calls": item["function_calls"],
                "web_search_call_count": item["web_search_call_count"],
            }
            out.write(json.dumps(row, sort_keys=True) + "\n")

    closure_paths = [
        ROOT / "slots/orch-graph/orch/results.json",
        ROOT / "slots/orch-graph/orch/sources.jsonl",
        ROOT / "slots/orch-graph/orch/contamination.json",
        ROOT / "slots/orch-graph/orch/research-report.md",
        ROOT / "slots/orch-graph/orch/failed-attempts.md",
        ROOT / "slots/orch-graph/orch/DOVE.zip",
        ROOT / "slots/orch-graph/orch/sign-09-spec.pdf",
        ROOT / "slots/orch-graph/orch/Algorithm specifications.pdf",
        ROOT / "slots/orch-graph/orch/evidence/source.sha256",
        ROOT / "slots/orch-graph/orch/evidence/environment.txt",
        ROOT / "insights/d28faad0cd40bc9d/authors/main-d28faad0cd40bc9d/native/research-report.md",
        ROOT / "insights/d28faad0cd40bc9d/authors/main-d28faad0cd40bc9d/native/failed-attempts.md",
        ROOT / "insights/d28faad0cd40bc9d/authors/main-d28faad0cd40bc9d/native/DOVE.zip",
        ROOT / "insights/d28faad0cd40bc9d/authors/main-d28faad0cd40bc9d/native/sign-09-spec.pdf",
    ]
    closure = {
        "schema": "dove-answer-source-closure/v1",
        "candidate": "027e8bfaf45c4dc69af31abbbb2e1f09",
        "obligation": "3d8e23701c1342e481e431a5d5800e6a",
        "attack_result": "737f8383b541cae5",
        "attack_attempt": "603c6959314944d0",
        "files": [
            {
                "path": str(path),
                "bytes": path.stat().st_size,
                "sha256": sha(path),
            }
            for path in closure_paths
        ],
    }
    (HERE / "answer-source-closure.json").write_text(
        json.dumps(closure, indent=2, sort_keys=True) + "\n"
    )

    env = {
        "cwd": str(HERE),
        "checker": str(
            ROOT
            / "run/slots/fc3572a4cff14b1b/source-integrity-final/audit_source_integrity.py"
        ),
        "checker_sha256": sha(
            ROOT
            / "run/slots/fc3572a4cff14b1b/source-integrity-final/audit_source_integrity.py"
        ),
        "command": (
            "env -i PATH=/opt/mmat-preview/venv/bin:/usr/local/bin:/usr/bin:/bin "
            "PYTHONPATH=/opt/mmat-preview/src/MMAT-v2 "
            "MMAT_CODEX_CONFIG=/home/mmat/.config/mmat-preview/providers/"
            "deepseek-official/config.toml "
            "/opt/mmat-preview/venv/bin/python "
            "/home/mmat/mmat-preview/runs/ngcc-sign-09-ds01/run/slots/"
            "fc3572a4cff14b1b/source-integrity-final/audit_source_integrity.py "
            "--root /home/mmat/mmat-preview/runs/ngcc-sign-09-ds01 "
            "--session-evidence /home/mmat/.cache/mmat/session-evidence/"
            "ce9cb74f2861008d5d76 "
            "--out /home/mmat/mmat-preview/runs/ngcc-sign-09-ds01/run/slots/"
            "91fd3ed4f80c46e3/source-integrity-v6"
        ),
        "network_access_performed_by_audit": False,
        "python": os.popen("/opt/mmat-preview/venv/bin/python --version").read().strip(),
    }
    (HERE / "environment-and-command.json").write_text(
        json.dumps(env, indent=2, sort_keys=True) + "\n"
    )


if __name__ == "__main__":
    main()
