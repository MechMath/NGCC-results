#!/usr/bin/env python3
"""Classify every native call whose separate output item is not retained."""

from __future__ import annotations

import collections
import hashlib
import json
import re
import sqlite3
from pathlib import Path


ROOT = Path("/home/mmat/mmat-preview/runs/ngcc-sign-09-ds01")
ARCHIVE = Path("/home/mmat/.cache/mmat/session-evidence/ce9cb74f2861008d5d76")
LIVE_ROLLOUT = Path(
    "/home/mmat/.cache/mmat/codex-9623bd9e88a049af/sessions/"
    "2026/11/14/rollout-2026-11-14T03-23-19-01a1d65d-456d-79a1-a613-7ee4f1b9f405.jsonl"
)
OUT = Path(__file__).with_name("missing-output-audit.json")

NETWORK = re.compile(
    r"(?i)(?:^|&&|\|\||;)\s*(?:sudo\s+|env\s+|command\s+)?"
    r"(?:curl|wget|apt-get\s+(?:download|install|update|upgrade)|"
    r"apt\s+(?:download|install|update|upgrade)|"
    r"pip[0-9.]*\s+install|python[0-9.]*\s+-m\s+pip\s+install|"
    r"git\s+(?:clone|fetch|pull|ls-remote)|ssh|scp|sftp)"
)


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_file(path: Path) -> tuple[str, list[dict]]:
    session_id = ""
    items: list[dict] = []
    with path.open(errors="replace") as stream:
        for line_number, line in enumerate(stream, 1):
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            payload = row.get("payload") if isinstance(row, dict) else None
            if not isinstance(payload, dict):
                continue
            if row.get("type") == "session_meta":
                session_id = str(payload.get("id") or "")
                continue
            if row.get("type") != "response_item":
                continue
            items.append(
                {
                    "line": line_number,
                    "payload": payload,
                    "timestamp": row.get("timestamp"),
                }
            )
    return session_id, items


def classify(name: str, payload: dict) -> tuple[str, str, dict]:
    raw_arguments = payload.get("arguments")
    try:
        arguments = (
            json.loads(raw_arguments)
            if isinstance(raw_arguments, str)
            else (raw_arguments if isinstance(raw_arguments, dict) else {})
        )
    except json.JSONDecodeError:
        arguments = {"raw_arguments": raw_arguments}

    command = str(arguments.get("cmd") or "")
    if name == "exec_command":
        if NETWORK.search(command):
            return "network_candidate", "exec_command with network operator", arguments
        return "local_command", "exec_command with no network operator", arguments
    if name == "research":
        action = str(arguments.get("action") or "")
        if action in {"evidence_review", "evidence_review_read"}:
            return "local_research_control", "task-local evidence review", arguments
        if action in {"source_capture", "source_read", "source_claim", "baseline_search", "baseline_chase"}:
            return "network_candidate", "research source acquisition action", arguments
        return "local_research_control", "task-local MMAT research action", arguments
    if name in {"wait_agent", "write_stdin"}:
        return "local_control", f"task-local {name}", arguments
    return "other", f"unclassified {name}", arguments


paths = sorted(ARCHIVE.glob("**/*.jsonl"))
if LIVE_ROLLOUT.is_file():
    paths.append(LIVE_ROLLOUT)

file_rows = []
unique_session_snapshots: dict[str, set[str]] = collections.defaultdict(set)
all_items: list[dict] = []
parse_error_count = 0
for path in paths:
    session_id, items = parse_file(path)
    digest = sha(path)
    unique_session_snapshots[session_id].add(digest)
    file_rows.append(
        {
            "path": str(path),
            "sha256": digest,
            "bytes": path.stat().st_size,
            "session_id": session_id,
            "response_item_count": len(items),
        }
    )
    for item in items:
        all_items.append({"file": str(path), "session_id": session_id, **item})

calls: dict[str, dict] = {}
outputs: set[str] = set()
web_search_items = 0
for item in all_items:
    payload = item["payload"]
    item_type = str(payload.get("type") or "")
    call_id = str(payload.get("call_id") or payload.get("id") or "")
    if item_type in {
        "function_call_output",
        "custom_tool_call_output",
        "tool_search_output",
    } and call_id:
        outputs.add(call_id)
    if item_type == "web_search_call":
        web_search_items += 1
    if item_type in {
        "function_call",
        "custom_tool_call",
        "tool_search_call",
        "web_search_call",
        "image_generation_call",
    } and call_id:
        calls[call_id] = {
            "call_id": call_id,
            "type": item_type,
            "name": str(payload.get("name") or item_type),
            "file": item["file"],
            "session_id": item["session_id"],
            "line": item["line"],
            "timestamp": item["timestamp"],
            "payload": payload,
        }

missing = []
for call_id, call in calls.items():
    if call_id in outputs:
        continue
    role, basis, arguments = classify(call["name"], call["payload"])
    missing.append(
        {
            **call,
            "classification": role,
            "classification_basis": basis,
            "arguments_parsed": arguments,
        }
    )

connection = sqlite3.connect(f"file:{ROOT / 'graph.db'}?mode=ro", uri=True)
graph_session_ids = {
    row[0]
    for row in connection.execute(
        "SELECT DISTINCT session_id FROM model_executions WHERE session_id IS NOT NULL AND session_id <> ''"
    )
}
graph_execution_count = connection.execute(
    "SELECT COUNT(*) FROM model_executions"
).fetchone()[0]
connection.close()

covered_session_ids = set(unique_session_snapshots)
missing_graph_sessions = sorted(graph_session_ids - covered_session_ids)
network_missing = [row for row in missing if row["classification"] == "network_candidate"]

report = {
    "schema": "mmat.dove-missing-output-audit/v1",
    "network_access_performed_by_audit": False,
    "roots": {"task": str(ROOT), "archive": str(ARCHIVE), "live_rollout": str(LIVE_ROLLOUT)},
    "counts": {
        "jsonl_files": len(file_rows),
        "unique_session_ids": len(covered_session_ids),
        "unique_session_snapshots": sum(len(v) for v in unique_session_snapshots.values()),
        "response_items": len(all_items),
        "call_items": len(calls),
        "separate_output_ids": len(outputs),
        "missing_separate_outputs": len(missing),
        "web_search_items": web_search_items,
        "graph_model_executions": graph_execution_count,
        "graph_nonempty_session_ids": len(graph_session_ids),
        "graph_session_ids_without_snapshot": len(missing_graph_sessions),
    },
    "missing_separate_outputs": missing,
    "missing_classification_counts": dict(
        collections.Counter(row["classification"] for row in missing)
    ),
    "one_external_acquisition": bool(network_missing),
    "network_candidates": network_missing,
    "missing_graph_session_ids": missing_graph_sessions,
    "live_rollout_present": LIVE_ROLLOUT.is_file(),
    "live_rollout_sha256": sha(LIVE_ROLLOUT) if LIVE_ROLLOUT.is_file() else None,
    "file_rows": file_rows,
    "meaning": (
        "A call without a separate output item delivered no represented result. "
        "The classification is based on the retained call arguments only; this "
        "audit makes no claim about unretained kernel, proxy, provider, or "
        "unfinished-session traffic."
    ),
}
OUT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
print(
    json.dumps(
        {
            "output": str(OUT),
            "sha256": sha(OUT),
            "counts": report["counts"],
            "missing_classification_counts": report["missing_classification_counts"],
            "missing": [
                {
                    "call_id": row["call_id"],
                    "name": row["name"],
                    "classification": row["classification"],
                    "arguments": row["arguments_parsed"],
                }
                for row in missing
            ],
            "one_external_acquisition": report["one_external_acquisition"],
        },
        indent=2,
        sort_keys=True,
    )
)
