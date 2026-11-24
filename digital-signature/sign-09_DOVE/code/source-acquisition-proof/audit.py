#!/usr/bin/env python3
"""Audit the task-local acquisition-to-rollout retention bridge.

This script performs no network access and reads only the current task run.
It writes one canonical JSON report plus a SHA-256 manifest.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any


RUN_INSTANCE = "8fb015d7d2ee4bdfae1cf50660d33edb"
STALE_EXECUTION = "88b65ec8561b4c5080b123dc70c88c0d"
STALE_SESSIONS = {
    "01a1d589-e428-7b30-89ff-15b089f1ee0c",
    "01a1d58b-d41d-7d02-ad94-e7065daf6cf6",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()


def parse_jsonl(path: Path) -> tuple[list[dict[str, Any]], int]:
    rows: list[dict[str, Any]] = []
    errors = 0
    with path.open(encoding="utf-8", errors="strict") as stream:
        for line in stream:
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError):
                errors += 1
                continue
            if isinstance(value, dict):
                rows.append(value)
    return rows, errors


def rollout_inventory(session_root: Path) -> dict[str, Any]:
    sessions: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    manifests: list[dict[str, Any]] = []
    parse_errors = 0
    session_meta_missing = 0
    total_files = 0

    for path in sorted(session_root.glob("**/*.jsonl")):
        total_files += 1
        rows, errors = parse_jsonl(path)
        parse_errors += errors
        session_id = ""
        response_types: collections.Counter[str] = collections.Counter()
        item_completed_types: collections.Counter[str] = collections.Counter()
        callable_names: collections.Counter[str] = collections.Counter()
        calls: dict[str, dict[str, Any]] = {}
        outputs: set[str] = set()

        for row in rows:
            payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
            if row.get("type") == "session_meta":
                session_id = str(payload.get("session_id") or payload.get("id") or "")
            if row.get("type") != "response_item":
                continue
            item_type = str(payload.get("type") or "")
            response_types[item_type] += 1
            call_id = str(payload.get("call_id") or "")

            if item_type.endswith("_output") and call_id:
                if call_id:
                    outputs.add(call_id)
                continue

            if item_type in {
                "function_call",
                "custom_tool_call",
                "tool_search_call",
                "web_search_call",
                "image_generation_call",
            }:
                name = str(payload.get("name") or item_type)
                callable_names[name] += 1
                if call_id:
                    calls[call_id] = {
                        "id": call_id,
                        "type": item_type,
                        "name": name,
                "has_separate_output_item": item_type
                in {
                    "function_call",
                    "custom_tool_call",
                    "tool_search_call",
                    "web_search_call",
                    "image_generation_call",
                },
                        "call_record": payload,
                    }

            if item_type == "image_view" or payload.get("type") == "image_view":
                callable_names["image_view"] += 1

        if not session_id:
            session_meta_missing += 1
            continue

        calls_with_missing_output = [
            {
                "id": call["id"],
                "type": call["type"],
                "name": call["name"],
            }
            for call in calls.values()
            if call["has_separate_output_item"] and call["id"] not in outputs
        ]
        record = {
            "path": str(path),
            "relative_path": str(path.relative_to(session_root)),
            "sha256": sha256_file(path),
            "size": path.stat().st_size,
            "parse_errors": errors,
            "response_item_types": dict(sorted(response_types.items())),
            "item_completed_types": dict(sorted(item_completed_types.items())),
            "callable_names": dict(sorted(callable_names.items())),
            "web_search_calls": response_types.get("web_search_call", 0),
            "calls_with_missing_output": calls_with_missing_output,
        }
        if all(old["sha256"] != record["sha256"] for old in sessions[session_id]):
            sessions[session_id].append(record)

    for path in sorted(session_root.glob("**/manifest-*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        manifests.append(
            {
                "path": str(path),
                "sha256": sha256_file(path),
                "dispatch": payload.get("dispatch") or "",
                "session_ids": sorted(set(payload.get("session_ids") or [])),
                "native_web": payload.get("native_web"),
                "native_results": payload.get("native_results"),
                "files": payload.get("files") or [],
            }
        )

    return {
        "session_root": str(session_root),
        "jsonl_file_count": total_files,
        "parse_errors": parse_errors,
        "session_meta_missing_files": session_meta_missing,
        "session_count": len(sessions),
        "session_snapshot_count": sum(len(v) for v in sessions.values()),
        "sessions": dict(sorted(sessions.items())),
        "manifest_count": len(manifests),
        "manifest_native_web": dict(
            collections.Counter(str(row["native_web"]) for row in manifests)
        ),
        "manifests_referencing_stale_sessions": [
            row
            for row in manifests
            if STALE_SESSIONS.intersection(row["session_ids"])
        ],
    }


def live_codex_inventory(codex_home: Path, run_root: Path) -> dict[str, Any]:
    state = codex_home / "state_5.sqlite"
    if not state.exists():
        return {"state_database": str(state), "thread_count": 0, "threads": []}
    connection = sqlite3.connect(f"file:{state}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        candidates = [
            dict(row)
            for row in connection.execute(
                """
                SELECT id, rollout_path, cwd, source, model_provider, model, archived
                  FROM threads
                 ORDER BY created_at, id
                """
            )
        ]
    finally:
        connection.close()

    root = str(run_root.resolve())
    threads = []
    for row in candidates:
        cwd = str(Path(row["cwd"]).resolve()) if row["cwd"] else ""
        if not (cwd == root or cwd.startswith(root + "/")):
            continue
        path = Path(row["rollout_path"])
        if not path.is_file():
            threads.append({**row, "rollout_present": False})
            continue
        rows, errors = parse_jsonl(path)
        response_types: collections.Counter[str] = collections.Counter()
        callable_names: collections.Counter[str] = collections.Counter()
        for event in rows:
            payload = (
                event.get("payload") if isinstance(event.get("payload"), dict) else {}
            )
            if event.get("type") != "response_item":
                continue
            item_type = str(payload.get("type") or "")
            response_types[item_type] += 1
            if item_type in {
                "function_call",
                "custom_tool_call",
                "tool_search_call",
                "web_search_call",
                "image_generation_call",
                "image_view",
            }:
                callable_names[str(payload.get("name") or item_type)] += 1
        threads.append(
            {
                **row,
                "rollout_present": True,
                "rollout_size": path.stat().st_size,
                "rollout_sha256": sha256_file(path),
                "parse_errors": errors,
                "response_item_types": dict(sorted(response_types.items())),
                "callable_names": dict(sorted(callable_names.items())),
                "web_search_calls": response_types.get("web_search_call", 0),
            }
        )
    return {"state_database": str(state), "thread_count": len(threads), "threads": threads}


def graph_inventory(database: Path) -> dict[str, Any]:
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        rows = [
            dict(row)
            for row in connection.execute(
                """
                SELECT id, role, session_id, invocation, outcome, started_at,
                       finished_at, exit_reason, owner_process
                  FROM model_executions
                 ORDER BY started_at, id
                """
            )
        ]
        stale = [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM model_executions WHERE id=?", (STALE_EXECUTION,)
            )
        ]
    finally:
        connection.close()
    session_ids = {row["session_id"] for row in rows if row["session_id"]}
    return {
        "database": str(database),
        "execution_count": len(rows),
        "nonempty_session_execution_count": sum(bool(row["session_id"]) for row in rows),
        "distinct_session_ids": sorted(session_ids),
        "outcomes": dict(collections.Counter(row["outcome"] for row in rows)),
        "stale_execution": stale[0] if stale else None,
    }


def invocation_inventory(run_root: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for path in sorted(run_root.rglob(".mmat-exec-*/invocation.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        directory = path.parent
        stdout = directory / "stdout.log"
        stderr = directory / "stderr.log"
        rows.append(
            {
                "path": str(path),
                "sha256": sha256_file(path),
                "stdout_present": stdout.exists(),
                "stdout_size": stdout.stat().st_size if stdout.exists() else None,
                "stderr_present": stderr.exists(),
                "stderr_size": stderr.stat().st_size if stderr.exists() else None,
                "started_at": value.get("started_at"),
                "finished_at": value.get("finished_at"),
                "returncode": value.get("returncode"),
                "error": value.get("error"),
            }
        )
    return {
        "count": len(rows),
        "missing_stdout": [row for row in rows if not row["stdout_present"]],
        "rows": rows,
    }


def _blob(run_root: Path, digest: str) -> dict[str, Any]:
    path = run_root / "blobs" / digest
    raw = path.read_bytes()
    if sha256_bytes(raw) != digest:
        raise ValueError(f"blob hash mismatch: {path}")
    return json.loads(raw)


def journal_inventory(run_root: Path) -> dict[str, Any]:
    database = run_root / "graph.db.tool-server-costs.sqlite3"
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        identity = dict(connection.execute("SELECT * FROM identity").fetchone())
        attempt_rows = list(connection.execute("SELECT * FROM attempts ORDER BY sequence"))
    finally:
        connection.close()

    kinds: collections.Counter[str] = collections.Counter()
    open_calls: list[dict[str, Any]] = []
    input_errors: list[dict[str, Any]] = []
    failed_returns: list[dict[str, Any]] = []
    for row in attempt_rows:
        begin = _blob(run_root, row["begin_blob"])
        kinds[str(begin.get("kind"))] += 1
        if row["finish_blob"] is None:
            open_calls.append(
                {
                    "sequence": row["sequence"],
                    "id": row["id"],
                    "kind": begin.get("kind"),
                    "call": begin,
                }
            )
            continue
        finish = _blob(run_root, row["finish_blob"])
        if finish.get("input_error"):
            input_errors.append(
                {
                    "sequence": row["sequence"],
                    "id": row["id"],
                    "kind": begin.get("kind"),
                    "error": finish["input_error"],
                }
            )
        if finish.get("outcome") == "failed":
            failed_returns.append(
                {
                    "sequence": row["sequence"],
                    "id": row["id"],
                    "kind": begin.get("kind"),
                    "error_type": finish.get("error_type"),
                }
            )

    return {
        "database": str(database),
        "identity": identity,
        "attempt_count": len(attempt_rows),
        "kinds": dict(kinds),
        "open_call_count": len(open_calls),
        "input_error_count": len(input_errors),
        "failed_return_count": len(failed_returns),
        "open_call_examples": open_calls[:8],
        "input_error_examples": input_errors[:8],
        "failed_return_examples": failed_returns[:8],
    }


def code_inventory(code_root: Path) -> dict[str, Any]:
    names = [
        "mmat/agent/backend.py",
        "mmat/agent/session_evidence.py",
        "mmat/agent/mcp_server.py",
        "mmat/tool_surface.py",
        "mmat/research/tool_server_costs.py",
        "mmat/research/tool_server_journal.py",
        "tests/test_native_search_evidence.py",
    ]
    return {
        name: {
            "sha256": sha256_file(code_root / name),
            "size": (code_root / name).stat().st_size,
        }
        for name in names
    }


def stale_crosscheck(
    session_inventory: dict[str, Any], graph: dict[str, Any]
) -> dict[str, Any]:
    found = {
        session_id: session_inventory["sessions"].get(session_id, [])
        for session_id in sorted(STALE_SESSIONS)
    }
    references = session_inventory["manifests_referencing_stale_sessions"]
    return {
        "execution": graph["stale_execution"],
        "execution_database_session_id": (
            graph["stale_execution"].get("session_id")
            if graph["stale_execution"]
            else None
        ),
        "raw_rollouts_found": found,
        "manifest_reference_count": len(references),
        "all_raw_rollouts_found": all(bool(rows) for rows in found.values()),
    }


def web_crosscheck(session_inventory: dict[str, Any]) -> dict[str, Any]:
    rows = []
    for session_id, snapshots in session_inventory["sessions"].items():
        for snapshot in snapshots:
            if snapshot["web_search_calls"]:
                rows.append(
                    {
                        "session_id": session_id,
                        "path": snapshot["path"],
                        "sha256": snapshot["sha256"],
                        "web_search_calls": snapshot["web_search_calls"],
                    }
                )
    return {
        "native_web_capability_count": sum(
            count
            for label, count in session_inventory["manifest_native_web"].items()
            if label == "live"
        ),
        "actual_web_search_snapshots": rows,
        "actual_web_search_count": sum(row["web_search_calls"] for row in rows),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--run-root",
        type=Path,
        default=Path("/home/mmat/mmat-preview/runs/ngcc-sign-09-ds01"),
    )
    parser.add_argument(
        "--session-root",
        type=Path,
        default=Path(
            "/home/mmat/.cache/mmat/session-evidence/ce9cb74f2861008d5d76"
        ),
    )
    parser.add_argument(
        "--code-root",
        type=Path,
        default=Path("/home/mmat/mmat-preview/releases/preview-20261113-lean-b21987e-r2/MMAT-v2"),
    )
    parser.add_argument(
        "--codex-home",
        type=Path,
        default=Path("/home/mmat/.cache/mmat/codex-caf15ec0537546de"),
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    graph = graph_inventory(args.run_root / "graph.db")
    sessions = rollout_inventory(args.session_root)
    live = live_codex_inventory(args.codex_home, args.run_root)
    invocations = invocation_inventory(args.run_root)
    journal = journal_inventory(args.run_root)
    graph_sessions = set(graph["distinct_session_ids"])
    raw_sessions = set(sessions["sessions"])

    report = {
        "schema": "mmat.acquisition-retention-bridge-audit/v1",
        "run_instance": RUN_INSTANCE,
        "run_root": str(args.run_root),
        "graph": graph,
        "sessions": sessions,
        "live_codex_home": live,
        "graph_sessions_missing_any_snapshot": sorted(graph_sessions - raw_sessions),
        "invocations": invocations,
        "tool_server_journal": journal,
        "stale_execution_crosscheck": stale_crosscheck(sessions, graph),
        "native_web_crosscheck": web_crosscheck(sessions),
        "installed_code": code_inventory(args.code_root),
        "checks": {
            "all_graph_sessions_have_raw_snapshot": not (graph_sessions - raw_sessions),
            "live_task_rollouts_present": all(
                row.get("rollout_present") for row in live["threads"]
            ),
            "all_raw_rollouts_parse_without_error": sessions["parse_errors"] == 0,
            "all_stale_sessions_have_raw_rollout": stale_crosscheck(
                sessions, graph
            )["all_raw_rollouts_found"],
            "actual_native_web_calls_are_retained": all(
                row["sha256"]
                for row in web_crosscheck(sessions)["actual_web_search_snapshots"]
            ),
        },
        "meaning": (
            "Task-local evidence inventory. It does not inspect kernel, proxy, "
            "firewall, provider-internal, or other-task traffic."
        ),
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    args.output.write_text(payload, encoding="utf-8")
    manifest = args.output.with_suffix(args.output.suffix + ".sha256")
    manifest.write_text(
        f"{sha256_bytes(payload.encode())}  {args.output.name}\n", encoding="ascii"
    )
    print(
        json.dumps(
            {
                "output": str(args.output),
                "sha256": sha256_bytes(payload.encode()),
                "checks": report["checks"],
                "graph_executions": graph["execution_count"],
                "graph_sessions_missing": report[
                    "graph_sessions_missing_any_snapshot"
                ],
                "raw_session_count": sessions["session_count"],
                "raw_session_snapshot_count": sessions["session_snapshot_count"],
                "live_task_thread_count": live["thread_count"],
                "manifest_count": sessions["manifest_count"],
                "web_search_call_count": report["native_web_crosscheck"][
                    "actual_web_search_count"
                ],
                "journal_open_calls": journal["open_call_count"],
                "journal_input_errors": journal["input_error_count"],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
