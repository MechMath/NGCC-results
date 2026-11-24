#!/usr/bin/env python3
"""Read-only retained-history audit for the DOVE source-integrity obligation."""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import pathlib
import re
import sqlite3
import sys


ZIP_URL = "https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/DOVE.zip"
PDF_URL = "https://cdn.jsdelivr.net/gh/ngcc-dev/ngcc-harness@dc66c6cb3c06e75bdea0048e21fa4e13c63f00af/sign-09/sign-09-spec.pdf"
ZIP_SHA = "19169e545f6a6fd90b844b0deb72db81b5eb73c136873d1dae113c2c39d1c6e0"
PDF_SHA = "c76b7b8263ef94e17b9c1821b6d8087cb3125b493ce655b4eddbabfa5f19e729"
STALE = "88b65ec8561b4c5080b123dc70c88c0d"


def sha(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def blob(root: pathlib.Path, digest: str):
    path = root / "blobs" / digest
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--session-evidence")
    args = parser.parse_args()
    root = pathlib.Path(args.root).resolve()
    out = pathlib.Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    graph_path = root / "graph.db"
    tool_path = root / "graph.db.tool-server-costs.sqlite3"
    graph = sqlite3.connect(f"file:{graph_path}?mode=ro", uri=True)
    tool = sqlite3.connect(f"file:{tool_path}?mode=ro", uri=True)

    executions = []
    cols = [row[1] for row in graph.execute("PRAGMA table_info(model_executions)")]
    for row in graph.execute("SELECT * FROM model_executions ORDER BY started_at,id"):
        executions.append(dict(zip(cols, row)))

    invocations = []
    for path in sorted(root.rglob(".mmat-exec-*/invocation.json")):
        rel_dir = path.parent.relative_to(root).as_posix()
        try:
            data = json.loads(path.read_text())
        except (OSError, UnicodeError, json.JSONDecodeError):
            data = {}
        stdout = path.with_name("stdout.log")
        invocations.append({
            "dir": rel_dir,
            "invocation_sha256": sha(path),
            "stdout_present": stdout.is_file(),
            "stdout_sha256": sha(stdout) if stdout.is_file() else None,
            "stdout_bytes": stdout.stat().st_size if stdout.is_file() else None,
            "contains_stale_execution": STALE in json.dumps(data),
        })

    stale_rows = []
    tool_post_baseline = []
    tool_cols = [row[1] for row in tool.execute("PRAGMA table_info(attempts)")]
    for row in tool.execute("SELECT * FROM attempts ORDER BY sequence"):
        item = dict(zip(tool_cols, row))
        begin = blob(root, item["begin_blob"]) or {}
        finish = blob(root, item["finish_blob"]) if item["finish_blob"] else {}
        begin_path = root / "blobs" / item["begin_blob"]
        try:
            begin_mtime = begin_path.stat().st_mtime
        except OSError:
            begin_mtime = None
        if (
            begin.get("kind") == "tool_call"
            and begin_mtime is not None
            and begin_mtime >= 1794589980
        ):
            input_blob = finish.get("input_blob")
            payload = blob(root, input_blob) if input_blob else None
            if isinstance(payload, dict) and "params" in payload:
                params = payload.get("params") or {}
                params = {**params, **(params.get("arguments") or {})}
            else:
                params = payload or {}
            name = str(params.get("name") or params.get("tool") or "")
            action = str(params.get("action") or "")
            external = name in {
                "source_capture", "source_read", "source_claim",
                "baseline_search", "baseline_chase", "web_search", "web_run",
            } or action in {
                "source_capture", "source_read", "source_claim",
                "baseline_search", "baseline_chase",
            }
            tool_post_baseline.append({
                "sequence": item["sequence"],
                "begin_blob": item["begin_blob"],
                "finish_blob": item["finish_blob"],
                "begin_mtime": begin_mtime,
                "model_execution_id": begin.get("actor", {}).get("model_execution_id"),
                "tool": name,
                "action": action,
                "outcome": (finish or {}).get("outcome"),
                "error_type": (finish or {}).get("error_type"),
                "external_source_operation": external,
            })
        if begin.get("actor", {}).get("model_execution_id") != STALE:
            continue
        input_blob = finish.get("input_blob")
        payload = blob(root, input_blob) if input_blob else None
        stale_rows.append({
            "sequence": item["sequence"],
            "kind": begin.get("kind"),
            "begin_blob": item["begin_blob"],
            "finish_blob": item["finish_blob"],
            "outcome": (finish or {}).get("outcome"),
            "error_type": (finish or {}).get("error_type"),
            "input_blob": input_blob,
            "tool": (payload or {}).get("name")
                or ((payload or {}).get("params") or {}).get("name"),
            "arguments": (payload or {}).get("arguments")
                or ((payload or {}).get("params") or {}).get("arguments"),
        })

    actual_web_items = []
    transcript_files = 0
    transcript_json_errors = 0
    for path in sorted(root.rglob("stdout.log")):
        transcript_files += 1
        try:
            lines = path.open("r", errors="strict")
        except OSError:
            continue
        with lines:
            for lineno, line in enumerate(lines, 1):
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    transcript_json_errors += 1
                    continue
                item = row.get("item") if isinstance(row, dict) else None
                if isinstance(item, dict) and item.get("type") in (
                    "web_search_call", "web_search", "web_run"
                ):
                    actual_web_items.append({
                        "path": path.relative_to(root).as_posix(),
                        "line": lineno,
                        "type": item.get("type"),
                        "item": item,
                    })

    native_rollouts = []
    native_web_items = []
    archived_session_ids = set()
    native_file_summaries = []
    native_calls = []
    seen_native_call_ids = set()
    evidence_root = (
        pathlib.Path(args.session_evidence).resolve()
        if args.session_evidence else None
    )
    native_paths = []
    if evidence_root and evidence_root.is_dir():
        native_paths = sorted(evidence_root.rglob("*.jsonl"))
    elif (root / "session-evidence").is_dir():
        native_paths = sorted((root / "session-evidence").rglob("*.jsonl"))
    for path in native_paths:
        native_rollouts.append(str(path))
        file_sessions = set()
        file_functions = collections.Counter()
        file_web_count = 0
        with path.open("r", errors="replace") as stream:
            for lineno, line in enumerate(stream, 1):
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(row, dict) and row.get("type") == "session_meta":
                    session_id = (row.get("payload") or {}).get("id")
                    if isinstance(session_id, str):
                        archived_session_ids.add(session_id)
                        file_sessions.add(session_id)
                payload = row.get("payload") if isinstance(row, dict) else None
                if isinstance(payload, dict) and payload.get("type") == "web_search_call":
                    file_web_count += 1
                    native_web_items.append({
                        "path": str(path),
                        "line": lineno,
                        "payload": payload,
                    })
                if isinstance(payload, dict) and payload.get("type") == "function_call":
                    file_functions[str(payload.get("name"))] += 1
                    call_id = str(payload.get("id") or "")
                    if not call_id or call_id not in seen_native_call_ids:
                        if call_id:
                            seen_native_call_ids.add(call_id)
                        native_calls.append({
                            "path": str(path),
                            "line": lineno,
                            "timestamp": row.get("timestamp", ""),
                            "call_id": call_id,
                            "name": payload.get("name"),
                            "arguments": payload.get("arguments"),
                        })
        native_file_summaries.append({
            "path": str(path),
            "sha256": sha(path),
            "bytes": path.stat().st_size,
            "session_ids": sorted(file_sessions),
            "function_calls": dict(file_functions),
            "web_search_call_count": file_web_count,
        })

    audit_report = root / "run/slots/c12d636c8dd64d98/audit-output/audit_report.json"
    if not audit_report.is_file():
        audit_report = None
    audit = json.loads(audit_report.read_text()) if audit_report else {}

    raw_scan_report = (
        root / "run/slots/1090b53e80f3413d/audit-output-f3-1090/audit_report.json"
    )
    raw_scan = json.loads(raw_scan_report.read_text()) if raw_scan_report.is_file() else {}
    false_positive_rows = []
    seen_false_positive_items = set()
    for event in raw_scan.get("prohibited_access_events", []):
        item_key = (event.get("source_log"), event.get("line"), event.get("item_id"))
        if item_key in seen_false_positive_items:
            continue
        seen_false_positive_items.add(item_key)
        if True:
            text = json.dumps(event, sort_keys=True)
            if re.search(r"\b(rg|python|grep|cat|sed)\b", text) and not event.get("destinations"):
                false_positive_rows.append({
                    "source_bucket": "1090 prohibited_access_events",
                    "source_log": event.get("source_log"),
                    "line": event.get("line"),
                    "tool": event.get("tool"),
                    "command": event.get("command"),
                    "destinations": event.get("destinations", []),
                    "classification": "local_text_scan_false_positive",
                })

    native_network_candidates = []
    native_tool_security = []
    native_action_classes = collections.Counter()
    acquisition_operator = re.compile(
        r"(?i)(?:^|&&|\|\||;)\s*(?:sudo\s+|env\s+|command\s+)?"
        r"(?:curl|wget|apt-get\s+(?:download|install|update|upgrade)|"
        r"apt\s+(?:download|install|update|upgrade)|"
        r"pip[0-9.]*\s+install|python[0-9.]*\s+-m\s+pip\s+install|"
        r"git\s+(?:clone|fetch|pull|ls-remote)|ssh|scp|sftp)"
    )
    python_network_operator = re.compile(
        r"(?is)(?:requests\.(?:get|post|request)\s*\(|"
        r"urllib\.request\.(?:urlopen|Request)\s*\(|"
        r"(?:socket|s)\.connect\s*\()"
    )
    url_pattern = re.compile(r"https?://[^\s'\"<>]+", re.I)

    def parsed_arguments(value):
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                result = json.loads(value)
                return result if isinstance(result, dict) else {}
            except json.JSONDecodeError:
                return {}
        return {}

    post_baseline_cut = "2026-11-13T17:13:00"
    for call in native_calls:
        post_baseline = str(call.get("timestamp") or "") >= post_baseline_cut
        if not post_baseline:
            continue
        raw_args = call.get("arguments") or ""
        args_obj = parsed_arguments(raw_args)
        name = str(call.get("name") or "")
        shell_cmd = args_obj.get("cmd") if name == "exec_command" else ""
        if not isinstance(shell_cmd, str):
            shell_cmd = ""
        is_operator = bool(
            acquisition_operator.search(shell_cmd)
            or (shell_cmd.lstrip().startswith(("python", "python3"))
                and python_network_operator.search(shell_cmd))
        )
        urls = sorted(set(url_pattern.findall(shell_cmd)))
        if name == "exec_command":
            roles = []
            unauthorized = []
            if is_operator:
                for url in urls:
                    if url == ZIP_URL:
                        roles.append("original_material")
                    elif url == PDF_URL:
                        roles.append("original_specification")
                    elif re.match(
                        r"https?://(?:archive\.ubuntu\.com|security\.ubuntu\.com|"
                        r"pypi\.org|files\.pythonhosted\.org|www\.rarlab\.com)/",
                        url, re.I
                    ):
                        roles.append("operational_package_or_tool")
                    else:
                        unauthorized.append(url)
                lowered = shell_cmd.lower()
                if any(token in lowered for token in (
                    "pip install", "-m pip install", "pip3 install", "apt-get download",
                    "apt download", "rarlab.com"
                )):
                    roles.append("operational_package_or_tool")
                native_action_classes[
                    "external_acquisition" if roles else
                    ("unresolved_network_operator" if unauthorized else
                     "external_operator_without_url")
                ] += 1
                native_network_candidates.append({
                    **call,
                    "parsed_arguments": args_obj,
                    "urls": urls,
                    "network_operator": True,
                    "roles": sorted(set(roles)),
                    "unauthorized_urls": unauthorized,
                })
            else:
                native_action_classes["local_command_or_scan"] += 1
        elif name in (
            "research", "source_capture", "source_claim",
            "baseline_search", "baseline_chase"
        ):
            action = str(args_obj.get("action") or name)
            external_actions = {
                "source_capture", "baseline_search", "baseline_chase",
                "source_read",
            }
            if action in external_actions:
                native_action_classes["external_research_tool"] += 1
                native_tool_security.append({**call, "parsed_arguments": args_obj})
            else:
                native_action_classes["local_mmat_research_tool"] += 1
        else:
            native_action_classes["local_mmat_or_control_tool"] += 1

    source_roles = collections.Counter()
    network_events_path = (
        root / "run/slots/c12d636c8dd64d98/audit-output/network_events.jsonl"
    )
    if network_events_path.is_file():
        with network_events_path.open("r", errors="replace") as stream:
            for line in stream:
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                role = row.get("source_role")
                if role:
                    source_roles[role] += 1
                else:
                    for item in row.get("source_roles") or []:
                        source_roles[item] += 1

    stale_exec = next((x for x in executions if x["id"] == STALE), None)
    report = {
        "schema": "dove-source-integrity-audit/v1",
        "root": str(root),
        "network_access_performed_by_audit": False,
        "exact_identities": {
            "dove_zip_url": ZIP_URL,
            "dove_zip_sha256": ZIP_SHA,
            "pinned_pdf_url": PDF_URL,
            "pinned_pdf_sha256": PDF_SHA,
        },
        "graph_db": {
            "path": graph_path.relative_to(root).as_posix(),
            "sha256_at_read": sha(graph_path),
            "model_execution_count": len(executions),
        },
        "tool_journal_db": {
            "path": tool_path.relative_to(root).as_posix(),
            "sha256_at_read": sha(tool_path),
        },
        "invocations": invocations,
        "missing_stdout": [x for x in invocations if not x["stdout_present"]],
        "stale_execution": stale_exec,
        "stale_tool_rows": stale_rows,
        "tool_journal_post_baseline": {
            "cutoff_epoch": 1794589980,
            "count": len(tool_post_baseline),
            "tool_counts": dict(collections.Counter(
                row["tool"] for row in tool_post_baseline
            )),
            "external_source_operation_count": sum(
                row["external_source_operation"] for row in tool_post_baseline
            ),
            "rows": tool_post_baseline,
        },
        "stale_actual_tool_calls": [
            x for x in stale_rows if x["kind"] == "tool_call"
        ],
        "stale_failed_grouped_calls": [
            x for x in stale_rows
            if x["kind"] == "grouped_call" and x["outcome"] == "failed"
        ],
        "transcript_scan": {
            "stdout_files": transcript_files,
            "json_parse_errors": transcript_json_errors,
            "actual_native_web_items": actual_web_items,
            "native_rollout_files": native_rollouts,
            "archived_session_ids": sorted(archived_session_ids),
            "stale_session_meta_present": (
                "01a1d589-e428-7b30-89ff-15b089f1ee0c"
                in archived_session_ids
            ),
            "stale_session_files": [
                row for row in native_file_summaries
                if "01a1d589-e428-7b30-89ff-15b089f1ee0c"
                in row["session_ids"]
            ],
            "native_file_summaries": native_file_summaries,
            "native_rollout_web_items": native_web_items,
            "native_call_count": len(native_calls),
            "native_post_baseline_call_count": sum(
                str(call.get("timestamp") or "") >= post_baseline_cut
                for call in native_calls
            ),
            "native_calls_by_name": dict(collections.Counter(
                str(call.get("name")) for call in native_calls
            )),
            "native_network_candidates": native_network_candidates,
            "native_research_or_source_calls": native_tool_security,
            "native_action_classes": dict(native_action_classes),
            "native_external_acquisition_actions": native_network_candidates,
            "native_network_candidate_count": len(native_network_candidates),
            "native_network_operator_count": len(native_network_candidates),
            "native_unauthorized_url_count": sum(
                len(row["unauthorized_urls"]) for row in native_network_candidates
            ),
        },
        "retained_audit": {
            "path": audit_report.relative_to(root).as_posix() if audit_report else None,
            "sha256": sha(audit_report) if audit_report else None,
            "counts": audit.get("counts"),
            "finding": audit.get("finding"),
            "source_role_counts": dict(source_roles),
        },
        "local_scan_false_positives": false_positive_rows,
        "raw_scan_report": {
            "path": raw_scan_report.relative_to(root).as_posix()
                if raw_scan_report.is_file() else None,
            "sha256": sha(raw_scan_report) if raw_scan_report.is_file() else None,
            "prohibited_access_event_count": len(raw_scan.get("prohibited_access_events", [])),
            "prohibited_identifier_acquisition_event_count": len(
                raw_scan.get("prohibited_identifier_acquisition_events", [])
            ),
            "unexpected_online_attack_event_count": len(
                raw_scan.get("unexpected_online_attack_events", [])
            ),
        },
        "interpretation": {
            "actual_research_actions": "established only by retained command/tool/native records and research artifacts",
            "capability_only": "web_search=live enables a possible native action; it is not evidence that an action occurred",
            "missing_stdout": "no native rollout was retained, so unrecorded possible actions cannot be promoted to actual use",
            "non_claim": "no claim about unretained kernel, proxy, firewall, or provider-internal activity",
        },
    }
    (out / "audit.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    summary = [
        "# DOVE source-integrity audit",
        "",
        f"- graph model executions: {len(executions)}",
        f"- invocation directories: {len(invocations)}",
        f"- missing stdout transcripts: {len(report['missing_stdout'])}",
        f"- stale execution outcome: {(stale_exec or {}).get('outcome')}",
        f"- stale actual tool calls: {len(report['stale_actual_tool_calls'])}",
        f"- stale failed grouped calls: {len(report['stale_failed_grouped_calls'])}",
        f"- actual native web items in retained transcripts/rollouts: {len(actual_web_items) + len(native_web_items)}",
        f"- local regex-scan false positives reclassified: {len(false_positive_rows)}",
        f"- retained audit source-role counts: {dict(source_roles)}",
        "",
        "Capability (`web_search=live`) is distinct from a retained actual tool action.",
        "The audit makes no negative claim about unretained kernel, proxy, firewall,",
        "provider-internal, or currently unfinished session activity.",
    ]
    (out / "REPORT.md").write_text("\n".join(summary) + "\n")
    print(json.dumps({
        "ok": True,
        "audit": str(out / "audit.json"),
        "report": str(out / "REPORT.md"),
        "summary": summary,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
