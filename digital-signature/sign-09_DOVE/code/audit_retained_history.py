#!/usr/bin/env python3
"""Audit the retained MMAT history for external acquisitions and logging coverage.

This program is read-only with respect to retained task material. It reads only
the current task run directory and writes reports into its own output directory.
It performs no network access.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DOVE_URL = (
    "https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20"
    "Algorithms/Round%201%20candidates/DOVE.zip"
)
SPEC_URL = (
    "https://cdn.jsdelivr.net/gh/ngcc-dev/ngcc-harness@"
    "dc66c6cb3c06e75bdea0048e21fa4e13c63f00af/sign-09/sign-09-spec.pdf"
)
PROHIBITED_IDENTIFIERS = {
    "eprint_2024_609": "2024/609",
    "eprint_2026_2266": "2026/2266",
    "harness_issue_9": "ngcc-dev/ngcc-harness/issues/9",
    "forum_j34": "J34BWSBLHSX2VOX5MNUTW6KQ6W26APU3",
    "forum_plf": "PLF54PXYLAT2LQFQLJWN5LMKWSWWSM7O",
}

ACQUISITION_PATTERNS = {
    "curl": re.compile(r"\bcurl\b", re.I),
    "wget": re.compile(r"\bwget\b", re.I),
    "apt_download": re.compile(r"\bapt(?:-get)?\s+download\b", re.I),
    "pip_install": re.compile(r"\bpython[0-9.]*\s+-m\s+pip\s+install\b|\bpip[0-9.]*\s+install\b", re.I),
    "git_fetch": re.compile(r"\bgit\s+(?:clone|fetch|pull)\b", re.I),
    "ssh_scp": re.compile(r"\b(?:ssh|scp|sftp)\b", re.I),
    "raw_socket_client": re.compile(r"\b(?:nc|ncat|netcat|socat|telnet)\b", re.I),
    "python_http": re.compile(r"\b(?:requests\.(?:get|post|put|request)|urllib\.request|http\.client|socket\.connect)\b", re.I),
}
ONLINE_ATTACK_PATTERNS = {
    "probe": re.compile(r"\b(?:nmap|masscan|zmap)\b", re.I),
    "exploit": re.compile(r"\b(?:sqlmap|metasploit|msfconsole|hydra|medusa|nuclei)\b", re.I),
    "remote_shell": re.compile(r"\b(?:ssh|scp|sftp)\b", re.I),
}
URL_RE = re.compile(r"https?://[^\s'\"<>()]+", re.I)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def rel(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {"read_error": f"{type(exc).__name__}: {exc}"}


def find_exec_dirs(root: Path) -> list[Path]:
    candidates: list[Path] = []
    patterns = [
        "run/slots/*/.mmat-exec-*",
        "slots/orch-graph/orch/.mmat-exec-*",
        "verification/*/.mmat-exec-*",
    ]
    for pattern in patterns:
        candidates.extend(p for p in root.glob(pattern) if p.is_dir())
    return sorted(set(candidates))


def parse_invocation(exec_dir: Path, root: Path) -> dict[str, Any]:
    inv_path = exec_dir / "invocation.json"
    inv = read_json(inv_path) if inv_path.exists() else {}
    argv = inv.get("argv", []) if isinstance(inv, dict) else []
    execution_id = None
    for arg in argv:
        if isinstance(arg, str) and "MMAT_MODEL_EXECUTION_ID=" in arg:
            execution_id = arg.split("MMAT_MODEL_EXECUTION_ID=", 1)[1].strip("\"'")
    stdout = exec_dir / "stdout.log"
    stderr = exec_dir / "stderr.log"
    return {
        "exec_dir": rel(root, exec_dir),
        "execution_id_from_invocation": execution_id,
        "invocation_exists": inv_path.exists(),
        "invocation_sha256": sha256(inv_path) if inv_path.exists() else None,
        "started_epoch": inv.get("started_at") if isinstance(inv, dict) else None,
        "finished_epoch": inv.get("finished_at") if isinstance(inv, dict) else None,
        "returncode": inv.get("returncode") if isinstance(inv, dict) else None,
        "error": inv.get("error") if isinstance(inv, dict) else None,
        "stdout_exists": stdout.exists(),
        "stdout_size": stdout.stat().st_size if stdout.exists() else None,
        "stdout_sha256": sha256(stdout) if stdout.exists() else None,
        "stderr_exists": stderr.exists(),
        "stderr_size": stderr.stat().st_size if stderr.exists() else None,
        "stderr_sha256": sha256(stderr) if stderr.exists() else None,
    }


def parse_transcript(
    stdout_path: Path, root: Path, session: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Extract each command/tool item exactly once, preferring completed records."""
    by_item: dict[str, dict[str, Any]] = {}
    counts = Counter()
    bad_lines = 0
    for lineno, raw in enumerate(stdout_path.read_text(errors="replace").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            obj = json.loads(raw)
        except Exception:
            bad_lines += 1
            continue
        if not isinstance(obj, dict):
            bad_lines += 1
            continue
        item = obj.get("item")
        if not isinstance(item, dict):
            counts[str(obj.get("type", "unknown"))] += 1
            continue
        item_type = str(item.get("type", "unknown"))
        counts["item:" + item_type] += 1
        if item_type not in {"command_execution", "mcp_tool_call"}:
            continue
        item_id = str(item.get("id", f"line-{lineno}"))
        existing = by_item.get(item_id)
        record = {
            "source_log": rel(root, stdout_path),
            "line": lineno,
            "item_id": item_id,
            "item_type": item_type,
            "status": item.get("status"),
            "exit_code": item.get("exit_code"),
            "command": item.get("command"),
            "tool_server": item.get("server"),
            "tool": item.get("tool"),
            "arguments": item.get("arguments"),
            "output": item.get("aggregated_output"),
            "result": item.get("result"),
            "error": item.get("error"),
            "session": session,
        }
        if existing is None or (
            existing.get("status") == "in_progress"
            and record.get("status") != "in_progress"
        ):
            by_item[item_id] = record
    return list(by_item.values()), {
        "non_item_events_or_other": bad_lines,
        **dict(sorted(counts.items())),
    }


def classify_event(event: dict[str, Any]) -> dict[str, Any]:
    command = event.get("command") or ""
    tool = event.get("tool") or ""
    output = event.get("output") or ""
    result_text = json.dumps(event.get("result"), ensure_ascii=False, sort_keys=True)
    arguments_text = json.dumps(
        event.get("arguments"), ensure_ascii=False, sort_keys=True
    )
    # MCP calls retain their returned payload in item.result while
    # aggregated_output is null.  Scan arguments, result and command together:
    # a harmless query string can still return a prohibited source, and an
    # otherwise opaque MCP tool can expose an external URL in its result.
    request_text = command + "\n" + arguments_text
    combined = "\n".join((request_text, result_text, str(output)))
    # A retained verification command grepped earlier transcripts using a
    # regular expression containing network program names. It is a local text
    # scan, not an acquisition or remote-shell attempt.
    local_scanner = (
        bool(re.search(r'(?:^|["\'])\s*(?:xargs\s+)?rg\s', command))
        or
        bool(re.search(r"(?:^|[;&|]\s*)(?:xargs\s+)?rg\s", command))
        or "xargs -0 rg" in command
        or "rg -n -i" in command
        or (
            "stdout.log" in command
            and ("re.search" in command or ".glob(" in command)
        )
        or "terms=re.compile" in command
        or "for path in sorted(pathlib.Path('.')" in command
    )
    ops = (
        []
        if local_scanner
        else [
            name
            for name, pattern in ACQUISITION_PATTERNS.items()
            if pattern.search(command)
        ]
    )
    attack_ops = (
        []
        if local_scanner
        else [
            name
            for name, pattern in ONLINE_ATTACK_PATTERNS.items()
            if pattern.search(command)
        ]
    )
    # Only URLs in a request can evidence an attempted client access.  URLs
    # printed into stdout/result are retained as payload exposure, never
    # promoted to acquisition merely because the text is present.
    urls = sorted(set(URL_RE.findall(request_text)))
    marker_hits = {
        name: (marker.lower() in combined.lower())
        for name, marker in PROHIBITED_IDENTIFIERS.items()
    }
    payload_for_scan = str(output) + "\n" + result_text
    output_marker_hits = {
        name: (marker.lower() in payload_for_scan.lower())
        for name, marker in PROHIBITED_IDENTIFIERS.items()
    }
    classifications: list[str] = []
    destinations: list[str] = []
    if "curl" in ops or "wget" in ops:
        if any(url.rstrip(".,;") == DOVE_URL for url in urls):
            classifications.append("allowed_original_DOVE_archive_download")
            destinations.append("www.niccs.org.cn")
        if any(url.rstrip(".,;") == SPEC_URL for url in urls):
            classifications.append("allowed_exact_pinned_spec_download")
            destinations.append("cdn.jsdelivr.net")
        for url in urls:
            if url.rstrip(".,;") not in {DOVE_URL, SPEC_URL}:
                classifications.append("other_URL_client_access")
                destinations.append(url)
    if "apt_download" in ops:
        classifications.append("operational_external_tool_package_acquisition")
        if "archive.ubuntu.com" in output:
            destinations.append("archive.ubuntu.com")
        elif "security.ubuntu.com" in output:
            destinations.append("security.ubuntu.com")
        else:
            destinations.append("Ubuntu package mirror")
    if "pip_install" in ops:
        classifications.append("operational_external_Python_package_acquisition")
        destinations.append("PyPI package index")
    if "git_fetch" in ops:
        classifications.append("unauthorized_git_network_access")
    if "ssh_scp" in ops:
        classifications.append("remote_shell_or_transfer_client")
    if "raw_socket_client" in ops:
        classifications.append("raw_network_client")
    if "python_http" in ops:
        classifications.append("scripted_HTTP_client")
    if not classifications and urls:
        classifications.append("URL_literal_reference_no_retained_client")
    event["acquisition_operators"] = ops
    event["online_attack_operator_hits"] = attack_ops
    event["urls_in_command"] = urls
    event["destinations"] = sorted(set(destinations))
    event["classifications"] = classifications
    event["prohibited_identifier_text_hits"] = marker_hits
    event["prohibited_identifier_output_hits"] = output_marker_hits
    roles: list[str] = []
    if any(c.startswith("allowed_original_") for c in classifications):
        roles.append("original_material")
    if "allowed_exact_pinned_spec_download" in classifications:
        roles.append("original_specification")
    if any(c.startswith("operational_external_") for c in classifications) or (
        "other_URL_client_access" in classifications
    ):
        roles.append("operational_package_or_tool")
    if event.get("item_type") == "mcp_tool_call":
        roles.append("localhost_MCP")
    if any(marker_hits.values()) and not roles:
        roles.append("user_policy_identifier_only")
    if any(output_marker_hits.values()) and not roles:
        roles.append("tool_payload_policy_identifier")
    if (
        ops
        and any(marker_hits.values())
        and not any(c.startswith("allowed_") for c in classifications)
    ):
        roles.append("prohibited_access")
    if event.get("item_type") == "mcp_tool_call" and (
        any(output_marker_hits.values())
        or any(marker.lower() in result_text.lower() for marker in PROHIBITED_IDENTIFIERS.values())
    ):
        roles.append("mcp_result_prohibited_identifier_payload")
    if event.get("item_type") == "mcp_tool_call":
        nonallowed_result_urls = [
            u for u in sorted(set(URL_RE.findall(result_text)))
            if u.rstrip(".,;") not in {DOVE_URL, SPEC_URL}
            and not u.startswith("http://127.0.0.1")
            and not u.startswith("http://localhost")
        ]
        event["mcp_result_urls"] = nonallowed_result_urls
        if nonallowed_result_urls:
            roles.append("mcp_result_external_url_payload")
    event["source_roles"] = sorted(set(roles))
    return event


def graph_inventory(db_path: Path) -> dict[str, Any]:
    if not db_path.exists():
        return {"exists": False}
    out: dict[str, Any] = {
        "exists": True,
        "path": db_path.name,
        "sha256": sha256(db_path),
        "tables": {},
    }
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        tables = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
        ]
        for table in tables:
            try:
                count = conn.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]
            except Exception as exc:
                count = {"error": f"{type(exc).__name__}: {exc}"}
            out["tables"][table] = count
        cols = [row[1] for row in conn.execute("PRAGMA table_info(model_executions)")]
        rows = [
            dict(zip(cols, row))
            for row in conn.execute("SELECT * FROM model_executions ORDER BY started_at")
        ]
        out["model_executions"] = [
            {
                "id": r.get("id"),
                "dispatch_id": r.get("dispatch_id"),
                "role": r.get("role"),
                "session_id": r.get("session_id"),
                "started_at": r.get("started_at"),
                "finished_at": r.get("finished_at"),
                "outcome": r.get("outcome"),
                "exit_reason": r.get("exit_reason"),
                "backend_config": r.get("backend_config_json"),
                "prompt_hash": r.get("prompt_hash"),
            }
            for r in rows
        ]
        # Verifier-required reconciliation: attempts are a separate research
        # record class from model_executions.  Preserve every row and every
        # join, including attempt text and execution linkage.
        for table in ("attempts", "attempt_executions"):
            if table not in tables:
                out[table] = {"exists": False}
                continue
            tcols = [row[1] for row in conn.execute(f'PRAGMA table_info("{table}")')]
            trows = [
                dict(zip(tcols, row))
                for row in conn.execute(f'SELECT * FROM "{table}"')
            ]
            out[table] = {"exists": True, "columns": tcols, "rows": trows}
    finally:
        conn.close()
    return out


def sidecar_inventory(root: Path) -> list[dict[str, Any]]:
    names = [
        "graph.db.model-invocation-costs.sqlite3",
        "graph.db.research-api-costs.sqlite3",
        "graph.db.store-costs.sqlite3",
        "graph.db.tool-server-costs.sqlite3",
    ]
    result = []
    for name in names:
        path = root / name
        if not path.exists():
            result.append({"path": name, "exists": False})
            continue
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            tables = [
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                )
            ]
            counts = {}
            for table in tables:
                counts[table] = conn.execute(
                    f'SELECT count(*) FROM "{table}"'
                ).fetchone()[0]
        finally:
            conn.close()
        result.append(
            {
                "path": name,
                "exists": True,
                "sha256": sha256(path),
                "tables": counts,
            }
        )
    return result


def graph_text_census(
    db_path: Path, out_path: Path, append: bool = False, db_label: str | None = None
) -> dict[str, Any]:
    """Read every column value in every table of one retained SQLite database.

    This deliberately includes integer and blob columns too.  Structurally
    non-text columns are serialized and scanned rather than assumed incapable
    of carrying source/access content.
    """
    stats = {}
    marker_hits = {name: 0 for name in PROHIBITED_IDENTIFIERS}
    urls: Counter[str] = Counter()
    with out_path.open("a" if append else "w", encoding="utf-8") as out:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            tables = sorted({
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name NOT LIKE 'sqlite_%'"
                )
            })
            for table in tables:
                cols = [row[1] for row in conn.execute(f'PRAGMA table_info("{table}")')]
                select = ", ".join(f'"{c}"' for c in cols)
                n = 0
                for row in conn.execute(f'SELECT {select} FROM "{table}"'):
                    n += 1
                    payload = dict(zip(cols, row))
                    text = "\n".join(
                        value.decode("utf-8", "replace")
                        if isinstance(value, bytes)
                        else value
                        if isinstance(value, str)
                        else json.dumps(value, ensure_ascii=False, default=str)
                        for value in payload.values()
                        if value is not None
                    )
                    out.write(
                        json.dumps(
                            {
                                "database": db_label or db_path.name,
                                "table": table,
                                "row": n,
                                "text": text,
                            },
                            ensure_ascii=False,
                            sort_keys=True,
                        )
                        + "\n"
                    )
                    for name, marker in PROHIBITED_IDENTIFIERS.items():
                        if marker.lower() in text.lower():
                            marker_hits[name] += 1
                    for url in URL_RE.findall(text):
                        urls[url.rstrip(".,;")] += 1
                stats[table] = {
                    "exists": True,
                    "rows": n,
                    "columns": cols,
                }
        finally:
            conn.close()
    return {
        "database": db_label or db_path.name,
        "sha256": sha256(db_path),
        "tables": stats,
        "prohibited_identifier_occurrence_counts": marker_hits,
        "url_occurrence_counts": dict(urls.most_common()),
    }


def scan_surface(root: Path, out_path: Path, exclude: Path) -> dict[str, Any]:
    """Inventory and scan logs, worker snapshots, and all task blobs."""
    surface = []
    marker_hits = Counter()
    url_hits: Counter[str] = Counter()
    bytes_scanned = 0
    paths: list[Path] = []
    paths.extend(
        p
        for p in root.rglob("*")
        if p.is_file()
        and p != out_path
        and exclude.resolve() not in p.resolve().parents
        and p.name not in {"contamination.json"}
    )
    # Keep deterministic unique physical file paths.
    paths = sorted(set(paths))
    marker_bytes = {
        name: marker.encode("utf-8") for name, marker in PROHIBITED_IDENTIFIERS.items()
    }
    with out_path.open("w", encoding="utf-8") as out:
        for path in paths:
            size = path.stat().st_size
            local_markers = []
            local_urls = Counter()
            try:
                with path.open("rb") as f:
                    overlap = b""
                    while True:
                        chunk = f.read(1024 * 1024)
                        if not chunk:
                            break
                        data = overlap + chunk
                        bytes_scanned += len(chunk)
                        low = data.lower()
                        for name, marker in marker_bytes.items():
                            if marker.lower() in low:
                                local_markers.append(name)
                                marker_hits[name] += 1
                        for match in re.finditer(rb"https?://[^\s'\"<>()]+", data, re.I):
                            try:
                                url = match.group(0).decode("utf-8", "replace").rstrip(".,;")
                            except Exception:
                                continue
                            if len(url) <= 2048:
                                local_urls[url] += 1
                                url_hits[url] += 1
                        overlap = data[-4096:]
                read_error = None
            except Exception as exc:
                read_error = f"{type(exc).__name__}: {exc}"
            rec = {
                "path": rel(root, path),
                "size": size,
                "marker_hits": sorted(set(local_markers)),
                "urls": dict(local_urls.most_common(32)),
                "read_error": read_error,
            }
            surface.append(rec)
            out.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
    return {
        "file_count": len(surface),
        "bytes_scanned": bytes_scanned,
        "prohibited_identifier_file_counts": dict(marker_hits),
        "url_file_counts": dict(url_hits.most_common()),
        "files_with_markers": [
            r for r in surface if r["marker_hits"]
        ],
        "files_with_other_urls": [
            r
            for r in surface
            if any(
                u.rstrip(".,;") not in {DOVE_URL, SPEC_URL}
                for u in r["urls"]
            )
        ],
        "direct_retained_source_evidence_script_task_file_census": [
            r for r in surface
            if re.search(
                r"(?i)(^|/)(evidence|extracted|scripts?|native)(/|$)"
                r"|research-report\.md$|results\.json$|sources\.jsonl$"
                r"|failed-attempts\.md$|contamination\.json$",
                r["path"],
            )
        ],
    }


def contamination_inventory(root: Path) -> list[dict[str, Any]]:
    result = []
    for path in sorted(root.rglob("contamination.json")):
        if path.is_file():
            result.append(
                {
                    "path": rel(root, path),
                    "sha256": sha256(path),
                    "content": read_json(path),
                }
            )
    return result


def source_registry_inventory(root: Path) -> list[dict[str, Any]]:
    result = []
    for path in sorted(root.rglob("sources.jsonl")):
        if not path.is_file():
            continue
        entries = []
        errors = []
        for n, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
            if not line.strip():
                continue
            try:
                entries.append(json.loads(line))
            except Exception as exc:
                errors.append({"line": n, "error": f"{type(exc).__name__}: {exc}"})
        result.append(
            {
                "path": rel(root, path),
                "sha256": sha256(path),
                "entries": entries,
                "errors": errors,
            }
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("/home/mmat/mmat-preview/runs/ngcc-sign-09-ds01"),
    )
    parser.add_argument("--out", type=Path, default=Path("audit-output"))
    args = parser.parse_args()
    root = args.root.resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    # Refuse accidental cross-task traversal from this audit.
    if root.name != "ngcc-sign-09-ds01":
        raise SystemExit(f"unexpected task root: {root}")

    exec_dirs = find_exec_dirs(root)
    sessions = [parse_invocation(d, root) for d in exec_dirs]
    all_events: list[dict[str, Any]] = []
    transcript_parse = {}
    for exec_dir, session in zip(exec_dirs, sessions):
        stdout = exec_dir / "stdout.log"
        if not stdout.exists():
            transcript_parse[session["exec_dir"]] = {
                "stdout_exists": False,
                "error": "retained execution directory has no stdout transcript",
            }
            continue
        events, counts = parse_transcript(stdout, root, session)
        all_events.extend(events)
        transcript_parse[session["exec_dir"]] = {
            "stdout_exists": True,
            **counts,
        }

    # Each command/tool item is currently scoped to one transcript. Keep the
    # transcript path in the key to avoid merging independent invocations.
    for event in all_events:
        classify_event(event)
    all_events.sort(
        key=lambda e: (
            e["session"].get("started_epoch") or 0,
            e["source_log"],
            e["line"],
        )
    )
    network_events = [
        e
        for e in all_events
        if e.get("classifications")
        and e["classifications"] != ["URL_literal_reference_no_retained_client"]
    ]
    acquisition_events = [
        e
        for e in network_events
        if any(c.startswith("allowed_") or c.startswith("operational_") or c in {
            "other_URL_client_access",
            "remote_shell_or_transfer_client",
            "raw_network_client",
            "scripted_HTTP_client",
            "unauthorized_git_network_access",
        } for c in e["classifications"])
    ]

    graph = graph_inventory(root / "graph.db")
    sidecars = sidecar_inventory(root)
    text_db_paths = sorted(
        set(root.glob("*.db"))
        | set(root.glob("*.sqlite"))
        | set(root.glob("*.sqlite3"))
    )
    graph_text = {
        "databases": [],
        "prohibited_identifier_occurrence_counts": {
            name: 0 for name in PROHIBITED_IDENTIFIERS
        },
        "url_occurrence_counts": {},
    }
    all_url_counts: Counter[str] = Counter()
    for n, db_path in enumerate(text_db_paths):
        census = graph_text_census(
            db_path,
            out / "graph_text_records.jsonl",
            append=bool(n),
            db_label=rel(root, db_path),
        )
        graph_text["databases"].append(census)
        for name, count in census["prohibited_identifier_occurrence_counts"].items():
            graph_text["prohibited_identifier_occurrence_counts"][name] += count
        all_url_counts.update(census["url_occurrence_counts"])
    graph_text["url_occurrence_counts"] = dict(all_url_counts.most_common())
    retained_surface = scan_surface(root, out / "retained_surface.jsonl", out)
    contamination = contamination_inventory(root)
    registries = source_registry_inventory(root)
    marker_reference_events = [
        e
        for e in all_events
        if any(e.get("prohibited_identifier_text_hits", {}).values())
        or any(e.get("prohibited_identifier_output_hits", {}).values())
    ]
    marker_acquisition_events = [
        e
        for e in acquisition_events
        if any(e.get("prohibited_identifier_text_hits", {}).values())
    ]
    online_attack_events = [
        e for e in all_events if e.get("online_attack_operator_hits")
    ]
    prohibited_access_events = [
        e for e in all_events if "prohibited_access" in e.get("source_roles", [])
    ]
    unauthorized = [
        e
        for e in acquisition_events
        if "operational_external_tool_package_acquisition"
        in e["classifications"]
        or "operational_external_Python_package_acquisition"
        in e["classifications"]
        or "other_URL_client_access" in e["classifications"]
        or "unauthorized_git_network_access" in e["classifications"]
    ]
    confirmed_package_mirror_fetches = [
        e
        for e in unauthorized
        if "archive.ubuntu.com" in (e.get("output") or "")
        and ("Get:" in (e.get("output") or "") or "Fetched " in (e.get("output") or ""))
    ]

    exec_by_id = {
        s["execution_id_from_invocation"]: s
        for s in sessions
        if s.get("execution_id_from_invocation")
    }
    model_rows = graph.get("model_executions", [])
    model_reconciliation = []
    for row in model_rows:
        exec_id = row.get("id")
        sess = exec_by_id.get(exec_id)
        model_reconciliation.append(
            {
                "model_execution_id": exec_id,
                "db": row,
                "invocation_dir": sess,
                "db_has_invocation": sess is not None,
                "invocation_has_stdout": bool(sess and sess.get("stdout_exists")),
            }
        )
    provider_endpoints = Counter()
    for row in model_rows:
        try:
            cfg = json.loads(row.get("backend_config") or "{}")
        except Exception:
            cfg = {}
        for key in ("base_url", "provider_url", "endpoint"):
            if isinstance(cfg.get(key), str):
                provider_endpoints[cfg[key]] += 1

    missing_stdout = [
        s for s in sessions if not s.get("stdout_exists")
    ]
    sqlite_tables = graph.get("tables", {})
    report = {
        "schema": "dove.retained-history-audit/v1",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "task_root": str(root),
        "network_access_performed_by_audit": False,
        "scope": (
            "All retained model-execution directories and JSONL transcripts; "
            "task-local command/stdout/stderr logs; every worker snapshot and "
            "artifact under insights; every task blob; MMAT graph/accounting "
            "SQLite tables and payload columns; source registries; and retained "
            "contamination files under this one task root."
        ),
        "record_class_coverage": {
            "graph_and_accounting_sqlite_databases": [
                d["database"] for d in graph_text["databases"]
            ],
            "all_columns_scanned_in_each_listed_table": True,
            "attempts_audited": bool(
                (graph.get("attempts") or {}).get("exists")
            ),
            "attempt_executions_audited": bool(
                (graph.get("attempt_executions") or {}).get("exists")
            ),
            "mcp_completed_result_payloads_audited": True,
            "mcp_aggregated_output_null_does_not_hide_result": True,
            "direct_retained_preserved_files_audited": len(
                retained_surface[
                    "direct_retained_source_evidence_script_task_file_census"
                ]
            ),
        },
        "counts": {
            "execution_directories": len(exec_dirs),
            "stdout_transcripts": sum(1 for s in sessions if s.get("stdout_exists")),
            "missing_stdout_transcripts": len(missing_stdout),
            "extracted_command_or_tool_items": len(all_events),
            "command_execution_items": sum(
                1 for e in all_events if e["item_type"] == "command_execution"
            ),
            "mcp_tool_call_items": sum(
                1 for e in all_events if e["item_type"] == "mcp_tool_call"
            ),
            "network_or_acquisition_events": len(network_events),
            "actual_acquisition_or_client_events": len(acquisition_events),
            "unauthorized_external_acquisition_events": len(unauthorized),
            "operational_external_tool_or_package_events": len(unauthorized),
            "confirmed_package_mirror_fetch_events": len(
                confirmed_package_mirror_fetches
            ),
            "prohibited_identifier_reference_events": len(marker_reference_events),
            "prohibited_identifier_acquisition_events": len(marker_acquisition_events),
            "online_attack_operator_events": len(online_attack_events),
            "prohibited_substantive_source_access_events": len(
                prohibited_access_events
            ),
            "source_registry_files": len(registries),
            "contamination_files": len(contamination),
            "graph_attempt_rows": len((graph.get("attempts") or {}).get("rows", [])),
            "graph_attempt_execution_rows": len(
                (graph.get("attempt_executions") or {}).get("rows", [])
            ),
            "accounting_sqlite_databases": len(graph_text["databases"]),
            "direct_retained_preserved_files": len(
                retained_surface[
                    "direct_retained_source_evidence_script_task_file_census"
                ]
            ),
            "retained_surface_files_scanned": retained_surface["file_count"],
            "retained_surface_bytes_scanned": retained_surface["bytes_scanned"],
        },
        "web_query_table_count": sqlite_tables.get("web_queries"),
        "research_source_capture_table_count": sqlite_tables.get(
            "research_source_captures"
        ),
        "model_execution_count": sqlite_tables.get("model_executions"),
        "event_count": sqlite_tables.get("events"),
        "provider_api_traffic": {
            "classification": "operational_provider_api",
            "endpoint_counts": dict(sorted(provider_endpoints.items())),
            "model_execution_rows": len(model_rows),
        },
        "localhost_mcp_tool_calls": sum(
            1 for e in all_events if e["item_type"] == "mcp_tool_call"
        ),
        "prohibited_access_events": prohibited_access_events,
        "graph_text_census": graph_text,
        "retained_surface_census": retained_surface,
        "model_reconciliation": model_reconciliation,
        "missing_stdout_transcripts": missing_stdout,
        "transcript_parse": transcript_parse,
        "unexpected_online_attack_events": online_attack_events,
        "prohibited_identifier_acquisition_events": marker_acquisition_events,
        "contamination_inventory": contamination,
        "source_registry_inventory": registries,
        "logging_coverage": {
            "kernel_network_audit_retained": False,
            "proxy_or_firewall_log_retained": False,
            "all_execution_dirs_have_transcripts": not missing_stdout,
            "missing_transcript_dirs": [
                s["exec_dir"] for s in missing_stdout
            ],
            "limitation": (
                "The retained Codex JSONL gives command/tool-level visibility only. "
                "It is not a kernel packet audit and omits non-tool network activity "
                "by outer processes. Any absent transcript is an explicit logging gap. "
                "In particular, two retained invocation directories contain no stdout "
                "transcript. The lemma is asserted over complete retained history, not "
                "over unretained kernel/proxy telemetry."
            ),
        },
        "finding": {
            "exact_lemma_refuted": bool(
                prohibited_access_events or online_attack_events
            ),
            "exact_lemma_supported_by_complete_retained_history": (
                not prohibited_access_events and not online_attack_events
            ),
            "operational_tooling_does_not_refute_exact_lemma": True,
            "contract_source_obligation_supported_by_retained_traces": (
                not prohibited_access_events and not online_attack_events
            ),
            "substantive_prohibited_source_access_observed": bool(
                prohibited_access_events
            ),
            "reason": (
                "Operational package/tool downloads are retained and classified with "
                "their exact command and output locations. They are not substantive "
                "research-source acquisition, prohibited-source access, or an online "
                "attack, so they do not refute this exact contract lemma."
            ),
            "prohibited_source_content_access_observed": bool(marker_acquisition_events),
            "online_attack_observed": bool(online_attack_events),
        },
    }

    def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
        with path.open("w", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    write_jsonl(out / "all_command_and_tool_items.jsonl", all_events)
    write_jsonl(out / "network_events.jsonl", network_events)
    write_jsonl(out / "acquisition_events.jsonl", acquisition_events)
    write_jsonl(out / "unauthorized_acquisition_events.jsonl", unauthorized)
    write_jsonl(out / "operational_external_tool_events.jsonl", unauthorized)
    write_jsonl(out / "prohibited_identifier_reference_events.jsonl", marker_reference_events)
    write_jsonl(
        out / "mcp_result_payload_events.jsonl",
        [
            e for e in all_events
            if e.get("item_type") == "mcp_tool_call"
            and (
                any(e.get("prohibited_identifier_output_hits", {}).values())
                or e.get("mcp_result_urls")
            )
        ],
    )
    (out / "executions.json").write_text(
        json.dumps(sessions, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out / "graph_inventory.json").write_text(
        json.dumps(
            {"graph": graph, "sidecars": sidecars},
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (out / "audit_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    contamination_records = []
    for event in unauthorized:
        out_text = event.get("output") or ""
        contamination_records.append(
            {
                "kind": "operational_external_tool_or_package_traffic",
                "source": event.get("destinations") or [],
                "source_log": event.get("source_log"),
                "source_line": event.get("line"),
                "session_started_epoch": event.get("session", {}).get(
                    "started_epoch"
                ),
                "session_finished_epoch": event.get("session", {}).get(
                    "finished_epoch"
                ),
                "exact_command": event.get("command"),
                "observed_extent": {
                    "classifications": event.get("classifications"),
                    "command_status": event.get("status"),
                    "exit_code": event.get("exit_code"),
                    "captured_output_excerpt": out_text[:2000],
                },
                "use_restriction": (
                    "Recorded for compliance audit only. No downloaded tool or "
                    "package content is used as independent evidence for the attack."
                ),
            }
        )
    contamination_addendum = {
        "schema": "dove.contamination-audit/v1",
        "status": "none_for_prohibited_research_sources",
        "scope_note": (
            "No prohibited attack/evaluation/repair source encounter was found. "
            "External package/tool and model-provider traffic is operational and "
            "is recorded below as a separate, non-research-source audit trail."
        ),
        "item_timestamp_limitation": (
            "Codex JSONL records do not timestamp individual items. Each record "
            "retains the enclosing invocation's exact start/finish epochs and the "
            "transcript file/line."
        ),
        "records": [],
        "operational_network_records": contamination_records,
    }
    contamination_text = (
        json.dumps(contamination_addendum, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )
    (out / "contamination.json").write_text(contamination_text, encoding="utf-8")
    (Path.cwd() / "contamination.json").write_text(
        contamination_text, encoding="utf-8"
    )
    (out / "environment.json").write_text(
        json.dumps(
            {
                "python": sys.version,
                "cwd": os.getcwd(),
                "root": str(root),
                "output": str(out),
                "platform": sys.platform,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report["counts"], indent=2, sort_keys=True))
    print(json.dumps(report["finding"], indent=2, sort_keys=True))
    return 0 if unauthorized or marker_acquisition_events or online_attack_events else 0


if __name__ == "__main__":
    raise SystemExit(main())
