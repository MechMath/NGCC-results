#!/usr/bin/env python3
"""Fail closed unless the retained-history audit covers every promised class."""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
report = json.loads((HERE / "audit-output/audit_report.json").read_text())
errors: list[str] = []

def check(ok: bool, message: str) -> None:
    print(("PASS " if ok else "FAIL ") + message)
    if not ok:
        errors.append(message)

counts = report["counts"]
coverage = report["record_class_coverage"]
finding = report["finding"]
logging = report["logging_coverage"]

check(counts["graph_attempt_rows"] > 0, "graph attempts enumerated")
check(counts["graph_attempt_execution_rows"] > 0, "attempt_executions enumerated")
check(coverage["attempts_audited"], "attempts columns/files audited")
check(coverage["attempt_executions_audited"], "attempt_executions columns/files audited")
check(coverage["all_columns_scanned_in_each_listed_table"], "all columns in every listed database table scanned")
check(len(coverage["graph_and_accounting_sqlite_databases"]) == 5, "graph and four accounting databases audited")
check(coverage["mcp_completed_result_payloads_audited"], "completed MCP result payloads audited")
check(counts["direct_retained_preserved_files"] > 0, "direct retained source/evidence/script/task files inventoried")
check(not finding["exact_lemma_refuted"], "operational tooling does not refute exact contract lemma")
check(finding["exact_lemma_supported_by_complete_retained_history"], "exact retained-history lemma supported")
check(not finding["substantive_prohibited_source_access_observed"], "no prohibited substantive source access observed")
check(not finding["prohibited_source_content_access_observed"], "no prohibited content access observed")
check(not finding["online_attack_observed"], "no online attack observed")
check(not logging["kernel_network_audit_retained"], "kernel telemetry limitation explicit")
check(not logging["proxy_or_firewall_log_retained"], "proxy/firewall limitation explicit")
check(
    set(logging["missing_transcript_dirs"])
    == {
        "run/slots/c12d636c8dd64d98/.mmat-exec-z5xf60tk",
        "verification/review_182098f5f35870ccb82327553c8b9a663e3ccfee0b7c829ed8315226760f998b/.mmat-exec-6g4d22_6",
    },
    "both missing-transcript paths explicit",
)

registries = report["source_registry_inventory"]
text = json.dumps(registries, sort_keys=True)
check(
    "19169e545f6a6fd90b844b0deb72db81b5eb73c136873d1dae113c2c39d1c6e0" in text,
    "retained source registries contain exact DOVE ZIP hash",
)
check(
    "c76b7b8263ef94e17b9c1821b6d8087cb3125b493ce655b4eddbabfa5f19e729" in text,
    "retained source registries contain exact pinned PDF hash",
)

surface_rows = [
    json.loads(line)
    for line in (HERE / "audit-output/retained_surface.jsonl").read_text().splitlines()
    if line.strip()
]
check(
    all(row.get("read_error") is None for row in surface_rows),
    "every retained surface file was readable",
)
mcp_payload_rows = [
    json.loads(line)
    for line in (HERE / "audit-output/mcp_result_payload_events.jsonl").read_text().splitlines()
    if line.strip()
]
check(
    all(row.get("item_type") == "mcp_tool_call" for row in mcp_payload_rows),
    "result-payload index contains only MCP tool calls",
)
network_rows = [
    json.loads(line)
    for line in (HERE / "audit-output/network_events.jsonl").read_text().splitlines()
    if line.strip()
]
roles = {role for row in network_rows for role in row.get("source_roles", [])}
check("prohibited_access" not in roles, "network inventory contains no prohibited-access role")
check(
    roles <= {
        "original_material",
        "original_specification",
        "operational_package_or_tool",
        "localhost_MCP",
    },
    "every external operation has a non-research or exact-original-source role",
)

if errors:
    print(f"\n{len(errors)} check(s) failed", file=sys.stderr)
    raise SystemExit(1)
print("\nall checks passed")
