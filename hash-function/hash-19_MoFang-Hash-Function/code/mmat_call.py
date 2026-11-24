#!/usr/bin/env python3
"""Call one MMAT MCP tool through the local stdio server."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys


RUN_ROOT = "/home/mmat/mmat-preview/campaigns/rebuild-20261119/runs/rebuild-103-hash-19-ds02"
RELEASE = "/home/mmat/mmat-preview/releases/crypto-rebuild-fa27aa82/MMAT-v2"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("tool")
    parser.add_argument("arguments")
    parser.add_argument("--raw", action="store_true")
    ns = parser.parse_args()

    env = os.environ.copy()
    env.update(
        {
            "PYTHONPATH": RELEASE,
            "MMAT_DB": f"{RUN_ROOT}/graph.db",
            "MMAT_ROLE": "orch",
            "MMAT_PHASE": "1",
            "MMAT_PREVIEW_CONFIG": "/home/mmat/mmat-preview/campaigns/rebuild-20261119/runtime-fa27aa82.json",
            "MMAT_FEATURE_TELEMETRY": "1",
            "MMAT_FEATURE_EXACT_CONTRACTS": "1",
            "MMAT_FEATURE_ANSWER_DELIVERY": "1",
            "MMAT_FEATURE_LAYERED_REVIEW": "1",
            "MMAT_FEATURE_MAIN_RESEARCH": "1",
            "MMAT_FEATURE_RESEARCH_LIVENESS": "1",
            "MMAT_FEATURE_HANDOFF_V2": "1",
            "MMAT_FEATURE_INCREMENTAL_CONTEXT": "1",
            "MMAT_FEATURE_INCREMENTAL_CLEANUP": "1",
        }
    )
    arguments = ns.arguments
    if arguments.startswith("@"):
        with open(arguments[1:], encoding="utf-8") as f:
            arguments = f.read()

    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    call = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": ns.tool,
            "arguments": json.loads(arguments),
        },
    }
    payload = json.dumps(init) + "\n" + json.dumps(call) + "\n"
    proc = subprocess.run(
        ["python3", "-m", "mmat.agent.mcp_server", "--role", "orch", "--phase", "1"],
        input=payload,
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )
    if proc.stderr:
        print(proc.stderr, file=sys.stderr, end="")
    responses = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    response = next((r for r in responses if r.get("id") == 2), None)
    if response is None:
        return 2
    if ns.raw:
        print(json.dumps(response, indent=2, ensure_ascii=False))
        return 0 if "error" not in response else 1
    result = response["result"]
    content = result.get("content") or []
    if content:
        print(content[0].get("text", ""))
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if not result.get("isError") else 1


if __name__ == "__main__":
    raise SystemExit(main())
