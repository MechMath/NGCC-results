#!/usr/bin/env python3
"""Fallback caller for the run's MCP tool when the native transport drops."""

import json
import os
import subprocess
import sys


def main() -> int:
    if len(sys.argv) not in (3, 4):
        print("usage: mcp_call.py TOOL 'JSON_ARGS' ['PRE_SEARCH']", file=sys.stderr)
        return 2
    tool, raw_args = sys.argv[1], sys.argv[2]
    args = json.loads(raw_args)
    pre_search = sys.argv[3] if len(sys.argv) == 4 else ""

    env = os.environ.copy()
    env.update(
        {
            "MMAT_DB": "/home/mmat/mmat-preview/campaigns/rebuild-20261119/runs/rebuild-086-hash-02-ds02/graph.db",
            "MMAT_ROLE": "orch",
            "MMAT_PHASE": "1",
            "MMAT_MODEL_LOW": "deepseek-flash",
            "MMAT_MODEL_MID": "deepseek-flash",
            "MMAT_MODEL_HIGH": "deepseek-flash",
            "MMAT_MODEL_ORCH": "deepseek-flash",
            "MMAT_MODEL_VERIFIER": "deepseek-flash",
            "MMAT_EFFORT_LOW": "medium",
            "MMAT_EFFORT_MID": "medium",
            "MMAT_EFFORT_HIGH": "medium",
            "MMAT_EFFORT_ORCH": "medium",
            "MMAT_EFFORT_VERIFIER": "medium",
            "MMAT_PROVIDER_GUARD_DIR": "/home/mmat/mmat-preview/provider-guards",
            "MMAT_PROVIDER_GUARD_ID": "fa0f61746103ec7edbec945323f8e96906330221614ca0b56661bedd27a644c4",
            "PYTHONPATH": "/home/mmat/mmat-preview/releases/crypto-rebuild-fa27aa82/MMAT-v2",
            "MMAT_PREVIEW_CONFIG": "/home/mmat/mmat-preview/campaigns/rebuild-20261119/runtime-fa27aa82.json",
            "MMAT_CODEX_AUTH": "api",
            "MMAT_CODEX_CONFIG": "/home/mmat/.config/mmat-preview/providers/deepseek-official/config.toml",
            "MMAT_FEATURE_TELEMETRY": "1",
            "MMAT_FEATURE_EXACT_CONTRACTS": "1",
            "MMAT_FEATURE_ANSWER_DELIVERY": "1",
            "MMAT_FEATURE_LAYERED_REVIEW": "1",
            "MMAT_FEATURE_MAIN_RESEARCH": "1",
            "MMAT_FEATURE_RESEARCH_LIVENESS": "1",
            "MMAT_FEATURE_HANDOFF_V2": "1",
            "MMAT_FEATURE_INCREMENTAL_CONTEXT": "1",
            "MMAT_FEATURE_INCREMENTAL_CLEANUP": "1",
            "CODEX_HOME": "/home/mmat/.cache/mmat/codex-orch-b809357314cc",
        }
    )
    process = subprocess.Popen(
        ["python3", "-m", "mmat.agent.mcp_server", "--role", "orch", "--phase", "1"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    assert process.stdin is not None
    assert process.stdout is not None

    requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "fallback", "version": "1"},
            },
        }
    ]
    if pre_search:
        requests.append(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "graph_read", "arguments": {"action": "search", "query": pre_search}},
            }
        )
    call_id = 3 if pre_search else 2
    requests.append(
        {
            "jsonrpc": "2.0",
            "id": call_id,
            "method": "tools/call",
            "params": {"name": tool, "arguments": args},
        }
    )
    for request in requests:
        process.stdin.write(json.dumps(request, separators=(",", ":")) + "\n")
    process.stdin.flush()

    response = None
    while True:
        line = process.stdout.readline()
        if not line:
            break
        payload = json.loads(line)
        if payload.get("id") == call_id:
            response = payload
            break

    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()

    if response is None:
        stderr = process.stderr.read() if process.stderr is not None else ""
        print(f"no tool response; stderr:\n{stderr}", file=sys.stderr)
        return 1
    result = response.get("result", response)
    content = result.get("content", []) if isinstance(result, dict) else []
    if content:
        print(content[0].get("text", json.dumps(result, ensure_ascii=False)))
        for extra in content[1:]:
            print(extra.get("text", ""), file=sys.stderr)
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
