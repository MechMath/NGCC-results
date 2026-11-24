#!/usr/bin/env python3
"""One-shot stdio client for the local MMAT MCP server after transport loss."""

import argparse
import json
import os
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("tool")
    parser.add_argument("args_file", nargs="?")
    parser.add_argument("--json", dest="inline_json")
    parser.add_argument(
        "--db",
        default="/home/mmat/mmat-preview/campaigns/rebuild-20261119/"
        "runs/rebuild-085-hash-01-ds02/graph.db",
    )
    opts = parser.parse_args()

    if opts.inline_json is not None:
        arguments = json.loads(opts.inline_json)
    elif opts.args_file is not None:
        with open(opts.args_file, encoding="utf-8") as handle:
            arguments = json.load(handle)
    else:
        parser.error("provide args_file or --json")

    env = os.environ.copy()
    env.update(
        {
            "MMAT_DB": opts.db,
            "MMAT_ROLE": "orch",
            "MMAT_PHASE": "1",
            "MMAT_WORKSPACE": os.getcwd(),
            "MMAT_NODE": "",
            "MMAT_ATTEMPT": "",
            "MMAT_DISPATCH": "",
        }
    )
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "mmat.agent.mcp_server",
            "--role",
            "orch",
            "--phase",
            "1",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    assert proc.stdin is not None
    assert proc.stdout is not None

    def request(payload: dict) -> dict:
        proc.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
        proc.stdin.flush()
        line = proc.stdout.readline()
        if not line:
            proc.wait(timeout=5)
            stderr = proc.stderr.read() if proc.stderr is not None else ""
            raise RuntimeError(
                "MMAT MCP server closed without a response"
                + (f":\n{stderr}" if stderr else "")
            )
        return json.loads(line)

    request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    response = request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": opts.tool, "arguments": arguments},
        }
    )
    print(json.dumps(response, ensure_ascii=False, indent=2))
    proc.terminate()
    proc.wait(timeout=5)
    stderr = proc.stderr.read() if proc.stderr is not None else ""
    if stderr:
        print(stderr, file=sys.stderr)
    return 0 if "error" not in response else 1


if __name__ == "__main__":
    raise SystemExit(main())
