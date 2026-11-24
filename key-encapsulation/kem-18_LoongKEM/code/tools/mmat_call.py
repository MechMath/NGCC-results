#!/usr/bin/env python3
"""Local transport fallback for the MMAT orchestrator API."""

import json
import os
import sys

from mmat.agent.mcp_server import ToolServer
from mmat.graph.store import Store


ROOT = "/home/mmat/mmat-preview/campaigns/rebuild-20261119/runs/rebuild-052-kem-18-ds01"


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: mmat_call.py TOOL < payload.json")
    store = Store(os.path.join(ROOT, "graph.db"))
    server = ToolServer(
        store,
        "",
        "",
        "",
        1,
        role="orch",
        workspace=os.getcwd(),
        auto_verify=False,
    )
    payload = json.load(sys.stdin)
    result = server.call(sys.argv[1], payload)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
