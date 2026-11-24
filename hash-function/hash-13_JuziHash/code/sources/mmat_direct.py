#!/usr/bin/env python3
"""Call the local MMAT tool server directly when the MCP transport is down.

This uses the same ToolServer and role gating as the normal MCP transport; it
does not bypass a tool restriction.
"""

from __future__ import annotations

import json
import os
import sys

from mmat.agent.mcp_server import ToolServer
from mmat.graph.store import Store


DB = (
    "/home/mmat/mmat-preview/campaigns/rebuild-20261119/"
    "runs/rebuild-097-hash-13-ds02/graph.db"
)
NODE = "403010660299066d"
WORKSPACE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("usage: mmat_direct.py TOOL [JSON_ARGS]")
    tool = sys.argv[1]
    args = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    store = Store(DB)
    server = ToolServer(store, NODE, "", "", 1, "orch", WORKSPACE)
    result = server.call(tool, args)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
