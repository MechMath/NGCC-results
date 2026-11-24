#!/usr/bin/env python3
"""Call the official MMAT tool surface in-process when the MCP transport is down."""

import json
import os
import sys

from mmat.agent.mcp_server import ToolServer
from mmat.graph.store import Store


DB = "/home/mmat/mmat-preview/campaigns/rebuild-20261119/runs/rebuild-101-hash-17-ds02/graph.db"
NODE = "57e93509a6cd9816"
DISPATCH = "eda45a90ab4a4111"


def main():
    store = Store(DB)
    server = ToolServer(
        store,
        NODE,
        "",
        DISPATCH,
        1,
        role="prover",
        workspace=os.getcwd(),
        auto_verify=os.environ.get("MMAT_LOCAL_AUTO_VERIFY") == "1",
    )
    request = json.load(sys.stdin)
    result = server.call(request["tool"], request.get("args", {}))
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
