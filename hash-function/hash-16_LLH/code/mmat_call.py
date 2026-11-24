#!/usr/bin/env python3
import json
import subprocess
import sys


def main() -> None:
    tool = sys.argv[1]
    arguments = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    process = subprocess.Popen(
        [sys.executable, "-m", "mmat.agent.mcp_server", "--role", "prover", "--phase", "1"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    def send(message: dict) -> None:
        process.stdin.write(json.dumps(message) + "\n")
        process.stdin.flush()

    def receive() -> dict:
        line = process.stdout.readline()
        if not line:
            raise RuntimeError(process.stderr.read())
        return json.loads(line)

    send(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mmat-call", "version": "0"},
            },
        }
    )
    receive()
    send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
    send(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        }
    )
    response = receive()
    process.terminate()
    print(json.dumps(response, indent=2))


if __name__ == "__main__":
    main()
