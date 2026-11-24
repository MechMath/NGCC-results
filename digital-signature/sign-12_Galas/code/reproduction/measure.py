#!/usr/bin/env python3
"""Measure one local process's wall time, CPU time, and peak RSS."""

import json
import resource
import subprocess
import sys
import time


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: measure.py <executable>")

    started = time.monotonic()
    proc = subprocess.run([sys.argv[1]], capture_output=True, text=True)
    elapsed = time.monotonic() - started
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    print(
        json.dumps(
            {
                "argv": sys.argv[1:],
                "returncode": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "wall_seconds": elapsed,
                "user_seconds": usage.ru_utime,
                "system_seconds": usage.ru_stime,
                "max_rss_bytes_on_linux": usage.ru_maxrss * 1024,
            },
            sort_keys=True,
        )
    )
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
