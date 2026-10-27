#!/usr/bin/env python3
"""Read-only bridge to the already-running lab TShark 4.2.2.

Capture paths are opened on the host and streamed to TShark over stdin.  The
container receives no host path and no filesystem mount is added or changed.
"""
import os
import subprocess
import sys

CONTAINER = "oiran-lab-controller-1"

def main() -> int:
    args = sys.argv[1:]
    capture = None
    if "-r" in args:
        index = args.index("-r")
        if index + 1 >= len(args):
            print("missing value for -r", file=sys.stderr)
            return 2
        capture = args[index + 1]
        args[index + 1] = "-"
    command = ["docker", "exec", "-i", CONTAINER, "tshark", *args]
    if capture is None:
        return subprocess.run(command, check=False).returncode
    with open(capture, "rb") as source:
        return subprocess.run(command, stdin=source, check=False).returncode

if __name__ == "__main__":
    raise SystemExit(main())
