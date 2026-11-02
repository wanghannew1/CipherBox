"""CipherBox launcher: thin client for .cbx file association / double-click.

Never decrypts locally (plan todo 14): forwards one open request to the
resident agent over the named pipe and exits with the response.  If the pipe
is absent the launcher starts the resident agent detached, waits bounded
(<=10s, the ONE sanctioned poll), retries once, then fails loudly.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from agent.ipc import PIPE_NAME, PipeError, connect_and_request

SPAWN_WAIT_S = 10.0
POLL_INTERVAL_S = 0.25

_EXIT_OK = 0
_EXIT_REFUSED = 2
_EXIT_UNREACHABLE = 3


def main(argv: list[str] | None = None, *, spawn_wait_s: float | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cipherbox-launcher",
                                     description="forward a .cbx open request to the resident agent")
    parser.add_argument("cbx_path", help="absolute path of the .cbx file to open")
    parser.add_argument("--pipe", default=PIPE_NAME, help="agent open-request pipe")
    args = parser.parse_args(argv)
    request = {"cmd": "open", "path": os.path.abspath(args.cbx_path)}

    try:
        response = connect_and_request(args.pipe, request)
    except PipeError as first_error:
        if not first_error.pipe_absent:
            print(f"cipherbox: agent pipe error: {first_error}", file=sys.stderr)
            return _EXIT_UNREACHABLE
        if not spawn_agent():
            print("cipherbox: cannot start the resident agent", file=sys.stderr)
            return _EXIT_UNREACHABLE
        try:
            response = _await_agent(args.pipe, request,
                                    SPAWN_WAIT_S if spawn_wait_s is None else spawn_wait_s)
        except PipeError as exc:
            print(f"cipherbox: {exc}", file=sys.stderr)
            return _EXIT_UNREACHABLE

    print(json.dumps(response, sort_keys=True))
    if response.get("ok"):
        return _EXIT_OK
    print(f"cipherbox: open refused: {response.get('error', 'unknown error')}",
          file=sys.stderr)
    return _EXIT_REFUSED


def _await_agent(pipe_name: str, request: dict, wait_s: float) -> dict:
    """Bounded poll for the agent pipe, one final retry, then fail loudly."""
    deadline = time.monotonic() + wait_s
    last_error: PipeError | None = None
    while time.monotonic() < deadline:
        try:
            return connect_and_request(pipe_name, request)
        except PipeError as exc:
            last_error = exc
            time.sleep(min(POLL_INTERVAL_S, max(0.0, deadline - time.monotonic())))
    try:
        return connect_and_request(pipe_name, request)
    except PipeError as exc:
        raise PipeError(
            f"resident agent did not become reachable within {wait_s:g}s "
            f"({last_error} -> {exc})") from exc


def spawn_agent() -> bool:
    """Start the resident agent detached; its own mutex rejects duplicates."""
    repo_root = str(Path(__file__).resolve().parents[1])
    try:
        subprocess.Popen(
            [sys.executable, "-m", "agent"],
            cwd=repo_root,
            creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        print(f"cipherbox: cannot start resident agent: {exc}", file=sys.stderr)
        return False
    return True


if __name__ == "__main__":
    raise SystemExit(main())
