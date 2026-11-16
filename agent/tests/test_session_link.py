"""Session-link lifecycle tests: spawn/protocol/waits with scripted workers.

The link worker runs as a real subprocess of the test interpreter executing
small inline scripts, so the JSON-line protocol, the registered->loaded gate,
and the crash reporting are exercised against REAL process semantics (the
repo's pattern: real pipes, real threads, fake only the unavailable thing —
here that is LibreOffice's python and soffice).
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from agent.session_link import (
    LinkError,
    LinkSpec,
    queue_dir_for,
    spawn,
)

OK_WORKER = textwrap.dedent("""
    import json, sys, time
    spec = sys.stdin.read()
    print(json.dumps({"event": "registered", "frames": 2}), flush=True)
    print(json.dumps({"event": "loaded"}), flush=True)
    time.sleep(0.3)
    print(json.dumps({"event": "closed", "crashed": False}), flush=True)
""")

CRASH_WORKER = textwrap.dedent("""
    import json, sys, time
    sys.stdin.read()
    print(json.dumps({"event": "registered", "frames": 1}), flush=True)
    print(json.dumps({"event": "loaded"}), flush=True)
    time.sleep(0.2)
    import os
    os._exit(3)  # die WITHOUT the final closed line
""")

FAIL_WORKER = textwrap.dedent("""
    import json, sys
    sys.stdin.read()
    sys.stderr.write("soffice pipe never came up\\n")
    print(json.dumps({"ok": False, "error": "controlled soffice unreachable"}),
          flush=True)
    sys.exit(1)
""")

HANG_WORKER = textwrap.dedent("""
    import json, sys, time
    sys.stdin.read()
    print(json.dumps({"event": "registered", "frames": 1}), flush=True)
    time.sleep(30)  # never 'loaded' within the test's short timeout
""")


def make_spec(tmp_path: Path) -> LinkSpec:
    return LinkSpec(
        soffice_pipe="cipherbox-controlled-uuid-1",
        doc_path=str(tmp_path / "a.docx"),
        agent_pipe=r"\\.\pipe\cipherbox-link",
        queue_dir=str(tmp_path / "audit-queue"))


def script_spawner(source: str):
    """A spawner running the inline script under the test interpreter."""
    def spawner(argv, *, payload: str, cwd: str) -> subprocess.Popen:
        process = subprocess.Popen(
            [sys.executable, "-c", source],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, cwd=cwd)
        process.stdin.write(payload)
        process.stdin.close()
        return process
    return spawner


class TestSpawnAndGate:
    def test_await_loaded_returns_frame_count(self, tmp_path: Path):
        handle = spawn(make_spec(tmp_path), spawner=script_spawner(OK_WORKER))
        try:
            frames = handle.await_loaded(timeout_s=10)
            assert frames == 2
        finally:
            handle.close()
            handle.process.wait(timeout=5)

    def test_worker_failure_before_loaded_raises_link_error(self, tmp_path: Path):
        handle = spawn(make_spec(tmp_path), spawner=script_spawner(FAIL_WORKER))
        try:
            with pytest.raises(LinkError, match="controlled soffice unreachable"):
                handle.await_loaded(timeout_s=10)
        finally:
            handle.close()
            handle.process.wait(timeout=5)

    def test_worker_exit_without_error_line_raises_link_error(self, tmp_path: Path):
        # exits instantly without emitting anything parseable
        source = "import sys\nsys.stdin.read()\nsys.exit(1)"
        handle = spawn(make_spec(tmp_path), spawner=script_spawner(source))
        try:
            with pytest.raises(LinkError, match="rc=1"):
                handle.await_loaded(timeout_s=10)
        finally:
            handle.close()

    def test_timeout_raises_link_error_and_worker_survives(self, tmp_path: Path):
        handle = spawn(make_spec(tmp_path), spawner=script_spawner(HANG_WORKER))
        try:
            with pytest.raises(LinkError, match="not loaded after"):
                handle.await_loaded(timeout_s=0.5)
            assert handle.process.poll() is None  # NOT killed by the gate
        finally:
            handle.kill()
            handle.close()
            handle.process.wait(timeout=5)

    def test_spawner_oserror_becomes_link_error(self, tmp_path: Path):
        def failing_spawner(argv, *, payload, cwd):
            raise OSError("LO python missing")

        with pytest.raises(LinkError, match="cannot start link worker"):
            spawn(make_spec(tmp_path), spawner=failing_spawner)


class TestWaitClose:
    def test_clean_close_returns_event(self, tmp_path: Path):
        handle = spawn(make_spec(tmp_path), spawner=script_spawner(OK_WORKER))
        try:
            handle.await_loaded(timeout_s=10)
            closed = handle.wait_close()
            assert closed == {"event": "closed", "crashed": False}
        finally:
            handle.close()
            handle.process.wait(timeout=5)

    def test_worker_death_without_final_line_reports_crash(self, tmp_path: Path):
        handle = spawn(make_spec(tmp_path), spawner=script_spawner(CRASH_WORKER))
        try:
            handle.await_loaded(timeout_s=10)
            closed = handle.wait_close()
            assert closed == {"event": "closed", "crashed": True}
            assert handle.process.returncode == 3
        finally:
            handle.close()


class TestKillAndPayload:
    def test_kill_terminates_worker(self, tmp_path: Path):
        handle = spawn(make_spec(tmp_path), spawner=script_spawner(HANG_WORKER))
        handle.kill()  # no await: kill straight away
        handle.process.wait(timeout=5)
        assert handle.process.poll() is not None
        handle.close()

    def test_spec_payload_carries_all_fields(self, tmp_path: Path):
        spec = make_spec(tmp_path)
        payload = json.loads(spec.payload())
        assert payload == {
            "soffice_pipe": "cipherbox-controlled-uuid-1",
            "doc_path": spec.doc_path,
            "agent_pipe": spec.agent_pipe,
            "queue_dir": spec.queue_dir,
            "poll_seconds": 2.0,
        }

    def test_queue_dir_is_sibling_of_session_dirs(self):
        assert queue_dir_for(r"S:\.cipherbox-tmp").endswith(
            r".cipherbox-tmp\audit-queue")
