"""Session link worker: agent-side lifecycle (todo 17 interceptor wiring).

pyuno is version-locked to LibreOffice's bundled python, which cannot load
the resident agent's dependencies — so the ForceEncryptInterceptor lives in a
dedicated *link worker* process spawned per controlled session under LO's
python (``python -m agent.uno_link_worker``).  This module is the agent-side
half: spawn the worker, speak its JSON-line protocol, gate the controlled
session on the hard ordering (``registered`` then ``loaded`` — the document
is only ever loaded after interception is confirmed active), and wait for the
session end.  Nothing here imports uno; unit tests inject the spawner.

Worker stdout protocol (one JSON object per line):

    {"event": "registered", "frames": <n>}   interception active on n frames
    {"event": "loaded"}                      document loaded; session running
    {"event": "closed", "crashed": <bool>}   worker exiting (final line)
    {"ok": false, "error": "<why>"}          worker failed BEFORE loading

stdin payload (JSON): the :class:`LinkSpec` fields.  No secret travels in
either direction: the master key is fetched per forced save from the agent's
link pipe, never passed to the worker up front.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

REPO_ROOT = str(Path(__file__).resolve().parents[1])

# Bounded wait for the worker to reach "loaded" (connect + register + load).
DEFAULT_LOAD_TIMEOUT_S = 90.0


class LinkError(Exception):
    """The link worker could not be started, or never reached 'loaded'."""


@dataclass(frozen=True, slots=True)
class LinkSpec:
    """Everything the link worker needs; travels as one stdin JSON object."""

    soffice_pipe: str  # UNO pipe name the controlled soffice accepts on
    doc_path: str  # temp plaintext, loaded AFTER interception is confirmed
    agent_pipe: str  # agent link pipe (per-save key fetch + audit reports)
    queue_dir: str  # volume-side fallback queue for audits the agent misses
    poll_seconds: float = 2.0  # new-frame registration poll interval

    def payload(self) -> str:
        return json.dumps({
            "soffice_pipe": self.soffice_pipe,
            "doc_path": self.doc_path,
            "agent_pipe": self.agent_pipe,
            "queue_dir": self.queue_dir,
            "poll_seconds": self.poll_seconds,
        })


@dataclass(frozen=True)
class _Reader:
    lines: "queue.Queue[str]"
    thread: threading.Thread
    stderr_tail: "queue.Queue[str]"


@dataclass
class LinkHandle:
    """A live link worker: protocol reads + bounded waits + abort."""

    process: subprocess.Popen
    spec: LinkSpec
    reader: _Reader = field(repr=False, default=None)

    # -- protocol ------------------------------------------------------------

    def await_loaded(self, timeout_s: float = DEFAULT_LOAD_TIMEOUT_S) -> int:
        """Block until the worker reports interception active + doc loaded.

        Returns the number of frames the interceptor was registered on.
        Raises :class:`LinkError` if the worker exits first (its error line
        is the message), or on timeout (the worker is NOT killed here — the
        caller aborts the whole session, which kills it via the job/close).
        """
        deadline = time.monotonic() + max(timeout_s, 0.0)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LinkError(f"link worker not loaded after {timeout_s:.0f}s")
            try:
                line = self.reader.lines.get(timeout=min(remaining, 0.5))
            except queue.Empty:
                if self.process.poll() is not None:
                    raise LinkError(self._exit_message())
                continue
            event = _parse_event(line)
            if event.get("event") == "registered":
                frames = event.get("frames")
                if not isinstance(frames, int) or frames < 1:
                    raise LinkError(f"registered on {frames!r} frames")
                self._registered_frames = frames
            elif event.get("event") == "loaded":
                return getattr(self, "_registered_frames", 0)
            elif event.get("ok") is False:
                raise LinkError(str(event.get("error") or "link worker failed"))

    def wait_close(self) -> dict:
        """Block until the worker emits its final ``closed`` event.

        Returns the parsed event dict; a worker death without the final line
        is reported as ``{"event": "closed", "crashed": True}`` (bridge loss,
        soffice crash, kill) so the caller treats the session as abnormal.
        """
        while True:
            if self.reader.lines.empty() and self.process.poll() is not None:
                # Grace: the final line is written just before exit; a short
                # drain window keeps ordering between reader and wait().
                try:
                    line = self.reader.lines.get(timeout=2.0)
                except queue.Empty:
                    return {"event": "closed", "crashed": True}
                event = _parse_event(line)
                if event.get("event") == "closed":
                    return event
                return {"event": "closed", "crashed": True}
            try:
                line = self.reader.lines.get(timeout=0.5)
            except queue.Empty:
                continue
            event = _parse_event(line)
            if event.get("event") == "closed":
                return event
            if event.get("ok") is False:
                return {"event": "closed", "crashed": True,
                        "error": str(event.get("error") or "worker failed")}

    def kill(self) -> None:
        """Abort the worker process (session teardown; never raises)."""
        try:
            if self.process.poll() is None:
                self.process.kill()
        except OSError:
            pass

    def close(self) -> None:
        """Release pipe handles; the reader thread is a daemon and exits with
        the process."""
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass

    def stderr_text(self, limit: int = 500) -> str:
        """Best-effort stderr tail for failure messages (no secrets there)."""
        chunks = []
        while True:
            try:
                chunks.append(self.reader.stderr_tail.get_nowait())
            except queue.Empty:
                break
        return ("".join(chunks))[-limit:]

    # -- internals -----------------------------------------------------------

    def _exit_message(self) -> str:
        tail = self.stderr_text()
        detail = f"exited rc={self.process.returncode}"
        if tail:
            detail += f": {tail}"
        return f"link worker {detail}"


def default_spawner(argv: list[str], *, payload: str, cwd: str) -> subprocess.Popen:
    """Spawn the worker under LibreOffice's bundled python (real path)."""
    from agent.uno_driver import _resolve_lo_python

    lo_python = _resolve_lo_python()
    process = subprocess.Popen(
        [lo_python, *argv],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, cwd=cwd,
    )
    # The spec JSON crosses via stdin only (never argv); it is small enough
    # for the pipe buffer, and the worker reads it before anything else.
    process.stdin.write(payload)
    process.stdin.close()
    return process


def spawn(spec: LinkSpec, *, spawner: Callable[..., subprocess.Popen] | None = None,
          cwd: str = REPO_ROOT) -> LinkHandle:
    """Start one link worker and wrap it in a protocol handle."""
    do_spawn = spawner or default_spawner
    try:
        process = do_spawn(
            ["-m", "agent.uno_link_worker"],
            payload=spec.payload(), cwd=cwd)
    except OSError as exc:
        raise LinkError(f"cannot start link worker: {exc}") from exc
    handle = LinkHandle(process=process, spec=spec)
    handle.reader = _start_reader(process)
    return handle


# -- helpers -----------------------------------------------------------------

def _parse_event(line: str) -> dict:
    try:
        parsed = json.loads(line)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _start_reader(process: subprocess.Popen) -> _Reader:
    lines: "queue.Queue[str]" = queue.Queue()
    stderr_tail: "queue.Queue[str]" = queue.Queue()
    max_stderr_lines = 8

    def read_stdout() -> None:
        for raw in process.stdout:
            lines.put(raw.strip())

    def read_stderr() -> None:
        count = 0
        for raw in process.stderr:
            if raw.strip():
                count += 1
                if count > max_stderr_lines:
                    break
                stderr_tail.put(raw.strip())

    stdout_thread = threading.Thread(target=read_stdout, name="link-stdout", daemon=True)
    stderr_thread = threading.Thread(target=read_stderr, name="link-stderr", daemon=True)
    stdout_thread.start()
    stderr_thread.start()
    return _Reader(lines=lines, thread=stdout_thread, stderr_tail=stderr_tail)


def queue_dir_for(temp_root: str) -> str:
    """Volume-side fallback audit queue: a sibling of the session dirs so
    session cleanup never deletes it (todo 17 ① audit-queue\\ exemption)."""
    return os.path.join(temp_root, "audit-queue")
