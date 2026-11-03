"""Composition-root tests for agent/__main__.py.

Covers the startup order (keys ensure BEFORE recovery — recovery's orphan
re-encrypt needs the current key — and recovery BEFORE watcher start and
BEFORE pipe accept; all asserted through recording fakes injected via the
:class:`Runtime` seam), ``--once`` mode, and graceful shutdown with no
lingering threads.  Config-loader and build_runtime wiring tests live in
test_config.py.  Synchronization uses events only.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

import pytest

from agent.__main__ import Runtime, main, once_startup, run_resident, serve_resident
from agent.cleanup import RecoveryReport
from agent.config import AgentConfig
from agent.key_manager import CachedKey, KeySet, ServerUnreachableError, dpapi_encrypt

PIPE_NAME = "fake-open-pipe"


# ---------------------------------------------------------------------------
# recording fakes (injected through the Runtime seam)
# ---------------------------------------------------------------------------

class RecordingKeyManager:
    def __init__(self, order: list[str], *, error: Exception | None = None) -> None:
        self._order = order
        self._error = error
        self._key_set = KeySet(
            versions=[CachedKey(version=3, key="k3"), CachedKey(version=1, key="k1")],
            current=3)
        self.ensure_calls: list[bool] = []

    def ensure_keys(self, online: bool = True) -> KeySet:
        self.ensure_calls.append(online)
        self._order.append("keys.ensure")
        if self._error is not None:
            raise self._error
        return self._key_set


class RecordingAudit:
    def __init__(self, order: list[str]) -> None:
        self._order = order

    def flush(self) -> int:
        self._order.append("audit.flush")
        return 0

    def report(self, *args, **kwargs) -> bool:
        return True


class RecordingWatcher:
    def __init__(self, order: list[str]) -> None:
        self._order = order
        self.pending_seen = threading.Event()

    def start(self) -> None:
        self._order.append("watcher.start")

    def stop(self) -> None:
        self._order.append("watcher.stop")

    def process_pending(self, now: float | None = None) -> list[str]:
        self._order.append("watcher.pending")
        self.pending_seen.set()
        return []


class RecordingPipeServer:
    def __init__(self, order: list[str]) -> None:
        self._order = order
        self.pipe_name = PIPE_NAME
        self.serving = threading.Event()
        self._stop = threading.Event()
        self.closed = False

    def serve_forever(self) -> None:
        self._order.append("pipe.serve")
        self.serving.set()
        assert self._stop.wait(10), "test timed out waiting for pipe stop"

    def stop(self) -> None:
        self._stop.set()

    def close(self) -> None:
        self.closed = True
        self._order.append("pipe.closed")


def make_recording_recovery(order: list[str]):
    def recovery(_rt: Runtime) -> RecoveryReport:
        order.append("recovery")
        return RecoveryReport()

    return recovery


def fake_config(tmp: str = r"T:\unused") -> AgentConfig:
    return AgentConfig(
        server_url="https://cipherbox.example:8443",
        ca_cert_file="",
        protected_dir=os.path.join(tmp, "protected"),
        temp_root=os.path.join(tmp, "tmp"),
        service_profile=os.path.join(tmp, "svc"),
        controlled_profile=os.path.join(tmp, "ctl"),
        session_dir=os.path.join(tmp, "sessions"),
        keycache=os.path.join(tmp, "keycache.dat"),
        audit_queue=os.path.join(tmp, "audit-queue.json"))


def make_runtime(order: list[str], *, with_watcher: bool, km_error: Exception | None = None) -> Runtime:
    return Runtime(
        config=fake_config(),
        key_manager=RecordingKeyManager(order, error=km_error),
        audit=RecordingAudit(order),
        uno_driver=None,
        watcher=RecordingWatcher(order) if with_watcher else None,
        pipe_server=RecordingPipeServer(order),
        recovery_runner=make_recording_recovery(order))


def wait_and_stop(rt: Runtime) -> None:
    assert rt.pipe_server.serving.wait(5), "pipe never reached serve phase"
    rt.pipe_server.stop()


# ---------------------------------------------------------------------------
# startup order (plan todo 26) + graceful shutdown
# ---------------------------------------------------------------------------

class TestStartupOrder:
    def test_recovery_before_watcher_before_pipe(self):
        order: list[str] = []
        rt = make_runtime(order, with_watcher=True)
        thread = threading.Thread(target=run_resident, args=(rt,), daemon=True)

        thread.start()
        wait_and_stop(rt)
        thread.join(timeout=5)

        assert order[:5] == ["keys.ensure", "recovery", "audit.flush", "watcher.start", "pipe.serve"]
        assert order.count("watcher.stop") == 1
        assert order.count("pipe.closed") == 1
        assert not thread.is_alive()

    def test_no_watcher_skips_watcher_phases(self):
        order: list[str] = []
        rt = make_runtime(order, with_watcher=False)
        thread = threading.Thread(target=run_resident, args=(rt,), daemon=True)

        thread.start()
        wait_and_stop(rt)
        thread.join(timeout=5)

        assert order[:4] == ["keys.ensure", "recovery", "audit.flush", "pipe.serve"]
        assert "watcher.start" not in order
        assert "watcher.stop" not in order


class TestGracefulShutdown:
    def test_serve_resident_stops_cleanly_with_no_orphans(self):
        order: list[str] = []
        rt = make_runtime(order, with_watcher=True)
        outcomes: list[int] = []
        outer = threading.Thread(
            target=lambda: outcomes.append(serve_resident(rt)), daemon=True)

        outer.start()
        assert rt.pipe_server.serving.wait(5)
        # The 1s main loop drains watcher candidates between joins.
        assert rt.watcher.pending_seen.wait(5), "watcher never drained"
        rt.pipe_server.stop()  # what the signal handlers invoke
        outer.join(timeout=10)

        assert outcomes == [0]
        assert not outer.is_alive()
        assert order[:5] == ["keys.ensure", "recovery", "audit.flush", "watcher.start", "pipe.serve"]
        assert order.count("watcher.stop") == 1
        assert order.count("pipe.closed") == 1
        assert not any(t.name == "cipherbox-agent" for t in threading.enumerate())


# ---------------------------------------------------------------------------
# --once mode
# ---------------------------------------------------------------------------

class TestOnceMode:
    def test_reports_recovery_and_key_state(self):
        order: list[str] = []
        rt = make_runtime(order, with_watcher=True)

        report, key_state = once_startup(rt)

        assert isinstance(report, RecoveryReport)
        assert key_state == "ok: 2 version(s), current=v3"
        assert order == ["keys.ensure", "audit.flush", "recovery"]  # never watcher, never pipe

    def test_offline_without_cache_reports_unavailable(self):
        order: list[str] = []
        rt = make_runtime(
            order, with_watcher=False,
            km_error=ServerUnreachableError("offline and no key cache available"))

        report, key_state = once_startup(rt)

        assert isinstance(report, RecoveryReport)
        assert "unavailable" in key_state
        assert "offline and no key cache available" in key_state
        assert order == ["keys.ensure", "recovery"]  # flush skipped: ensure_keys failed

    def test_main_once_cli(self, tmp_path: Path, monkeypatch, capsys):
        order: list[str] = []
        rt = make_runtime(order, with_watcher=False)
        token_file = tmp_path / "token.dpapi"
        token_file.write_bytes(dpapi_encrypt(b"employee-token-1"))
        config_file = tmp_path / "client.json"
        config_file.write_text(json.dumps(_client_json(tmp_path)), encoding="utf-8")
        captured: dict = {}

        def fake_build(loaded, *, with_watcher, pipe_name="unused"):
            captured["loaded"] = loaded
            captured["with_watcher"] = with_watcher
            return rt

        monkeypatch.setattr("agent.__main__.build_runtime", fake_build)

        rc = main(["--once", "--config", str(config_file),
                   "--token-file", str(token_file)])

        assert rc == 0
        assert captured["with_watcher"] is False
        assert captured["loaded"].token == "employee-token-1"
        out = capsys.readouterr().out
        assert "recovery:" in out
        assert "keys: ok: 2 version(s), current=v3" in out


def _client_json(tmp_path: Path) -> dict:
    return {
        "server_url": "https://cipherbox.example:8443",
        "ca_cert_file": "",
        "protected_dir": "S:\\",
        "temp_root": r"S:\.cipherbox-tmp",
        "service_profile": r"S:\.cipherbox-profile\service",
        "controlled_profile": r"S:\.cipherbox-profile\controlled",
        "session_dir": r"S:\appdata-ish\sessions",
        "keycache": "config-relative/keycache.dat",
        "audit_queue": r"S:\appdata-ish\audit-queue.json",
    }
