"""Tests for agent/watcher.py (todo 12): exclusions, debounce, lock handling, startup scan."""

from __future__ import annotations

import os
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from agent.watcher import (
    DEBOUNCE_SECONDS,
    ProtectedFolderWatcher,
)


# ---------------------------------------------------------------------------
# fixtures / helpers
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_root(tmp_path: Path) -> str:
    return str(tmp_path)


def _mkfile(root: str, *parts: str, content: bytes = b"") -> str:
    """Create a file under root at os.path.join(root, *parts)."""
    full = os.path.join(root, *parts)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "wb") as fh:
        fh.write(content)
    return full


def _norm(p: str) -> str:
    return os.path.normcase(os.path.abspath(p))


# ---------------------------------------------------------------------------
# exclusions
# ---------------------------------------------------------------------------

class TestExclusions:
    def test_office_extension_included(self, tmp_root):
        w = ProtectedFolderWatcher(tmp_root, on_candidate=lambda p: None)
        assert w._should_track(_mkfile(tmp_root, "a.docx")) is True
        assert w._should_track(_mkfile(tmp_root, "b.xlsx")) is True
        assert w._should_track(_mkfile(tmp_root, "c.pptx")) is True

    def test_non_office_excluded(self, tmp_root):
        w = ProtectedFolderWatcher(tmp_root, on_candidate=lambda p: None)
        assert w._should_track(_mkfile(tmp_root, "a.txt")) is False
        assert w._should_track(_mkfile(tmp_root, "b.pdf")) is False
        assert w._should_track(_mkfile(tmp_root, "c.cbx")) is False

    def test_cbx_suffix_excluded(self, tmp_root):
        w = ProtectedFolderWatcher(tmp_root, on_candidate=lambda p: None)
        assert w._should_track(_mkfile(tmp_root, "a.docx.cbx")) is False
        assert w._should_track(_mkfile(tmp_root, "a.docx.cbx.tmp")) is False

    def test_lock_file_excluded(self, tmp_root):
        w = ProtectedFolderWatcher(tmp_root, on_candidate=lambda p: None)
        assert w._should_track(_mkfile(tmp_root, ".~lock.a.docx#")) is False

    def test_cipherbox_subdirs_excluded(self, tmp_root):
        w = ProtectedFolderWatcher(tmp_root, on_candidate=lambda p: None)
        for d in (".cipherbox-tmp", ".cipherbox-profile", ".cipherbox-quarantine"):
            assert w._should_track(_mkfile(tmp_root, d, "a.docx")) is False

    def test_nested_excluded_dir(self, tmp_root):
        w = ProtectedFolderWatcher(tmp_root, on_candidate=lambda p: None)
        assert w._should_track(_mkfile(tmp_root, "sub", ".cipherbox-tmp", "a.docx")) is False

    def test_case_insensitive_exclusion(self, tmp_root):
        w = ProtectedFolderWatcher(tmp_root, on_candidate=lambda p: None)
        assert w._should_track(_mkfile(tmp_root, ".CIPHERBOX-TMP", "a.docx")) is False


# ---------------------------------------------------------------------------
# companion lock
# ---------------------------------------------------------------------------

class TestCompanionLock:
    def test_lock_path_derivation(self, tmp_root):
        w = ProtectedFolderWatcher(tmp_root, on_candidate=lambda p: None)
        doc = _mkfile(tmp_root, "report.docx")
        assert w._companion_lock(doc) == os.path.join(tmp_root, ".~lock.report.docx#")

    def test_lock_present_blocks(self, tmp_root):
        w = ProtectedFolderWatcher(tmp_root, on_candidate=lambda p: None)
        doc = _mkfile(tmp_root, "report.docx")
        _mkfile(tmp_root, ".~lock.report.docx#")
        w._consider(doc)
        assert _norm(doc) in w._pending
        emitted = w.process_pending(now=time.time())
        assert emitted == []
        assert _norm(doc) in w._pending

    def test_lock_removed_emits(self, tmp_root):
        w = ProtectedFolderWatcher(tmp_root, on_candidate=lambda p: None)
        doc = _mkfile(tmp_root, "report.docx")
        lock = os.path.join(tmp_root, ".~lock.report.docx#")
        _mkfile(tmp_root, ".~lock.report.docx#")
        w._consider(doc)
        os.remove(lock)
        emitted = w.process_pending(now=time.time() + DEBOUNCE_SECONDS + 1)
        assert [_norm(e) for e in emitted] == [_norm(doc)]
        assert _norm(doc) not in w._pending


# ---------------------------------------------------------------------------
# debounce
# ---------------------------------------------------------------------------

class TestDebounce:
    def test_debounce_waits(self, tmp_root):
        emitted: list[str] = []
        w = ProtectedFolderWatcher(tmp_root, on_candidate=emitted.append)
        doc = _mkfile(tmp_root, "report.docx")
        w._consider(doc)
        assert w.process_pending(now=time.time()) == []
        assert w.process_pending(now=time.time() + 1) == []
        assert [_norm(e) for e in w.process_pending(now=time.time() + DEBOUNCE_SECONDS + 1)] == [_norm(doc)]

    def test_rewrite_resets_debounce(self, tmp_root):
        emitted: list[str] = []
        w = ProtectedFolderWatcher(tmp_root, on_candidate=emitted.append)
        doc = _mkfile(tmp_root, "report.docx")
        w._consider(doc)
        t0 = time.time()
        # Simulate file still being written: set mtime ahead of "now".
        os.utime(doc, (t0 + 5, t0 + 5))
        # At original debounce window: mtime is newer -> reset first_seen, no emit.
        assert w.process_pending(now=t0 + DEBOUNCE_SECONDS + 0.5) == []
        # first_seen was reset to the poll time; now past the new window.
        assert [_norm(e) for e in w.process_pending(now=t0 + 2 * DEBOUNCE_SECONDS + 1)] == [_norm(doc)]


# ---------------------------------------------------------------------------
# Restart Manager (mocked)
# ---------------------------------------------------------------------------

class TestRestartManager:
    @patch("agent.watcher._is_locked_by_another_process")
    def test_stale_lock_rm_says_free_proceeds(self, mock_rm, tmp_root):
        mock_rm.return_value = False
        emitted: list[str] = []
        w = ProtectedFolderWatcher(
            tmp_root, on_candidate=emitted.append, debounce_seconds=0.1,
        )
        doc = _mkfile(tmp_root, "report.docx")
        _mkfile(tmp_root, ".~lock.report.docx#")
        w._consider(doc)
        threshold_retry = int((2.0 * 3600) / 30.0) + 1
        now0 = time.time()
        for i in range(threshold_retry):
            w.process_pending(now=now0 + i * 30)
        assert [_norm(e) for e in emitted] == [_norm(doc)]

    @patch("agent.watcher._is_locked_by_another_process")
    def test_stale_lock_rm_says_held_skip(self, mock_rm, tmp_root):
        mock_rm.return_value = True
        emitted: list[str] = []
        w = ProtectedFolderWatcher(
            tmp_root, on_candidate=emitted.append, debounce_seconds=0.1,
        )
        doc = _mkfile(tmp_root, "report.docx")
        _mkfile(tmp_root, ".~lock.report.docx#")
        w._consider(doc)
        threshold_retry = int((2.0 * 3600) / 30.0) + 1
        now0 = time.time()
        for i in range(threshold_retry):
            w.process_pending(now=now0 + i * 30)
        assert emitted == []
        assert _norm(doc) not in w._pending


# ---------------------------------------------------------------------------
# startup scan
# ---------------------------------------------------------------------------

class TestStartupScan:
    def test_startup_scan_picks_existing_files(self, tmp_root):
        old = time.time() - 100
        existing = _mkfile(tmp_root, "existing.docx", content=b"hello")
        os.utime(existing, (old, old))
        _mkfile(tmp_root, "ignored.txt", content=b"nope")
        emitted: list[str] = []
        w = ProtectedFolderWatcher(tmp_root, on_candidate=emitted.append, scan_startup=True)
        w._startup_scan()
        emitted_now = w.process_pending(now=time.time())
        assert any("existing.docx" in e for e in emitted_now)
        assert not any("ignored.txt" in e for e in emitted_now)


# ---------------------------------------------------------------------------
# lifecycle
# ---------------------------------------------------------------------------

class TestLifecycle:
    def test_start_stop_idempotent(self, tmp_root):
        w = ProtectedFolderWatcher(tmp_root, on_candidate=lambda p: None)
        w.start()
        w.start()
        assert w._observer is not None
        w.stop()
        w.stop()
        assert w._observer is None
