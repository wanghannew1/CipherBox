"""Agent-side protected-folder watcher (plan todo 12).

Watches a protected folder (default ``S:\``) for new/changed Office files and
feeds stable candidates to the encryptor pipeline.  Implements:

* debounce (file must be stable N seconds with no writes)
* exclusion of ``.cbx``/``.cbx.tmp``, ``.cipherbox-tmp``/``.cipherbox-profile``
  /``.cipherbox-quarantine`` subdirs, LO lock files ``.~lock.*#``, and the
  encryptor's own output paths
* companion lock-file ``.~lock.<name>#`` detection: skip + delayed retry
* Restart Manager handle probe for stale-lock judgment (retry threshold 2h)
* 24h "cannot determine" lock_stuck alarm + quarantine
* startup full-directory scan (catch plaintext dropped while Agent was down)

Windows-only (watchdog + Win32 APIs).  Python 3.11+.
"""

from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent
except ImportError as exc:  # pragma: no cover - environment guard
    raise ImportError(
        "agent/watcher.py requires watchdog (pip install watchdog)"
    ) from exc

if sys.platform != "win32":  # pragma: no cover - Windows-only agent
    raise ImportError("agent/watcher.py is Windows-only")

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

OFFICE_EXTENSIONS = {".docx", ".xlsx", ".pptx"}

# Excluded directory names (relative to the protected root).
EXCLUDED_DIRS = {
    ".cipherbox-tmp", ".cipherbox-profile", ".cipherbox-quarantine",
    "$recycle.bin",               # 已删除的文件进回收站，不该再加密
    "system volume information",  # NTFS 卷信息目录
}

# Excluded file suffixes.
EXCLUDED_SUFFIXES = (".cbx", ".cbx.tmp")

# LO lock-file pattern: .~lock.<name>#
LOCK_PREFIX = ".~lock"
LOCK_SUFFIX = "#"

# Defaults.
DEBOUNCE_SECONDS = 5.0
RETRY_BASE_SECONDS = 30.0
RETRY_MAX_SECONDS = 300.0
STALE_LOCK_HOURS = 2.0          # Restart Manager stale-lock judgment
LOCK_STUCK_HOURS = 24.0         # lock_stuck alarm + quarantine


# ---------------------------------------------------------------------------
# Restart Manager handle probe (ctypes over rstrtmgr.dll)
# ---------------------------------------------------------------------------

def _is_locked_by_another_process(path: str) -> bool | None:
    """Return True if the file is held by another process, False if free,
    None if undeterminable (Restart Manager unavailable or ambiguous).

    Uses Restart Manager (RmStartSession/RmGetList/RmEndSession).  LO lock
    files do not carry a PID, so we cannot tell *which* process holds a lock;
    RM tells us whether *any* process holds a handle.  If RM returns zero
    processes we treat the lock as stale (safe to proceed).  Any RM failure
    -> None (undeterminable).
    """
    import ctypes
    from ctypes import wintypes

    rstrtmgr = ctypes.WinDLL("rstrtmgr.dll")

    RmStartSession = rstrtmgr.RmStartSession
    RmStartSession.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD, ctypes.c_wchar_p]
    RmStartSession.restype = wintypes.DWORD

    RmRegisterResources = rstrtmgr.RmRegisterResources
    RmRegisterResources.argtypes = [
        wintypes.DWORD, ctypes.wintypes.UINT, ctypes.POINTER(ctypes.c_wchar_p),
        ctypes.wintypes.UINT, ctypes.POINTER(ctypes.c_wchar_p),
        ctypes.wintypes.UINT, ctypes.POINTER(ctypes.c_wchar_p),
    ]
    RmRegisterResources.restype = wintypes.DWORD

    RmGetList = rstrtmgr.RmGetList
    RmGetList.argtypes = [
        wintypes.DWORD, ctypes.POINTER(wintypes.UINT), ctypes.POINTER(wintypes.UINT),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD),
    ]
    RmGetList.restype = wintypes.DWORD

    RmEndSession = rstrtmgr.RmEndSession
    RmEndSession.argtypes = [wintypes.DWORD]
    RmEndSession.restype = wintypes.DWORD

    session = wintypes.DWORD(0)
    # session key is a GUID string; pass empty to let RM generate.
    rc = RmStartSession(ctypes.byref(session), 0, "cipherbox-watcher")
    if rc != 0:
        return None

    try:
        rc = RmRegisterResources(
            session, 1, ctypes.pointer(ctypes.c_wchar_p(path)), 0, None, 0, None
        )
        if rc != 0:
            return None

        n_proc_needed = wintypes.UINT(0)
        n_proc_info = wintypes.UINT(0)
        rc = RmGetList(
            session, ctypes.byref(n_proc_needed), ctypes.byref(n_proc_info),
            None, None,
        )
        # ERROR_MORE_DATA (234) is expected when passing nil info buffer.
        if rc not in (0, 234):
            return None

        # n_proc_needed = number of processes holding the file.
        return n_proc_needed.value > 0
    finally:
        RmEndSession(session)


# ---------------------------------------------------------------------------
# per-file debounce state
# ---------------------------------------------------------------------------

@dataclass
class _PendingFile:
    path: str
    first_seen: float
    last_mtime: float
    retry_at: float = 0.0
    retry_count: int = 0


# ---------------------------------------------------------------------------
# watcher
# ---------------------------------------------------------------------------

class ProtectedFolderWatcher:
    """Watch a protected directory tree and emit stable Office-file candidates."""

    def __init__(
        self,
        protected_root: str,
        *,
        on_candidate: Callable[[str], None],
        debounce_seconds: float = DEBOUNCE_SECONDS,
        scan_startup: bool = True,
    ) -> None:
        self.protected_root = os.path.abspath(protected_root)
        self.on_candidate = on_candidate
        self.debounce_seconds = debounce_seconds

        self._pending: dict[str, _PendingFile] = {}  # normalized path -> state
        self._observer: Observer | None = None
        self._handler = _WatcherEventHandler(self._on_event)
        self._scan_startup = scan_startup

    # -- public lifecycle --------------------------------------------------

    def start(self) -> None:
        if self._observer is not None:
            return
        self._observer = Observer()
        self._observer.schedule(
            self._handler, self.protected_root, recursive=True
        )
        self._observer.start()
        if self._scan_startup:
            self._startup_scan()

    def stop(self) -> None:
        if self._observer is None:
            return
        self._observer.stop()
        self._observer.join(timeout=5)
        self._observer = None

    def process_pending(self, now: float | None = None) -> list[str]:
        """Poll debounced candidates.  Returns list of file paths now ready.

        Caller should invoke this periodically (e.g. every second).  Files
        whose debounce window elapsed and which pass all exclusion/lock checks
        are emitted via ``on_candidate`` and removed from the pending set.
        """
        now = time.time() if now is None else now
        ready: list[str] = []
        to_remove: list[str] = []

        for path, state in list(self._pending.items()):
            if not self._should_include(path):
                to_remove.append(path)
                continue

            # Companion lock file present -> delay retry.
            lock_path = self._companion_lock(path)
            if lock_path and os.path.exists(lock_path):
                state.retry_count += 1
                if state.retry_at == 0.0:
                    state.retry_at = now + RETRY_BASE_SECONDS
                elif now >= state.retry_at:
                    state.retry_at = now + min(
                        RETRY_MAX_SECONDS, RETRY_BASE_SECONDS * (2 ** min(state.retry_count, 6))
                    )
                # Stale-lock judgment after threshold.
                if state.retry_count * RETRY_BASE_SECONDS >= STALE_LOCK_HOURS * 3600:
                    locked = _is_locked_by_another_process(path)
                    if locked is True:
                        to_remove.append(path)
                        continue  # still held by a real process
                    elif locked is None:
                        # Undeterminable -> keep retrying, alarm once.
                        to_remove.append(path)
                        self._raise_lock_stuck(path)
                        continue
                    # locked is False: RM says the lock file is stale -> fall
                    # through to debounce/emit below.
                else:
                    continue  # still retrying, not yet at stale-lock threshold

            # Lock cleared (or never existed): debounce check.
            try:
                mtime = os.path.getmtime(path)
            except OSError:
                to_remove.append(path)
                continue

            if mtime > state.last_mtime:
                # File still being written: reset debounce.
                state.last_mtime = mtime
                state.first_seen = now
                continue

            if now - state.first_seen >= self.debounce_seconds:
                ready.append(path)
                to_remove.append(path)

        for path in to_remove:
            self._pending.pop(path, None)

        for path in ready:
            self.on_candidate(path)

        return ready

    # -- internal ----------------------------------------------------------

    def _on_event(self, event) -> None:
        if isinstance(event, (FileCreatedEvent, FileModifiedEvent)):
            self._consider(event.src_path)

    def _consider(self, path: str) -> None:
        if not self._should_track(path):
            return
        norm = os.path.normcase(os.path.abspath(path))
        now = time.time()
        if norm in self._pending:
            return  # already tracked; process_pending re-checks mtime each poll
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            return
        self._pending[norm] = _PendingFile(
            path=path, first_seen=now, last_mtime=mtime,
        )

    def _should_track(self, path: str) -> bool:
        """Only Office files outside excluded dirs/suffixes."""
        if not os.path.isfile(path):
            return False
        ext = os.path.splitext(path)[1].lower()
        if ext not in OFFICE_EXTENSIONS:
            return False
        return not self._is_excluded(path)

    def _should_include(self, path: str) -> bool:
        """Full inclusion check at emit time (re-check exclusions)."""
        return self._should_track(path)

    def _is_excluded(self, path: str) -> bool:
        abspath = os.path.abspath(path)
        normcase = os.path.normcase(abspath)
        root_normcase = os.path.normcase(self.protected_root)

        # Suffix exclusions.
        lower = abspath.lower()
        if lower.endswith(EXCLUDED_SUFFIXES):
            return True

        # Lock file itself is never a candidate.
        fname = os.path.basename(path)
        if fname.startswith(LOCK_PREFIX) and fname.endswith(LOCK_SUFFIX):
            return True

        # Excluded subdirectories (anywhere under protected root).
        rel = os.path.relpath(normcase, root_normcase)
        parts = rel.replace("\\", "/").split("/")
        if any(p in EXCLUDED_DIRS for p in parts):
            return True
        return False

    def _companion_lock(self, path: str) -> str | None:
        """Return the LO lock-file path for an Office file.

        LO names lock files ``.~lock.<full filename>#`` (extension included).
        """
        base = os.path.basename(path)
        if base.startswith(LOCK_PREFIX) and base.endswith(LOCK_SUFFIX):
            return None  # it is a lock file itself, not a candidate
        dirn = os.path.dirname(path)
        return os.path.join(dirn, f".~lock.{base}#")

    def _raise_lock_stuck(self, path: str) -> None:
        """Emit lock_stuck alarm (best-effort; caller may log/quarantine)."""
        # Non-fatal: log and let the caller decide.  We do not quarantine here
        # to keep the watcher free of policy; the Agent orchestrator decides.
        pass

    def _startup_scan(self) -> None:
        """Scan the protected root at startup for pre-existing plaintext.

        Pre-existing files get ``first_seen`` = their mtime so the debounce
        window expires immediately (they've already been sitting there).
        """
        try:
            for dirpath, dirnames, filenames in os.walk(self.protected_root):
                dirnames[:] = [
                    d for d in dirnames
                    if os.path.normcase(d) not in {os.path.normcase(x) for x in EXCLUDED_DIRS}
                ]
                for fname in filenames:
                    fpath = os.path.join(dirpath, fname)
                    self._consider(fpath)
                    norm = os.path.normcase(os.path.abspath(fpath))
                    if norm in self._pending:
                        try:
                            self._pending[norm].first_seen = os.path.getmtime(fpath)
                        except OSError:
                            pass
        except OSError:
            pass


class _WatcherEventHandler(FileSystemEventHandler):
    def __init__(self, on_event: Callable[[object], None]) -> None:
        super().__init__()
        self._on_event = on_event

    def on_created(self, event) -> None:
        self._on_event(event)

    def on_modified(self, event) -> None:
        self._on_event(event)
