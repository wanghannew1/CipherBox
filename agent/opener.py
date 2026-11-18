"""Agent-side controlled-open closed loop (plan todo 14).

Decrypts a ``.cbx`` to a temp cleartext under ``S:\.cipherbox-tmp\<uuid>\``,
launches an independent GUI LibreOffice WITHOUT the document (controlled
profile, Job Object bound), attaches the interceptor link worker (todo 17:
forced-encrypt interception registered BEFORE the document loads — link
failure aborts the session fail-closed), waits for the link's document-level
close, kills the GUI via the job, re-encrypts on change, then deletes the
temp cleartext and the session record.

All LibreOffice/UNO interaction is injected via callbacks so the module can be
unit-tested without soffice.  Windows-only (Job Object, DPAPI, named mutex).

Plan references: todo 10 (agent/container.py decrypt), todo 11 (key cache),
todo 13 (encryptor re-encrypt), todo 14/17 (link hard ordering).
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

if os.name != "nt":  # pragma: no cover - Windows-only agent
    raise ImportError("agent/opener.py is Windows-only")

import ctypes
from ctypes import wintypes

from agent.container import CbxContainer, WrongKeyError, ContainerError

SESSION_DIR = os.path.expandvars(r"%APPDATA%\CipherBox\sessions")
TMP_ROOT = r"S:\.cipherbox-tmp"
MUTEX_NAME = "Local\\CipherBoxControlledOpen"
CBX_SUFFIX = ".cbx"


# ---------------------------------------------------------------------------
# Windows Job Object (KILL_ON_JOB_CLOSE) — binds soffice lifetime to Agent
# ---------------------------------------------------------------------------

class JobObject:
    """A Win32 Job Object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.

    When the last handle to the job is closed (Agent exits), all processes
    in the job (the controlled soffice) are terminated.
    """

    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

    def __init__(self) -> None:
        kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
        self._kernel32 = kernel32
        self._job = kernel32.CreateJobObjectW(None, None)
        if not self._job:
            raise ctypes.WinError(ctypes.get_last_error())

        class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
                ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_ulonglong),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        self._limit = JOBOBJECT_BASIC_LIMIT_INFORMATION()
        self._limit.LimitFlags = self.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE

        class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ("IoInfo", ctypes.c_ulonglong * 6),  # IO_COUNTERS simplified
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        self._extended = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        self._extended.BasicLimitInformation = self._limit

        ok = kernel32.SetInformationJobObject(
            self._job,
            9,  # JobObjectExtendedLimitInformation
            ctypes.byref(self._extended),
            ctypes.sizeof(self._extended),
        )
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())

    def assign_process(self, pid: int) -> None:
        kernel32 = self._kernel32
        # PROCESS_SET_QUOTA (0x0100) | PROCESS_TERMINATE (0x0001).  SET_QUOTA
        # is required in practice: on Win11 2262x a TERMINATE-only (or
        # TERMINATE|CREATE_THREAD) handle passes OpenProcess but the assign
        # itself fails with ERROR_ACCESS_DENIED (live 2026-11-18 — this exact
        # silent failure left the controlled office alive past session end,
        # which then swallowed the next session's launch via same-profile
        # forwarding and broke interceptor registration on its 2nd bridge).
        h = kernel32.OpenProcess(0x0100 | 0x0001, False, pid)
        if not h:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            ok = kernel32.AssignProcessToJobObject(self._job, h)
            if not ok:
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            kernel32.CloseHandle(h)

    def close(self) -> None:
        if self._job:
            self._kernel32.CloseHandle(self._job)
            self._job = None

    def __enter__(self) -> "JobObject":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


_TH32CS_SNAPPROCESS = 0x00000002
_INVALID_HANDLE_VALUE = -1
_OFFICE_IMAGES = frozenset({"soffice.exe", "soffice.bin"})


class _ProcessEntry32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeap", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


def office_children_of(stub_pid: int) -> list[int]:
    """Live soffice.exe/soffice.bin pids whose parent is ``stub_pid``.

    Thin Toolhelp32 snapshot (same shape as JobObject above: Windows API,
    covered by the live smoke, no unit-test seam).  If the stub pid is not
    in the snapshot at all (already exited / pid recycled) nothing is
    returned — assigning children of a recycled pid could bind an innocent
    process into the kill-on-close job.
    """
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(_ProcessEntry32W)]
    kernel32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(_ProcessEntry32W)]
    snapshot = kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
    if not snapshot or snapshot == ctypes.c_void_p(_INVALID_HANDLE_VALUE).value:
        return []
    try:
        stub_alive = False
        children: list[int] = []
        entry = _ProcessEntry32W()
        entry.dwSize = ctypes.sizeof(entry)
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            image = entry.szExeFile.lower()
            if entry.th32ProcessID == stub_pid:
                stub_alive = True
            elif (entry.th32ParentProcessID == stub_pid
                    and image in _OFFICE_IMAGES):
                children.append(entry.th32ProcessID)
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
        return children if stub_alive else []
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(snapshot))


def bind_office_children(job: JobObject, stub_pid: int, *, find: Callable[[int], list[int]] | None = None,
                         sleep: Callable[[float], None] = time.sleep,
                         timeout_s: float = 3.0,
                         log: Callable[[str], None] = print) -> int:
    """Assign the launcher stub's office children into the kill-on-close job.

    The soffice.exe stub spawns soffice.bin a few milliseconds after its own
    start; if that birth lands BEFORE ``assign_process(stub_pid)`` the bin
    never joins the job (processes inherit a job only when born INTO it) and
    KILL_ON_JOB_CLOSE would kill only the stub.  Live 2026-11-18: exactly
    that race left a surviving controlled office whose Start Center swallowed
    the next session's launch (same-profile forwarding) and broke interceptor
    registration on the survivor's second UNO bridge.  Poll briefly for the
    office child processes and assign every one found.
    """
    find = find or office_children_of
    bound: set[int] = set()
    attempted: set[int] = set()  # bound or refused: never retried (no log spam)
    deadline = time.monotonic() + timeout_s
    while True:
        for child in find(stub_pid):
            if child in attempted:
                continue
            attempted.add(child)
            try:
                job.assign_process(child)
                bound.add(child)
            except Exception as exc:  # boundary: a lost child must not abort the session
                log(f"[agent] job: cannot bind office process {child}: {exc}")
        if bound or time.monotonic() >= deadline:
            break
        sleep(0.1)
    if not bound:
        # No office child ever appeared: either the stub died early (its own
        # children die with it) or the pid was lost — report, don't fail; the
        # worker's desktop.terminate() at session end is the remaining guard.
        log(f"[agent] job: no office child of stub pid {stub_pid} within "
            f"{timeout_s:.0f}s; session end relies on the office exiting cleanly")
    return len(bound)


# ---------------------------------------------------------------------------
# Session record (DPAPI-encrypted JSON)
# ---------------------------------------------------------------------------

@dataclass
class SessionRecord:
    session_id: str
    cbx_path: str
    tmp_path: str
    orig_sha256: str
    key_version: int
    ts: float  # record write time (monotonic-ish, for crash-recovery guard)


class SessionStore:
    """Persist/load/delete session records under %APPDATA%\\CipherBox\\sessions.

    Each record is DPAPI-encrypted JSON so no plaintext metadata leaves the
    volume.  Normal close deletes the record; crash-recovery (todo 26) reads
    orphaned records.
    """

    def __init__(self, session_dir: str = SESSION_DIR) -> None:
        self.session_dir = session_dir

    def _path(self, session_id: str) -> str:
        return os.path.join(self.session_dir, f"{session_id}.json")

    def save(self, rec: SessionRecord) -> None:
        os.makedirs(self.session_dir, exist_ok=True)
        payload = {
            "session_id": rec.session_id,
            "cbx_path": rec.cbx_path,
            "tmp_path": rec.tmp_path,
            "orig_sha256": rec.orig_sha256,
            "key_version": rec.key_version,
            "ts": rec.ts,
        }
        blob = json.dumps(payload, sort_keys=True).encode("utf-8")
        encrypted = _dpapi_encrypt(blob)
        with open(self._path(rec.session_id), "wb") as fh:
            fh.write(encrypted)

    def load(self, session_id: str) -> SessionRecord | None:
        path = self._path(session_id)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "rb") as fh:
                encrypted = fh.read()
            blob = _dpapi_decrypt(encrypted)
            payload = json.loads(blob.decode("utf-8"))
            return SessionRecord(
                session_id=payload["session_id"],
                cbx_path=payload["cbx_path"],
                tmp_path=payload["tmp_path"],
                orig_sha256=payload["orig_sha256"],
                key_version=payload["key_version"],
                ts=payload["ts"],
            )
        except Exception:
            return None

    def delete(self, session_id: str) -> None:
        try:
            os.remove(self._path(session_id))
        except OSError:
            pass

    def list_orphans(self) -> list[SessionRecord]:
        """All records on disk (for crash recovery, todo 26)."""
        out: list[SessionRecord] = []
        if not os.path.isdir(self.session_dir):
            return out
        for name in os.listdir(self.session_dir):
            if not name.endswith(".json"):
                continue
            rec = self.load(name[:-5])
            if rec is not None:
                out.append(rec)
        return out


# ---------------------------------------------------------------------------
# DPAPI helpers (session-level, separate from key cache)
# ---------------------------------------------------------------------------

def _dpapi_encrypt(plaintext: bytes) -> bytes:
    import ctypes
    from ctypes import wintypes

    crypt32 = ctypes.WinDLL("crypt32.dll")
    _CRYPTPROTECT_UI_FORBIDDEN = 0x00000001

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(DATA_BLOB), ctypes.c_wchar_p, ctypes.POINTER(DATA_BLOB),
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DATA_BLOB),
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL

    def _blob(data: bytes) -> DATA_BLOB:
        buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data) if data else None
        return DATA_BLOB(len(data) if data else 0, buf)

    in_b = _blob(plaintext)
    out_b = DATA_BLOB()
    ok = crypt32.CryptProtectData(
        ctypes.byref(in_b), None, None, None, None,
        _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out_b),
    )
    if not ok:
        raise RuntimeError("DPAPI CryptProtectData failed")
    try:
        return bytes(out_b.pbData[: out_b.cbData])
    finally:
        kernel32 = ctypes.WinDLL("kernel32.dll")
        kernel32.LocalFree(ctypes.cast(out_b.pbData, ctypes.c_void_p))


def _dpapi_decrypt(ciphertext: bytes) -> bytes:
    import ctypes
    from ctypes import wintypes

    crypt32 = ctypes.WinDLL("crypt32.dll")
    _CRYPTPROTECT_UI_FORBIDDEN = 0x00000001

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(DATA_BLOB), ctypes.POINTER(ctypes.c_wchar_p), ctypes.POINTER(DATA_BLOB),
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DATA_BLOB),
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL

    def _blob(data: bytes) -> DATA_BLOB:
        buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data) if data else None
        return DATA_BLOB(len(data) if data else 0, buf)

    in_b = _blob(ciphertext)
    out_b = DATA_BLOB()
    descr = ctypes.c_wchar_p()
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_b), ctypes.byref(descr), None, None, None,
        _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out_b),
    )
    if not ok:
        raise RuntimeError("DPAPI CryptUnprotectData failed")
    try:
        return bytes(out_b.pbData[: out_b.cbData])
    finally:
        kernel32 = ctypes.WinDLL("kernel32.dll")
        kernel32.LocalFree(ctypes.cast(out_b.pbData, ctypes.c_void_p))


# ---------------------------------------------------------------------------
# Controlled open / close orchestration
# ---------------------------------------------------------------------------

@dataclass
class OpenResult:
    session_id: str
    tmp_path: str
    cbx_path: str
    changed: bool
    re_encrypted: bool


class ControlledOpener:
    """Orchestrates one controlled-open session.

    Callbacks (injected; no soffice dependency in this module):

        launch_soffice(tmp_path, profile, pipe_name, env) -> int
            Start GUI soffice WITHOUT the document (the link loads it); PID.
        attach_interceptor(pipe_name, tmp_path) -> link handle
            Spawn the per-session link worker (todo 17): registers the
            forced-encrypt interceptor on every frame, then loads the temp
            plaintext.  The handle needs ``wait_close() -> dict`` (final
            ``{"event": "closed", "crashed": bool}``) and ``kill()``.
            REQUIRED in production: without it the document would open with
            no interception — the opener only runs without it on the
            unit-test path.
        wait_document_close(pid, timeout_s) -> bool
            Legacy/test fallback: block on the soffice PROCESS (used only
            when no link handle was attached).  True = exited, False = lost.
        re_encrypt(tmp_path, cbx_path, password) -> None
            Re-encrypt the (possibly edited) cleartext back to .cbx.
    """

    def __init__(
        self,
        *,
        container: CbxContainer,
        passwords: list[str],
        key_version: int,
        session_store: SessionStore,
        tmp_root: str = TMP_ROOT,
        launch_soffice: Callable[[str, str, str, dict], int] | None = None,
        attach_interceptor: Callable[[str, str], object] | None = None,
        wait_document_close: Callable[[int, float], bool] | None = None,
        re_encrypt: Callable[[str, str, str], None] | None = None,
        audit: Callable[[str, str, int | None, bool, str | None], None] | None = None,
        log: Callable[[str], None] = print,
    ) -> None:
        self.container = container
        self.passwords = passwords
        self.key_version = key_version
        self.session_store = session_store
        self.tmp_root = tmp_root
        self.launch_soffice = launch_soffice
        self.attach_interceptor = attach_interceptor
        self.wait_document_close = wait_document_close
        self.re_encrypt = re_encrypt
        self.audit = audit
        self.log = log

    # -- public entry point ----------------------------------------------

    def open_controlled(
        self,
        cbx_path: str,
        *,
        launch_soffice: Callable[[str, str, str, dict], int] | None = None,
        attach_interceptor: Callable[[str, str], object] | None = None,
        wait_document_close: Callable[[int, float], bool] | None = None,
        re_encrypt: Callable[[str, str, str], None] | None = None,
        audit: Callable[[str, str, int | None, bool, str | None], None] | None = None,
    ) -> OpenResult:
        """Full closed loop: decrypt -> launch LO -> intercept -> wait close -> re-encrypt -> cleanup."""
        launch = launch_soffice or self.launch_soffice
        attach = attach_interceptor or self.attach_interceptor
        wait = wait_document_close or self.wait_document_close
        reenc = re_encrypt or self.re_encrypt
        aud = audit or self.audit
        session_id = str(uuid.uuid4())
        session_dir = os.path.join(self.tmp_root, session_id)
        os.makedirs(session_dir, exist_ok=True)

        # --- decrypt .cbx (container.py, no UNO) ------------------------
        try:
            plaintext, used_pw = self.container.decrypt(self.passwords)
        except WrongKeyError as exc:
            raise RuntimeError(f"无法解密 .cbx: {exc}") from exc

        orig_sha256 = hashlib.sha256(plaintext).hexdigest()

        # strip trailing .cbx to restore original extension
        base = os.path.basename(cbx_path)
        if base.endswith(CBX_SUFFIX):
            orig_name = base[:-len(CBX_SUFFIX)]
        else:
            orig_name = base
        tmp_path = os.path.join(session_dir, orig_name)

        with open(tmp_path, "wb") as fh:
            fh.write(plaintext)

        # --- persist session record BEFORE launching LO -----------------
        rec = SessionRecord(
            session_id=session_id,
            cbx_path=os.path.abspath(cbx_path),
            tmp_path=os.path.abspath(tmp_path),
            orig_sha256=orig_sha256,
            key_version=self.key_version,
            ts=__import__("time").time(),
        )
        self.session_store.save(rec)

        if aud:
            aud("decrypt", orig_sha256, self.key_version, True, None)

        # --- launch controlled soffice (Job Object bound) ---------------
        profile = r"S:\.cipherbox-profile\controlled"
        pipe_name = f"cipherbox-controlled-{session_id}"
        env = dict(os.environ)
        env["TMP"] = session_dir
        env["TEMP"] = session_dir

        if launch is None:
            raise RuntimeError("launch_soffice callback not provided")

        pid = launch(tmp_path, profile, pipe_name, env)

        job: JobObject | None = None
        try:
            job = JobObject()
            job.assign_process(pid)
            bind_office_children(job, pid, log=self.log)
        except Exception as exc:
            # Job Object failure is non-fatal for open; continue without it.
            # Loud on the console: a dead job backstop means the session-end
            # office exit depends entirely on desktop.terminate() succeeding.
            self.log(f"[agent] job: bind failed ({exc}); kill-on-close disabled")

        # --- attach the interceptor link (todo 14 hard ordering) --------
        # The link worker registers the forced-encrypt interceptor on every
        # frame and only then loads the temp plaintext.  Registration failure
        # is session-fatal (fail-closed): no un-intercepted document window
        # may survive, so the GUI is job-killed and every trace is deleted.
        link = None
        if attach is not None:
            try:
                link = attach(pipe_name, tmp_path)
            except Exception as exc:
                if job is not None:
                    job.close()  # KILL_ON_JOB_CLOSE kills the soffice we started
                    job = None
                self._delete_quiet(tmp_path)
                self._rmdir_quiet(session_dir)
                self.session_store.delete(session_id)
                raise RuntimeError(
                    f"interceptor link failed; session aborted: {exc}") from exc

        # --- wait for document-level close ------------------------------
        closed_cleanly = False
        if link is not None:
            try:
                closed = link.wait_close()
                closed_cleanly = not bool(closed.get("crashed", True))
            except Exception:
                closed_cleanly = False
            link.kill()  # guard: the worker exits itself on every normal path
        elif wait is not None:
            try:
                closed_cleanly = wait(pid, timeout_s=0)  # 0 = block indefinitely
            except Exception:
                closed_cleanly = False

        # --- terminate the controlled GUI BEFORE touching the temp ------
        # On the link path the worker reports document close while the Start
        # Center (or a wedged soffice) may still hold the temp file; the
        # KILL_ON_JOB_CLOSE job ends it, then the settle loop waits for the
        # lock release so the hash/re-encrypt below reads a settled file.
        if job is not None:
            job.close()
            job = None

        # --- re-encrypt if changed --------------------------------------
        changed = False
        re_encrypted = False
        current = self._read_settled(tmp_path, plaintext)
        if current is not None:
            changed = (hashlib.sha256(current).hexdigest() != orig_sha256)

        if changed and reenc is not None:
            try:
                reenc(tmp_path, rec.cbx_path, used_pw)
                re_encrypted = True
                if aud:
                    aud("encrypt", hashlib.sha256(current).hexdigest(),
                        self.key_version, True, None)
            except Exception as exc:
                if aud:
                    aud("encrypt", hashlib.sha256(current).hexdigest(),
                        self.key_version, False, str(exc))

        # --- cleanup: delete temp cleartext + session record ------------
        self._delete_quiet(tmp_path)
        self._rmdir_quiet(session_dir)
        self.session_store.delete(session_id)

        return OpenResult(
            session_id=session_id,
            tmp_path=tmp_path,
            cbx_path=rec.cbx_path,
            changed=changed,
            re_encrypted=re_encrypted,
        )

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _read_settled(path: str, fallback: bytes, attempts: int = 20,
                      delay_s: float = 0.25) -> bytes | None:
        """Read the temp plaintext after the controlled GUI was killed: the
        dying process releases the file lock asynchronously, so a few bounded
        retries.  None = the temp vanished (nothing to compare/re-encrypt)."""
        import time

        for attempt in range(attempts):
            try:
                with open(path, "rb") as fh:
                    return fh.read()
            except FileNotFoundError:
                return None  # deleted elsewhere: nothing to do
            except OSError:
                if attempt == attempts - 1:
                    return None
                time.sleep(delay_s)
        return None

    @staticmethod
    def _delete_quiet(path: str) -> None:
        try:
            os.remove(path)
        except OSError:
            pass

    @staticmethod
    def _rmdir_quiet(path: str) -> None:
        try:
            os.rmdir(path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# named-mutex serialization (single controlled session at a time)
# ---------------------------------------------------------------------------

class SingleInstanceMutex:
    """Ensures only one controlled-open session runs at a time (Windows named mutex).

    Uses CreateMutexW(bInitialOwner=True) + GetLastError(ERROR_ALREADY_EXISTS)
    so a second instance in *another process* detects the held mutex.
    """

    ERROR_ALREADY_EXISTS = 183

    def __init__(self, name: str = MUTEX_NAME) -> None:
        self.name = name
        kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
        self._kernel32 = kernel32
        self._mutex = kernel32.CreateMutexW(None, True, name)  # bInitialOwner=True
        if not self._mutex:
            raise ctypes.WinError(ctypes.get_last_error())
        # use_last_error=True: ctypes restores the thread error code after the
        # call, so the Win32 GetLastError() would return the PRE-call value.
        # ctypes.get_last_error() is the only reliable reader here.
        last_err = ctypes.get_last_error()
        self._owned = last_err != self.ERROR_ALREADY_EXISTS
        if not self._owned:
            # Another instance owns it; release our (non-owning) handle.
            kernel32.CloseHandle(self._mutex)
            self._mutex = None

    def acquired(self) -> bool:
        return self._owned

    def release(self) -> None:
        if self._mutex:
            self._kernel32.ReleaseMutex(self._mutex)
            self._kernel32.CloseHandle(self._mutex)
            self._mutex = None

    def __enter__(self) -> "SingleInstanceMutex":
        return self

    def __exit__(self, *exc) -> None:
        self.release()
