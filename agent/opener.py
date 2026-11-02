"""Agent-side controlled-open closed loop (plan todo 14).

Decrypts a ``.cbx`` to a temp cleartext under ``S:\.cipherbox-tmp\<uuid>\``,
launches an independent GUI LibreOffice (controlled profile, Job Object bound),
waits for document-level close (XModel dispose/close event), re-encrypts on
change, then deletes the temp cleartext and the session record.

All LibreOffice/UNO interaction is injected via callbacks so the module can be
unit-tested without soffice.  Windows-only (Job Object, DPAPI, named mutex).

Plan references: todo 10 (agent/container.py decrypt), todo 11 (key cache),
todo 13 (encryptor re-encrypt).
"""

from __future__ import annotations

import hashlib
import json
import os
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
        h = kernel32.OpenProcess(0x0001 | 0x0002, False, pid)  # PROCESS_SET_QUOTA|PROCESS_TERMINATE
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
            Start GUI soffice on the temp cleartext; return its PID.
        wait_document_close(pid, timeout_s) -> bool
            Block until the document is closed (XModel dispose/close), or
            timeout.  True = closed cleanly, False = timeout/killed.
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
        wait_document_close: Callable[[int, float], bool] | None = None,
        re_encrypt: Callable[[str, str, str], None] | None = None,
        audit: Callable[[str, str, int | None, bool, str | None], None] | None = None,
    ) -> None:
        self.container = container
        self.passwords = passwords
        self.key_version = key_version
        self.session_store = session_store
        self.tmp_root = tmp_root
        self.launch_soffice = launch_soffice
        self.wait_document_close = wait_document_close
        self.re_encrypt = re_encrypt
        self.audit = audit

    # -- public entry point ----------------------------------------------

    def open_controlled(
        self,
        cbx_path: str,
        *,
        launch_soffice: Callable[[str, str, str, dict], int] | None = None,
        wait_document_close: Callable[[int, float], bool] | None = None,
        re_encrypt: Callable[[str, str, str], None] | None = None,
        audit: Callable[[str, str, int | None, bool, str | None], None] | None = None,
    ) -> OpenResult:
        """Full closed loop: decrypt -> launch LO -> wait close -> re-encrypt -> cleanup."""
        launch = launch_soffice or self.launch_soffice
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
        except Exception:
            # Job Object failure is non-fatal for open; continue without it.
            job = None

        # --- wait for document-level close ------------------------------
        closed_cleanly = False
        if wait is not None:
            try:
                closed_cleanly = wait(pid, timeout_s=0)  # 0 = block indefinitely
            except Exception:
                closed_cleanly = False

        # --- re-encrypt if changed --------------------------------------
        changed = False
        re_encrypted = False
        try:
            with open(tmp_path, "rb") as fh:
                current = fh.read()
            changed = (hashlib.sha256(current).hexdigest() != orig_sha256)
        except OSError:
            current = plaintext
            changed = False

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
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        try:
            os.rmdir(session_dir)
        except OSError:
            pass
        self.session_store.delete(session_id)

        if job is not None:
            job.close()

        return OpenResult(
            session_id=session_id,
            tmp_path=tmp_path,
            cbx_path=rec.cbx_path,
            changed=changed,
            re_encrypted=re_encrypted,
        )


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
        last_err = kernel32.GetLastError()
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
