"""Real Windows callbacks for ``agent/opener.ControlledOpener``.

The opener is callback-injected so it can be unit-tested without soffice;
this module provides the production callbacks:

* ``launch_soffice`` — start an independent GUI LibreOffice on the temp
  cleartext with the controlled profile + per-session UNO pipe, detached
  from the agent console, returning the PID;
* ``wait_document_close`` — block on the controlled soffice process
  (``OpenProcess`` + ``WaitForSingleObject``).  With the todo-17 interceptor
  link wired (the production path), the opener instead waits on the link
  worker, which detects document-level (XModel) close; this process-exit
  wait remains the fallback when no link handle exists (unit-test path).
"""

from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
from ctypes import wintypes
from pathlib import Path

DEFAULT_SOFFICE = r"C:\Program Files\LibreOffice\program\soffice.exe"

_SYNCHRONIZE = 0x00100000
_WAIT_OBJECT_0 = 0
_INFINITE = 0xFFFFFFFF

kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
kernel32.OpenProcess.restype = ctypes.c_void_p
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]


class LaunchError(Exception):
    """The controlled GUI soffice could not be located or started."""


def find_soffice() -> str:
    exe = shutil.which("soffice")
    if exe:
        return exe
    if os.path.isfile(DEFAULT_SOFFICE):
        return DEFAULT_SOFFICE
    raise LaunchError(
        f"soffice.exe not found on PATH or at {DEFAULT_SOFFICE}; "
        "install LibreOffice or extend PATH"
    )


def launch_soffice(tmp_path: str, profile: str, pipe_name: str, env: dict) -> int:
    """Start the controlled GUI soffice WITHOUT the document (opener contract).

    The temp plaintext is deliberately NOT passed on the command line: the
    link worker loads it via ``loadComponentFromURL`` only AFTER the
    interceptor is registered on every frame (todo 14 hard ordering
    "先注册、后加载" — loading at launch would open a fail-open window in
    which an un-intercepted SaveAs escapes).  ``tmp_path`` is still used for
    the TMP/TEMP environment the caller sets.
    """
    exe = find_soffice()
    profile_uri = Path(profile).as_uri()
    try:
        process = subprocess.Popen(
            [
                exe,
                "-env:UserInstallation=" + profile_uri,
                "--accept=pipe,name=%s;urp;" % pipe_name,
                "--norestore",
            ],
            env=env,
            creationflags=subprocess.DETACHED_PROCESS,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        raise LaunchError(f"cannot start {exe}: {exc}") from exc
    return process.pid


def wait_document_close(pid: int, timeout_s: float) -> bool:
    """Block until the controlled soffice process exits (opener contract).

    ``timeout_s <= 0`` waits indefinitely; otherwise the timeout is in
    seconds.  True = process exited, False = timeout or handle lost.
    """
    handle = kernel32.OpenProcess(_SYNCHRONIZE, False, pid)
    if not handle:
        return False  # already gone / access denied -> treat as closed
    try:
        millis = _INFINITE if timeout_s <= 0 else int(timeout_s * 1000)
        return kernel32.WaitForSingleObject(handle, millis) == _WAIT_OBJECT_0
    finally:
        kernel32.CloseHandle(handle)
