"""Raw Win32 named-pipe primitives via ctypes.

pywin32 was verified BROKEN on the reference workstation (``import win32pipe``
fails with a DLL load error), so this module binds the Win32 named-pipe API
directly.  No TCP: a named pipe's default DACL is bound to the creating user,
while loopback TCP would be reachable across user sessions (plan-forbidden).

Shared by the open-request server and its thin client (agent/ipc.py).
"""

from __future__ import annotations

import ctypes
import json
from ctypes import wintypes

GENERIC_READ_WRITE = 0xC0000000
PIPE_ACCESS_DUPLEX = 0x00000003
FILE_FLAG_OVERLAPPED = 0x40000000
PIPE_TYPE_BYTE = 0x00000000
PIPE_READMODE_BYTE = 0x00000000
PIPE_WAIT = 0x00000000
PIPE_UNLIMITED_INSTANCES = 0x000000FF
OPEN_EXISTING = 3
INVALID_HANDLE = wintypes.HANDLE(-1).value
INFINITE = 0xFFFFFFFF
WAIT_OBJECT_0 = 0
ERROR_PIPE_CONNECTED = 535
ERROR_PIPE_BUSY = 231
ERROR_IO_PENDING = 997
ERROR_BROKEN_PIPE = 109
ERROR_NO_DATA = 232
PIPE_ABSENT_ERRORS = (2, 3)  # ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND

BUFFER_SIZE = 64 * 1024

kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)


class OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_void_p),
        ("InternalHigh", ctypes.c_void_p),
        ("Offset", wintypes.DWORD),
        ("OffsetHigh", wintypes.DWORD),
        ("hEvent", wintypes.HANDLE),
    ]


class PipeError(Exception):
    """Typed pipe transport failure, carrying the Win32 error code if any."""

    def __init__(self, message: str, winerror: int | None = None) -> None:
        super().__init__(f"{message} (winerror={winerror})" if winerror is not None else message)
        self.winerror = winerror

    @property
    def pipe_absent(self) -> bool:
        """True when the pipe simply does not exist (agent not running)."""
        return self.winerror in PIPE_ABSENT_ERRORS


def _bind() -> None:
    kernel32.CreateNamedPipeW.restype = wintypes.HANDLE
    kernel32.CreateNamedPipeW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
    ]
    kernel32.ConnectNamedPipe.restype = wintypes.BOOL
    kernel32.ConnectNamedPipe.argtypes = [wintypes.HANDLE, ctypes.POINTER(OVERLAPPED)]
    kernel32.DisconnectNamedPipe.restype = wintypes.BOOL
    kernel32.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
    kernel32.ReadFile.restype = wintypes.BOOL
    kernel32.ReadFile.argtypes = [
        wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(OVERLAPPED),
    ]
    kernel32.WriteFile.restype = wintypes.BOOL
    kernel32.WriteFile.argtypes = [
        wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(OVERLAPPED),
    ]
    kernel32.FlushFileBuffers.restype = wintypes.BOOL
    kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CreateEventW.restype = wintypes.HANDLE
    kernel32.CreateEventW.argtypes = [
        wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR,
    ]
    kernel32.SetEvent.restype = wintypes.BOOL
    kernel32.SetEvent.argtypes = [wintypes.HANDLE]
    kernel32.WaitForMultipleObjects.restype = wintypes.DWORD
    kernel32.WaitForMultipleObjects.argtypes = [
        wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE), wintypes.BOOL, wintypes.DWORD,
    ]
    kernel32.GetOverlappedResult.restype = wintypes.BOOL
    kernel32.GetOverlappedResult.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(OVERLAPPED),
        ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
    ]
    kernel32.CancelIo.restype = wintypes.BOOL
    kernel32.CancelIo.argtypes = [wintypes.HANDLE]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    kernel32.WaitNamedPipeW.restype = wintypes.BOOL
    kernel32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]


_bind()


def create_manual_reset_event() -> wintypes.HANDLE:
    handle = kernel32.CreateEventW(None, True, False, None)
    if handle in (None, INVALID_HANDLE):
        raise PipeError("CreateEventW failed", ctypes.get_last_error())
    return handle


def wait_any(handles: list[int], milliseconds: int) -> int:
    """Wait until one handle is signalled; returns the raw Win32 wait code."""
    array = (wintypes.HANDLE * len(handles))(*handles)
    return kernel32.WaitForMultipleObjects(len(handles), array, False, milliseconds)


def encode_line(payload: dict) -> bytes:
    return (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")


def read_line(handle, max_bytes: int) -> str:
    """Read one UTF-8 line; a client that hangs up early yields what arrived."""
    raw = b""
    buffer = ctypes.create_string_buffer(BUFFER_SIZE)
    while b"\n" not in raw:
        if len(raw) > max_bytes:
            raise PipeError("request line exceeds size cap")
        read = wintypes.DWORD(0)
        if not kernel32.ReadFile(handle, buffer, BUFFER_SIZE, ctypes.byref(read), None):
            error = ctypes.get_last_error()
            if error in (ERROR_BROKEN_PIPE, ERROR_NO_DATA):
                break
            raise PipeError("ReadFile failed", error)
        if read.value == 0:
            break
        raw += buffer.raw[: read.value]
    return raw.split(b"\n", 1)[0].decode("utf-8", errors="replace").strip()


def write_all(handle, data: bytes) -> None:
    written = wintypes.DWORD(0)
    if not kernel32.WriteFile(handle, data, len(data), ctypes.byref(written), None):
        raise PipeError("WriteFile failed", ctypes.get_last_error())
    if written.value != len(data):
        raise PipeError(f"short write: {written.value}/{len(data)}")
