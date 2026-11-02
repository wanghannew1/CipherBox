"""Windows named-pipe transport for .cbx open requests (plan todo 14 queue).

Protocol (one JSON line each way, UTF-8, byte-mode pipe):

    request   {"cmd": "open", "path": "<absolute .cbx path>"}
    response  {"ok": true, ...}  |  {"ok": false, "error": "..."}

The server handles ONE connection at a time (serial controlled sessions);
requests queue naturally at the pipe while a session runs.  Win32 bindings
live in :mod:`agent.winpipe` (pywin32 is broken on this workstation).
"""

from __future__ import annotations

import ctypes
import json
import sys
import threading
import time
from ctypes import wintypes

from agent.winpipe import (
    BUFFER_SIZE,
    ERROR_IO_PENDING,
    ERROR_PIPE_BUSY,
    ERROR_PIPE_CONNECTED,
    GENERIC_READ_WRITE,
    INVALID_HANDLE,
    OPEN_EXISTING,
    OVERLAPPED,
    PIPE_ACCESS_DUPLEX,
    PIPE_READMODE_BYTE,
    PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES,
    PIPE_WAIT,
    WAIT_OBJECT_0,
    FILE_FLAG_OVERLAPPED,
    PipeError,
    create_manual_reset_event,
    encode_line,
    kernel32,
    read_line,
    wait_any,
    write_all,
)

PIPE_NAME = r"\\.\pipe\cipherbox-open"

MAX_REQUEST_BYTES = 64 * 1024


class OpenPipeServer:
    """Serial named-pipe server: accept -> one request -> one response -> next."""

    def __init__(self, handler, pipe_name: str = PIPE_NAME) -> None:
        self.handler = handler
        self.pipe_name = pipe_name
        self.listening = threading.Event()
        self._shutdown = create_manual_reset_event()
        self._shutdown_closed = False

    def stop(self) -> None:
        """Signal the serve loop to exit after the current connection finishes."""
        kernel32.SetEvent(self._shutdown)

    def close(self) -> None:
        if not self._shutdown_closed:
            kernel32.CloseHandle(self._shutdown)
            self._shutdown_closed = True

    # -- loop ----------------------------------------------------------------

    def serve_forever(self) -> None:
        instance = None
        try:
            instance = self._create_instance()
            self.listening.set()
            while True:
                if not self._await_client(instance):
                    break  # shutdown while waiting for a client
                # Standby instance created BEFORE serving the current one so a
                # client arriving right after this connection never finds the
                # pipe absent (no accept window between instances).
                current, instance = instance, None
                next_instance = self._create_instance()
                try:
                    self._serve_one(current)
                finally:
                    kernel32.DisconnectNamedPipe(current)
                    kernel32.CloseHandle(current)
                instance = next_instance
        finally:
            if instance is not None:
                kernel32.CloseHandle(instance)
            self.close()

    def _create_instance(self) -> int:
        handle = kernel32.CreateNamedPipeW(
            self.pipe_name,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, BUFFER_SIZE, BUFFER_SIZE, 0, None,
        )
        if handle in (None, INVALID_HANDLE):
            raise PipeError("CreateNamedPipeW failed", ctypes.get_last_error())
        return handle

    def _await_client(self, handle) -> bool:
        """Wait for a client; False means shutdown fired first."""
        overlapped = OVERLAPPED()
        overlapped.hEvent = create_manual_reset_event()
        try:
            if kernel32.ConnectNamedPipe(handle, ctypes.byref(overlapped)):
                return True  # completed synchronously
            error = ctypes.get_last_error()
            if error == ERROR_PIPE_CONNECTED:
                return True  # client connected between create and connect
            if error != ERROR_IO_PENDING:
                raise PipeError("ConnectNamedPipe failed", error)
            wait = wait_any([overlapped.hEvent, self._shutdown], 0xFFFFFFFF)
            if wait != WAIT_OBJECT_0:  # shutdown fired (or unexpected failure)
                kernel32.CancelIo(handle)
                return False
            transferred = wintypes.DWORD(0)
            if not kernel32.GetOverlappedResult(
                handle, ctypes.byref(overlapped), ctypes.byref(transferred), False
            ):
                raise PipeError("overlapped connect failed", ctypes.get_last_error())
            return True
        finally:
            kernel32.CloseHandle(overlapped.hEvent)

    def _serve_one(self, handle) -> None:
        try:
            line = read_line(handle, MAX_REQUEST_BYTES)
            response = self._dispatch(line)
            write_all(handle, encode_line(response))
            kernel32.FlushFileBuffers(handle)
        except PipeError as exc:
            print(f"[agent] pipe: connection dropped: {exc}", file=sys.stderr)

    def _dispatch(self, line: str) -> dict:
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            return {"ok": False, "error": "malformed JSON request"}
        if not isinstance(request, dict) or request.get("cmd") != "open":
            return {"ok": False, "error": "unsupported request: cmd must be 'open'"}
        path = request.get("path")
        if not isinstance(path, str) or not path:
            return {"ok": False, "error": "missing 'path' in open request"}
        try:
            return self.handler(path)
        except Exception as exc:  # boundary: handler failure -> JSON response
            return {"ok": False, "error": f"open failed: {exc}"}


def connect_and_request(pipe_name: str, request: dict, timeout_s: float = 5.0) -> dict:
    """Send one request line, return the parsed response dict.

    Raises :class:`PipeError` when the pipe is absent, busy past the deadline,
    or the round trip fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        handle = kernel32.CreateFileW(
            pipe_name, GENERIC_READ_WRITE, 0, None, OPEN_EXISTING, 0, None
        )
        if handle not in (None, INVALID_HANDLE):
            break
        error = ctypes.get_last_error()
        if error == ERROR_PIPE_BUSY:
            if time.monotonic() >= deadline:
                raise PipeError("pipe stayed busy", error)
            kernel32.WaitNamedPipeW(pipe_name, 1000)
            continue
        raise PipeError("cannot open pipe", error)
    try:
        write_all(handle, encode_line(request))
        response_line = read_line(handle, MAX_REQUEST_BYTES)
    finally:
        kernel32.CloseHandle(handle)
    try:
        return json.loads(response_line)
    except json.JSONDecodeError as exc:
        raise PipeError(f"unparseable response: {response_line[:200]!r}") from exc
