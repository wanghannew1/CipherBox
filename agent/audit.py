"""Agent-side audit reporting with local queue (plan todo 15).

Unified ``report(action, file_hash, key_version, ok)`` envelope carrying the
agent token + machine name.  ``employee`` is resolved server-side from the
Bearer token — the client never impersonates.

On POST /events failure, events are durably staged to a DPAPI-encrypted
queue at ``%APPDATA%\\CipherBox\\audit-queue.json`` and replayed when the
network returns.  Capacity is capped (default 10000); when full the oldest
entries are dropped and one meta event (ok=false) records how many were lost.

Windows-only (DPAPI).  Python 3.11+.
"""

from __future__ import annotations

import json
import os
import socket
import time
from dataclasses import dataclass, field
from typing import Callable

if os.name != "nt":  # pragma: no cover - Windows-only agent
    raise ImportError("agent/audit.py is Windows-only")

import ctypes
from ctypes import wintypes

import requests

QUEUE_FILE = os.path.expandvars(r"%APPDATA%\CipherBox\audit-queue.json")
DEFAULT_CAPACITY = 10_000
EVENTS_ENDPOINT = "/events"


# ---------------------------------------------------------------------------
# DPAPI (local queue encryption)
# ---------------------------------------------------------------------------

def _dpapi_encrypt(plaintext: bytes) -> bytes:
    crypt32 = ctypes.WinDLL("crypt32.dll")
    kernel32 = ctypes.WinDLL("kernel32.dll")
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
        kernel32.LocalFree(ctypes.cast(out_b.pbData, ctypes.c_void_p))


def _dpapi_decrypt(ciphertext: bytes) -> bytes:
    crypt32 = ctypes.WinDLL("crypt32.dll")
    kernel32 = ctypes.WinDLL("kernel32.dll")
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
        kernel32.LocalFree(ctypes.cast(out_b.pbData, ctypes.c_void_p))


# ---------------------------------------------------------------------------
# AuditReporter
# ---------------------------------------------------------------------------

@dataclass
class QueuedEvent:
    action: str
    file_hash: str
    key_version: int | None
    machine: str
    ok: bool
    ts: float
    error: str | None = None
    meta: bool = False  # True for capacity-overflow meta events


class AuditReporter:
    """Send audit events to the server; stage failures to a local DPAPI queue."""

    def __init__(
        self,
        *,
        server_url: str,
        token: str,
        machine: str | None = None,
        queue_file: str = QUEUE_FILE,
        capacity: int = DEFAULT_CAPACITY,
        timeout: float = 10.0,
        ca_bundle: str | None = None,
        http_post: Callable[[str, dict, float, str | None], requests.Response] | None = None,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.token = token
        self.machine = machine or socket.gethostname()
        self.queue_file = queue_file
        self.capacity = capacity
        self.timeout = timeout
        self.ca_bundle = ca_bundle
        self.http_post = http_post or self._default_post
        self._queue: list[dict] = self._load_queue()

    # -- public API ------------------------------------------------------

    def report(
        self,
        action: str,
        file_hash: str,
        key_version: int | None,
        ok: bool,
        error: str | None = None,
        meta: bool = False,
    ) -> bool:
        """Report one audit event.  Returns True if sent to server immediately.

        On failure the event is staged to the local queue.
        """
        event = {
            "action": action,
            "file_hash": file_hash,
            "key_version": key_version,
            "machine": self.machine,
            "ok": ok,
            "ts": time.time(),
            "error": error,
            "meta": meta,
        }
        if self._post_event(event):
            return True
        self._enqueue(event)
        return False

    def flush(self) -> int:
        """Replay all queued events to the server.  Returns number dispatched."""
        if not self._queue:
            return 0
        remaining: list[dict] = []
        dispatched = 0
        for ev in self._queue:
            if self._post_event(ev):
                dispatched += 1
            else:
                remaining.append(ev)
        self._queue = remaining
        self._save_queue()
        return dispatched

    # -- internal: HTTP --------------------------------------------------

    def _default_post(
        self, event: dict, timeout: float, ca_bundle: str | None
    ) -> requests.Response:
        return requests.post(
            f"{self.server_url}{EVENTS_ENDPOINT}",
            headers={"Authorization": f"Bearer {self.token}"},
            json=event,
            timeout=timeout,
            verify=ca_bundle,
        )

    def _post_event(self, event: dict) -> bool:
        try:
            resp = self.http_post(event, self.timeout, self.ca_bundle)
            return resp.status_code in (200, 202)
        except Exception:
            return False

    # -- internal: queue -------------------------------------------------

    def _enqueue(self, event: dict) -> None:
        self._queue.append(event)
        if len(self._queue) > self.capacity:
            dropped = len(self._queue) - self.capacity
            self._queue = self._queue[-self.capacity:]
            # Meta event recording overflow (ok=false).
            self._queue.append({
                "action": "audit_queue_overflow",
                "file_hash": "0" * 64,
                "key_version": None,
                "machine": self.machine,
                "ok": False,
                "ts": time.time(),
                "error": f"offline queue full, dropped {dropped} oldest events",
                "meta": True,
            })
        self._save_queue()

    def _load_queue(self) -> list[dict]:
        if not os.path.exists(self.queue_file):
            return []
        try:
            with open(self.queue_file, "rb") as fh:
                encrypted = fh.read()
            blob = _dpapi_decrypt(encrypted)
            return json.loads(blob.decode("utf-8"))
        except Exception:
            return []

    def _save_queue(self) -> None:
        os.makedirs(os.path.dirname(self.queue_file), exist_ok=True)
        blob = json.dumps(self._queue, sort_keys=True).encode("utf-8")
        encrypted = _dpapi_encrypt(blob)
        with open(self.queue_file, "wb") as fh:
            fh.write(encrypted)

    def clear_queue(self) -> None:
        """Drop all queued events (for tests)."""
        self._queue = []
        try:
            os.remove(self.queue_file)
        except OSError:
            pass
