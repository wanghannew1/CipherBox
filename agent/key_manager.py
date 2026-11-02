"""Agent-side master-key management with DPAPI local cache (plan todo 11).

Responsibilities:
- Fetch the FULL key-version set from the server (POST /key, authenticated).
- Encrypt the cache with Windows DPAPI and persist to
  ``%APPDATA%\\CipherBox\\keycache.dat`` (outside the VeraCrypt volume).
- On open: try every cached version against the .cbx verifier (via
  ``agent/container.py``) until one matches; return (version, password).
- Before encrypt: if online, refresh the version set from the server first;
  offline, use the cached set.
- 401 / unreachable -> explicit error, never fall back to an empty key.
- No matching version -> explicit "key missing" error, never silent failure.

Windows-only (DPAPI via ctypes).  Python 3.11+.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import requests

# Repo layout: agent/ is next to server/ and lo-encryption-demo/ under repo root.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
if str(_REPO_ROOT / "lo-encryption-demo" / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "lo-encryption-demo" / "src"))

from agent.container import CbxContainer, WrongKeyError  # noqa: E402

KEYCACHE_DIR = os.path.expandvars(r"%APPDATA%\CipherBox")
KEYCACHE_FILE = os.path.join(KEYCACHE_DIR, "keycache.dat")

# DPAPI flags
_CRYPTPROTECT_UI_FORBIDDEN = 0x00000001


class KeyManagerError(Exception):
    """Base error: key missing / server unreachable / auth failed."""


class KeyNotFoundError(KeyManagerError):
    """No cached key version can decrypt the container."""


class ServerAuthError(KeyManagerError):
    """Server rejected the agent token (401 / revoked / expired)."""


class ServerUnreachableError(KeyManagerError):
    """Server cannot be reached and no usable cache exists."""


# ---------------------------------------------------------------------------
# Windows DPAPI (ctypes over crypt32.dll)
# ---------------------------------------------------------------------------

def _is_windows() -> bool:
    return sys.platform == "win32"


def dpapi_encrypt(plaintext: bytes) -> bytes:
    """Encrypt bytes with DPAPI (current user, machine store). Windows-only."""
    if not _is_windows():
        raise KeyManagerError("DPAPI is Windows-only; cannot encrypt key cache on this platform")
    import ctypes
    from ctypes import wintypes

    crypt32 = ctypes.WinDLL("crypt32.dll")
    kernel32 = ctypes.WinDLL("kernel32.dll")

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),  # pDataIn
        ctypes.c_wchar_p,           # szDataDescr
        ctypes.POINTER(DATA_BLOB),  # pOptionalEntropy
        ctypes.c_void_p,            # pvReserved
        ctypes.c_void_p,            # pPromptStruct
        wintypes.DWORD,             # dwFlags
        ctypes.POINTER(DATA_BLOB),  # pDataOut
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    def _blob(data: bytes) -> DATA_BLOB:
        buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data) if data else None
        return DATA_BLOB(len(data) if data else 0, buf)

    in_blob = _blob(plaintext)
    out_blob = DATA_BLOB()
    ok = crypt32.CryptProtectData(
        ctypes.byref(in_blob), None, None, None, None,
        _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out_blob),
    )
    if not ok:
        raise KeyManagerError("DPAPI CryptProtectData failed")
    try:
        result = bytes(out_blob.pbData[: out_blob.cbData])
    finally:
        kernel32.LocalFree(ctypes.cast(out_blob.pbData, ctypes.c_void_p))
    return result


def dpapi_decrypt(ciphertext: bytes) -> bytes:
    """Decrypt DPAPI-encrypted bytes. Windows-only."""
    if not _is_windows():
        raise KeyManagerError("DPAPI is Windows-only; cannot decrypt key cache on this platform")
    import ctypes
    from ctypes import wintypes

    crypt32 = ctypes.WinDLL("crypt32.dll")
    kernel32 = ctypes.WinDLL("kernel32.dll")

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),  # pDataIn
        ctypes.POINTER(ctypes.c_wchar_p),  # ppszDataDescr
        ctypes.POINTER(DATA_BLOB),  # pOptionalEntropy
        ctypes.c_void_p,            # pvReserved
        ctypes.c_void_p,            # pPromptStruct
        wintypes.DWORD,             # dwFlags
        ctypes.POINTER(DATA_BLOB),  # pDataOut
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL

    def _blob(data: bytes) -> DATA_BLOB:
        buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data) if data else None
        return DATA_BLOB(len(data) if data else 0, buf)

    in_blob = _blob(ciphertext)
    out_blob = DATA_BLOB()
    descr = ctypes.c_wchar_p()
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob), ctypes.byref(descr), None, None, None,
        _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out_blob),
    )
    if not ok:
        raise KeyManagerError("DPAPI CryptUnprotectData failed (cache may be bound to another user/machine)")
    try:
        result = bytes(out_blob.pbData[: out_blob.cbData])
    finally:
        kernel32.LocalFree(ctypes.cast(out_blob.pbData, ctypes.c_void_p))
    return result


# ---------------------------------------------------------------------------
# KeyVersion / cache model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CachedKey:
    version: int
    key: str  # 64-hex master key / password


@dataclass(frozen=True)
class KeySet:
    versions: list[CachedKey]
    current: int | None

    def by_version(self, version: int) -> CachedKey | None:
        for v in self.versions:
            if v.version == version:
                return v
        return None

    def __iter__(self) -> Iterable[CachedKey]:
        # current version first, then the rest descending.
        ordered = sorted(self.versions, key=lambda v: v.version, reverse=True)
        return iter(ordered)


# ---------------------------------------------------------------------------
# KeyManager
# ---------------------------------------------------------------------------

class KeyManager:
    """Fetch, cache (DPAPI), and resolve master-key versions for .cbx containers."""

    def __init__(
        self,
        server_url: str,
        token: str,
        *,
        cache_file: str = KEYCACHE_FILE,
        timeout: float = 10.0,
        ca_bundle: str | None = None,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.token = token
        self.cache_file = cache_file
        self.timeout = timeout
        self.ca_bundle = ca_bundle
        self._keys: KeySet | None = None

    # -- network -----------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    def fetch_from_server(self) -> KeySet:
        """POST-equivalent GET /key from the server. Raises on 401/unreachable."""
        try:
            resp = requests.get(
                f"{self.server_url}/key",
                headers=self._headers(),
                timeout=self.timeout,
                verify=self.ca_bundle,
            )
        except requests.RequestException as exc:
            raise ServerUnreachableError(
                f"cannot reach key server at {self.server_url}: {exc}"
            ) from exc

        if resp.status_code == 401:
            raise ServerAuthError(
                "server rejected agent token (401: revoked/expired/unknown). "
                "Reconfigure the agent with a valid employee token."
            )
        if resp.status_code != 200:
            raise KeyManagerError(
                f"key server returned HTTP {resp.status_code}: {resp.text[:200]}"
            )

        body = resp.json()
        versions = [
            CachedKey(version=int(v["version"]), key=str(v["key"]))
            for v in body.get("versions", [])
        ]
        current = body.get("current")
        return KeySet(versions=versions, current=int(current) if current is not None else None)

    def save_cache(self, key_set: KeySet) -> None:
        """DPAPI-encrypt and persist the key set to the local cache file."""
        os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
        payload = {
            "current": key_set.current,
            "versions": [{"version": v.version, "key": v.key} for v in key_set.versions],
        }
        blob = json.dumps(payload, sort_keys=True).encode("utf-8")
        encrypted = dpapi_encrypt(blob)
        with open(self.cache_file, "wb") as fh:
            fh.write(encrypted)

    def load_cache(self) -> KeySet | None:
        """Load and DPAPI-decrypt the local cache. Returns None if absent/corrupt."""
        if not os.path.exists(self.cache_file):
            return None
        try:
            with open(self.cache_file, "rb") as fh:
                encrypted = fh.read()
            blob = dpapi_decrypt(encrypted)
            payload = json.loads(blob.decode("utf-8"))
            versions = [
                CachedKey(version=int(v["version"]), key=str(v["key"]))
                for v in payload.get("versions", [])
            ]
            return KeySet(versions=versions, current=payload.get("current"))
        except (KeyManagerError, OSError, json.JSONDecodeError, KeyError, ValueError):
            return None

    # -- public API --------------------------------------------------------

    def ensure_keys(self, online: bool = True) -> KeySet:
        """Return a usable KeySet: refresh from server if online, else cache.

        Raises ServerUnreachableError if offline and no cache exists.
        Raises ServerAuthError if the token is rejected.
        """
        if online:
            try:
                key_set = self.fetch_from_server()
                self.save_cache(key_set)
                self._keys = key_set
                return key_set
            except ServerUnreachableError:
                # Fall through to cache.
                pass
            except ServerAuthError:
                raise  # do NOT fall back to cache on auth failure

        cached = self.load_cache()
        if cached is not None:
            self._keys = cached
            return cached
        raise ServerUnreachableError(
            "offline and no key cache available; cannot encrypt/decrypt"
        )

    @property
    def keys(self) -> KeySet:
        if self._keys is None:
            raise KeyManagerError("keys not loaded: call ensure_keys() first")
        return self._keys

    def current_key(self) -> CachedKey:
        """Return the current (highest-version) key, for encryption."""
        key_set = self.keys
        if key_set.current is not None:
            cur = key_set.by_version(key_set.current)
            if cur is not None:
                return cur
        # Fall back to highest version present.
        if key_set.versions:
            return max(key_set.versions, key=lambda v: v.version)
        raise KeyManagerError("no key versions available")

    def resolve_key_for_container(
        self, container: CbxContainer
    ) -> tuple[CachedKey, bytes]:
        """Try every cached key version against the container verifier.

        Returns (matched_key, plaintext).  Raises KeyNotFoundError if none match.
        """
        key_set = self.keys
        if not key_set.versions:
            raise KeyNotFoundError("no cached key versions available")

        last_err: str | None = None
        for cached in key_set:
            try:
                plain, _used = container.decrypt([cached.key])
                return cached, plain
            except WrongKeyError as exc:
                last_err = str(exc)
                continue
            except ValueError:
                # padding invalid for this candidate -> wrong key
                last_err = "padding invalid"
                continue

        raise KeyNotFoundError(
            f"no cached key version decrypts this container ({last_err or 'unknown'})"
        )
