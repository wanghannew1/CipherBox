"""Pure cryptography for the CipherBox DataSpaces engine -- no ``uno`` dependency.

Extracted from ``cipherbox.py`` so the Agent (plain CPython on PATH) and the in-process
LibreOffice component share one implementation of the exact same algorithms:

* AES-256-CBC with PKCS#7 padding, via Windows CNG (``bcrypt.dll``) over ``ctypes``
* PBKDF2-HMAC-SHA256 key derivation (fixed salt) and per-file password verifiers
  (random per-file salt)
* the ``EncryptedPackage`` payload building blocks (``_i64`` length prefix) and the
  DataSpaceInfo password-verifier trailer parser

Only extraction, no algorithm change: every function is byte-compatible with the
original ``cipherbox.py`` implementation.  Windows-only (CNG), Python 3.11+.
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import os
import sys
import tempfile
from ctypes import wintypes

IV_LEN = 16
KEY_LEN = 32
PBKDF2_ITERATIONS = 20000
PBKDF2_SALT = b"CipherBoxDataSpace-v1"

# Password-verification block.  oox decides whether a candidate password is correct purely
# from the boolean returned by XPackageEncryption::generateEncryptionKey(); the verifier
# trailer appended to DataSpaceInfo lets the engine (and the agent-side container parser)
# answer that question honestly.
VERIFIER_MAGIC = b"CBPV"
VERIFIER_SALT_LEN = 16
VERIFIER_HASH_LEN = 32
VERIFIER_TRAILER_LEN = 4 + 4 + VERIFIER_SALT_LEN + 4 + VERIFIER_HASH_LEN

_LOG_PATH = os.path.join(tempfile.gettempdir(), "cipherbox-encryption.log")


def _log(message: str) -> None:
    line = "[CipherBoxCrypto] %s" % message
    try:
        with open(_LOG_PATH, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError:
        pass
    try:
        print(line, file=sys.stderr)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Windows CNG (bcrypt.dll) AES-256-CBC
# ---------------------------------------------------------------------------

_BCRYPT_SUCCESS = 0
_PBYTE = ctypes.POINTER(ctypes.c_ubyte)


def _load_bcrypt():
    dll = ctypes.WinDLL("bcrypt.dll")
    dll.BCryptOpenAlgorithmProvider.argtypes = [
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        wintypes.ULONG,
    ]
    dll.BCryptOpenAlgorithmProvider.restype = ctypes.c_long
    dll.BCryptCloseAlgorithmProvider.argtypes = [ctypes.c_void_p, wintypes.ULONG]
    dll.BCryptCloseAlgorithmProvider.restype = ctypes.c_long
    dll.BCryptSetProperty.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        _PBYTE,
        wintypes.ULONG,
        wintypes.ULONG,
    ]
    dll.BCryptSetProperty.restype = ctypes.c_long
    dll.BCryptGetProperty.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        _PBYTE,
        wintypes.ULONG,
        ctypes.POINTER(wintypes.ULONG),
        wintypes.ULONG,
    ]
    dll.BCryptGetProperty.restype = ctypes.c_long
    dll.BCryptGenerateSymmetricKey.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
        _PBYTE,
        wintypes.ULONG,
        _PBYTE,
        wintypes.ULONG,
        wintypes.ULONG,
    ]
    dll.BCryptGenerateSymmetricKey.restype = ctypes.c_long
    dll.BCryptDestroyKey.argtypes = [ctypes.c_void_p]
    dll.BCryptDestroyKey.restype = ctypes.c_long
    for name in ("BCryptEncrypt", "BCryptDecrypt"):
        fn = getattr(dll, name)
        fn.argtypes = [
            ctypes.c_void_p,
            _PBYTE,
            wintypes.ULONG,
            ctypes.c_void_p,
            _PBYTE,
            wintypes.ULONG,
            _PBYTE,
            wintypes.ULONG,
            ctypes.POINTER(wintypes.ULONG),
            wintypes.ULONG,
        ]
        fn.restype = ctypes.c_long
    return dll


def _as_pbuf(data: bytes):
    """Wrap bytes in a c_ubyte array; ctypes keeps it alive for the duration of the call."""
    if not data:
        return ctypes.cast(None, _PBYTE)
    return (ctypes.c_ubyte * len(data)).from_buffer_copy(data)


def _cbc_raw(key: bytes, iv: bytes, data: bytes, encrypt: bool) -> bytes:
    """Raw AES-256-CBC block transform via Windows CNG (no padding applied)."""
    if len(key) != KEY_LEN:
        raise ValueError("AES-256 needs a %d-byte key, got %d" % (KEY_LEN, len(key)))
    if len(iv) != IV_LEN:
        raise ValueError("AES-CBC needs a %d-byte IV, got %d" % (IV_LEN, len(iv)))
    if not data:
        # CNG rejects a zero-length CBC transform (input must be a whole number of blocks).
        return b""
    if len(data) % 16:
        raise ValueError("AES-CBC input must be a multiple of 16 bytes, got %d" % len(data))

    dll = _load_bcrypt()
    alg = ctypes.c_void_p()
    status = dll.BCryptOpenAlgorithmProvider(ctypes.byref(alg), "AES", None, 0)
    if status != _BCRYPT_SUCCESS:
        raise OSError("BCryptOpenAlgorithmProvider failed: 0x%08X" % (status & 0xFFFFFFFF))

    key_handle = ctypes.c_void_p()
    try:
        mode = "ChainingModeCBC".encode("utf-16-le") + b"\x00\x00"
        mode_buf = (ctypes.c_ubyte * len(mode)).from_buffer_copy(mode)
        status = dll.BCryptSetProperty(alg, "ChainingMode", mode_buf, len(mode), 0)
        if status != _BCRYPT_SUCCESS:
            raise OSError("BCryptSetProperty(ChainingMode) failed: 0x%08X" % (status & 0xFFFFFFFF))

        # The symmetric key object size is provider-defined and BCryptGetProperty is not
        # reliable across providers, so grow the buffer until the call succeeds.
        status = 0
        for object_size in (32, 64, 128, 256, 512, 1024, 2048, 4096):
            key_object = (ctypes.c_ubyte * object_size)()
            status = dll.BCryptGenerateSymmetricKey(
                alg,
                ctypes.byref(key_handle),
                ctypes.cast(key_object, _PBYTE),
                object_size,
                _as_pbuf(key),
                len(key),
                0,
            )
            if status == _BCRYPT_SUCCESS:
                _log("key object buffer = %d bytes" % object_size)
                break
            key_handle = ctypes.c_void_p()
        if status != _BCRYPT_SUCCESS:
            raise OSError(
                "BCryptGenerateSymmetricKey failed: 0x%08X" % (status & 0xFFFFFFFF)
            )

        out = (ctypes.c_ubyte * (len(data) + 32))()
        produced = wintypes.ULONG(0)
        fn = dll.BCryptEncrypt if encrypt else dll.BCryptDecrypt
        status = fn(
            key_handle,
            _as_pbuf(data),
            len(data),
            None,
            _as_pbuf(iv),
            len(iv),
            ctypes.cast(out, _PBYTE),
            len(out),
            ctypes.byref(produced),
            0,
        )
        if status != _BCRYPT_SUCCESS:
            raise OSError(
                "BCrypt%s failed: 0x%08X" % ("Encrypt" if encrypt else "Decrypt", status & 0xFFFFFFFF)
            )
        return bytes(bytearray(out[: produced.value]))
    finally:
        if key_handle:
            dll.BCryptDestroyKey(key_handle)
        dll.BCryptCloseAlgorithmProvider(alg, 0)


def _pkcs7_pad(data: bytes) -> bytes:
    pad = 16 - (len(data) % 16)
    return data + bytes([pad]) * pad


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % 16:
        raise ValueError("invalid PKCS#7 payload length %d" % len(data))
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("invalid PKCS#7 padding (key mismatch or corrupt payload)")
    return data[:-pad]


def aes_cbc(key: bytes, iv: bytes, data: bytes, encrypt: bool) -> bytes:
    """AES-256-CBC with PKCS#7 padding, as used for the EncryptedPackage payload."""
    if encrypt:
        return _cbc_raw(key, iv, _pkcs7_pad(data), True)
    return _pkcs7_unpad(_cbc_raw(key, iv, data, False))


def derive_key(password: str) -> bytes:
    """PBKDF2-HMAC-SHA256, 20000 iterations, fixed salt -> 32-byte AES key."""
    return hashlib.pbkdf2_hmac(
        "sha256", (password or "").encode("utf-8"), PBKDF2_SALT, PBKDF2_ITERATIONS, KEY_LEN
    )


def derive_verifier(password: str, salt: bytes) -> bytes:
    """Per-file password verifier: PBKDF2 over a *random* per-file salt.

    The AES key itself uses a fixed salt (see derive_key), so a verifier is needed to tell
    oox whether a candidate password is correct before anything is decrypted.  A per-file
    random salt keeps the verifier from being precomputable across files.
    """
    return hashlib.pbkdf2_hmac(
        "sha256", (password or "").encode("utf-8"), salt, PBKDF2_ITERATIONS, VERIFIER_HASH_LEN
    )


def make_verifier(password: str):
    """Return ``(salt, hash)`` for a fresh password verifier."""
    salt = os.urandom(VERIFIER_SALT_LEN)
    return salt, derive_verifier(password, salt)


def verifier_matches(password: str, salt: bytes, expected: bytes) -> bool:
    """Constant-time check of ``password`` against a stored verifier."""
    if not salt or not expected:
        # No verifier stored (e.g. a pre-existing file): accept, to stay backward compatible.
        return True
    return hmac.compare_digest(derive_verifier(password, salt), expected)


# ---------------------------------------------------------------------------
# Payload / verifier-trailer building blocks
# ---------------------------------------------------------------------------


def _i64(value: int) -> bytes:
    return int(value).to_bytes(8, "little", signed=True)


def _parse_verifier(blob: bytes):
    """Recover ``(salt, hash)`` from a DataSpaceInfo stream, or ``(None, None)``.

    The verifier is a fixed-shape trailer appended to DataSpaceInfo, so it is located at a
    known offset from the end and then validated field by field.  A file written before the
    verifier existed simply has no trailer and is treated as "no verifier" (which
    verifier_matches() accepts, keeping old files loadable).
    """
    if not blob or len(blob) < VERIFIER_TRAILER_LEN:
        return None, None
    start = len(blob) - VERIFIER_TRAILER_LEN
    if blob[start : start + 4] != VERIFIER_MAGIC:
        return None, None
    offset = start + 4
    salt_len = int.from_bytes(blob[offset : offset + 4], "little", signed=False)
    offset += 4
    if salt_len != VERIFIER_SALT_LEN:
        return None, None
    salt = bytes(blob[offset : offset + salt_len])
    offset += salt_len
    hash_len = int.from_bytes(blob[offset : offset + 4], "little", signed=False)
    offset += 4
    if hash_len != VERIFIER_HASH_LEN or offset + hash_len != len(blob):
        return None, None
    digest = bytes(blob[offset : offset + hash_len])
    return salt, digest
