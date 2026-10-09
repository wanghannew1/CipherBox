"""PyUNO implementation of ``com.sun.star.packages.XPackageEncryption``.

Registered as service ``com.sun.star.comp.oox.crypto.CipherBoxDataSpace``; oox resolves that
name by prepending ``com.sun.star.comp.oox.crypto.`` to the ``CryptoType`` value returned
from :meth:`CipherBoxDataSpace.createEncryptionData`.

The MS-OFFCRYPTO DataSpaces container layout is reproduced byte-for-byte from the reference
sample (bzzzil/lo_custom_encryption); only the payload cipher is upgraded from XOR to
AES-256-CBC.  AES is obtained from the Windows CNG provider through ``ctypes`` so the
component has no third-party dependency.
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import os
import sys
import tempfile
import traceback
from ctypes import wintypes

import uno
import unohelper
from com.sun.star.lang import (
    XInitialization,
    XServiceInfo,
    XSingleServiceFactory,
)
from com.sun.star.packages import XPackageEncryption

SERVICE_NAME = "com.sun.star.comp.oox.crypto.CipherBoxDataSpace"
IMPL_NAME = "com.sun.star.comp.oox.crypto.IMPL.CipherBoxDataSpace"

CRYPTO_TYPE = "CipherBoxDataSpace"
DATASPACE_NAME = "CipherBoxDataSpace"
TRANSFORM_NAME = "CipherBoxTransform"

TRANSFORM_GUID = "{C73DFACD-061F-43B0-8B64-AC620D2A8B50}"
TRANSFORM_INFO_NAME = "Microsoft.Metadata.CipherBoxTransform"
FEATURE_IDENTIFIER = "Microsoft.Container.DataSpaces"
REFERENCE_COMPONENT = "EncryptedPackage"

NV_CRYPTO_TYPE = "CryptoType"
NV_KEY = "CipherBoxKey"
# oox hands the engine the password as a NamedValue in the media encryption data and does
# *not* round-trip our CipherBoxKey on the save path, so the key is derived from this.
NV_PASSWORD = "Password"

STREAM_DATASPACEMAP = "\006DataSpaces/DataSpaceMap"
STREAM_VERSION = "\006DataSpaces/Version"
STREAM_DATASPACEINFO = "\006DataSpaces/DataSpaceInfo/" + DATASPACE_NAME
STREAM_TRANSFORMINFO = (
    "\006DataSpaces/TransformInfo/" + TRANSFORM_NAME + "/\006Primary"
)
STREAM_ENCRYPTEDPACKAGE = "EncryptedPackage"

IV_LEN = 16
KEY_LEN = 32
PBKDF2_ITERATIONS = 20000
PBKDF2_SALT = b"CipherBoxDataSpace-v1"

# Password-verification block.  oox decides whether a candidate password is correct purely
# from the boolean returned by XPackageEncryption::generateEncryptionKey() -- see
# PasswordVerifier::verifyPassword() in oox/source/core/filterdetect.cxx, which only calls
# createEncryptionData() when that boolean is true.  A component that always returns true
# therefore makes *every* password "correct", which is why LibreOffice's built-in
# "VelvetSweatshop" default probe would always win and the real password was never reached.
# These values let the engine answer that question honestly.
VERIFIER_MAGIC = b"CBPV"
VERIFIER_SALT_LEN = 16
VERIFIER_HASH_LEN = 32
VERIFIER_TRAILER_LEN = 4 + 4 + VERIFIER_SALT_LEN + 4 + VERIFIER_HASH_LEN

_LOG_PATH = os.path.join(tempfile.gettempdir(), "cipherbox-encryption.log")


def _log(message: str) -> None:
    line = "[CipherBoxDataSpace] %s" % message
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
# MS-OFFCRYPTO DataSpaces container streams
# ---------------------------------------------------------------------------


def _i32(value: int) -> bytes:
    return int(value).to_bytes(4, "little", signed=False)


def _i64(value: int) -> bytes:
    return int(value).to_bytes(8, "little", signed=True)


def _utf16_field(text: str) -> bytes:
    """int32 byte-length prefix, UTF-16LE payload, then 4-byte alignment padding.

    Mirrors the reference sample: ``writeInt32(len * 2)`` + ``writeUnicodeArray`` + padding.
    """
    raw = text.encode("utf-16-le")
    return _i32(len(raw)) + raw + b"\x00" * ((4 - (len(raw) & 3)) & 3)


def data_space_map() -> bytes:
    return b"".join(
        [
            _i32(8),  # header length
            _i32(1),  # entry count
            _i32(0x60),  # entry length
            _i32(1),  # reference count
            _i32(0),  # reference component type
            _utf16_field(REFERENCE_COMPONENT),
            _utf16_field(DATASPACE_NAME),
        ]
    )


def version() -> bytes:
    return b"".join(
        [
            _utf16_field(FEATURE_IDENTIFIER),
            _i32(1),  # reader version
            _i32(1),  # updater version
            _i32(1),  # writer version
        ]
    )


def _verifier_trailer(salt: bytes, digest: bytes) -> bytes:
    """Append-only block appended to DataSpaceInfo so the verifier survives a round trip."""
    return b"".join(
        [
            VERIFIER_MAGIC,
            _i32(len(salt)),
            salt,
            _i32(len(digest)),
            digest,
        ]
    )


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


def data_space_info(salt: bytes = None, digest: bytes = None) -> bytes:
    body = b"".join([_i32(8), _i32(1), _utf16_field(TRANSFORM_NAME)])
    if salt and digest:
        body += _verifier_trailer(salt, digest)
    return body


def transform_info() -> bytes:
    # MS-OFFCRYPTO 2.1.8 TransformInfoHeader; the length field counts the trailing +10 bytes.
    guid_len = len(TRANSFORM_GUID) * 2
    guid_pad = (4 - (len(TRANSFORM_GUID) & 3)) & 3
    return b"".join(
        [
            _i32(guid_len + guid_pad + 10),  # TransformLength
            _i32(1),  # TransformType
            _utf16_field(TRANSFORM_GUID),
            _utf16_field(TRANSFORM_INFO_NAME),
            _i32(1),  # ReaderVersion
            _i32(1),  # UpdateVersion
            _i32(1),  # WriterVersion
            _i32(4),  # ExtensibilityHeader
        ]
    )


# ---------------------------------------------------------------------------
# UNO helpers
# ---------------------------------------------------------------------------


def _find_context(args):
    """Pick the ``XComponentContext`` out of a factory argument tuple, if present.

    Two traps, both hit in practice:

    * ``XComponentContext`` is an *interface*, not a service, so
      ``supportsService("com.sun.star.lang.XComponentContext")`` is always false and would
      silently drop the real context -- hence ``queryInterface``.
    * ``uno.getTypeByName("com.sun.star.lang.XComponentContext")`` raises
      ``RuntimeError: Type ... is unknown`` on this build, so the lookup is best-effort and
      must be resolved *after* the empty-args check, or it would fail every zero-argument
      factory call (which oox makes when it activates the encryption engine).
    """
    if not args:
        return None
    try:
        wanted = uno.getTypeByName("com.sun.star.lang.XComponentContext")
    except Exception:  # noqa: BLE001
        _log("_find_context(): XComponentContext type not resolvable")
        return None
    for arg in args:
        try:
            found = arg.queryInterface(wanted)
        except Exception:  # noqa: BLE001
            continue
        if found is not None:
            return found
    return None


def _named_value(name: str, value):
    nv = uno.createUnoStruct("com.sun.star.beans.NamedValue")
    nv.Name = name
    nv.Value = value
    return nv


def _to_bytes(value) -> bytes:
    """Normalise a UNO ByteSequence / bytes / bytearray into plain ``bytes``."""
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    return bytes(bytearray(value))


def _read_all(stream) -> bytes:
    """Read an ``XInputStream`` to exhaustion.

    PyUNO's ``XInputStream.readBytes`` requires a ``bytes`` holder -- a ``bytearray`` is not
    convertible -- and returns a ``(count, data)`` tuple instead of filling the holder in place.
    """
    try:
        size = stream.available()
    except Exception:
        size = 0
    if size <= 0:
        return b""
    chunks = []
    total = 0
    while total < size:
        want = min(64 * 1024, size - total)
        result = stream.readBytes(bytes(want), want)
        if isinstance(result, tuple):
            count = int(result[0])
            data = _to_bytes(result[1]) if len(result) > 1 else b""
        else:
            count = int(result)
            data = b""
        if count <= 0 or not data:
            break
        chunks.append(data[:count])
        total += count
    return b"".join(chunks)


def _create(smgr_or_ctx, service_name):
    """Create a service, accepting either an ``XMultiServiceFactory`` or a context.

    ``XMultiServiceFactory.createInstance`` needs no context, which matters because the
    component loader only passes the *service manager* of the real process context.
    """
    if hasattr(smgr_or_ctx, "createInstance"):
        return smgr_or_ctx.createInstance(service_name)
    return smgr_or_ctx.ServiceManager.createInstanceWithContext(
        service_name, smgr_or_ctx
    )


def _sequence_output_stream(smgr, data=None):
    """Create a ``SequenceOutputStream``, optionally pre-filled with ``data``."""
    stream = _create(smgr, "com.sun.star.io.SequenceOutputStream")
    if data:
        # writeBytes takes an [in] sequence<byte>; PyUNO rejects a bare bytes object here.
        stream.writeBytes(uno.ByteSequence(_to_bytes(data)))
        stream.flush()
    return stream


def _seekable_output_stream(smgr, data, keep_alive=None):
    """Create an output stream pre-filled with ``data`` that is also ``XSeekable``.

    ``DocumentDecryption::decrypt()`` treats the ``[out]`` stream as an in-parameter: the
    C++ bridge passes a reference and the caller keeps using *its own* stream afterwards,
    querying it for ``io::XSeekable`` and calling ``seek(0)`` before importing the
    recovered package.  A ``SequenceOutputStream`` does not implement ``XSeekable``, so
    that query yields a null reference and the ``seek(0)`` call terminates the process.
    ``com.sun.star.io.TempFile`` returns a stream that satisfies both interfaces.

    ``RemoveFile`` defaults to true, which deletes the backing file once the ``TempFile``
    is released -- while the stream is still in use.  It is disabled, and the object is
    parked in ``keep_alive`` to keep the Python reference (and therefore the UNO object)
    alive for as long as the component lives.
    """
    temp = _create(smgr, "com.sun.star.io.TempFile")
    try:
        temp.RemoveFile = False
    except Exception:  # noqa: BLE001 - property missing on some builds; file removal is
        pass             # then governed by the process lifetime instead.
    stream = temp.getOutputStream()
    stream.writeBytes(uno.ByteSequence(_to_bytes(data)))
    stream.flush()
    # Leave the position at 0 so consumers may read or seek without extra bookkeeping.
    stream.seek(0)
    if keep_alive is not None:
        keep_alive.append((temp, stream))
    return stream


def _sequence_input_stream(smgr, data: bytes):
    stream = _create(smgr, "com.sun.star.io.SequenceInputStream")
    stream.initialize((uno.ByteSequence(data),))
    return stream


def _output_bytes(stream) -> bytes:
    try:
        out = stream.getOutputStream() if hasattr(stream, "getOutputStream") else None
        if out is not None:
            return bytes(out.getWrittenBytes())
    except Exception:
        pass
    try:
        return bytes(stream.getWrittenBytes())
    except Exception:
        return b""


# ---------------------------------------------------------------------------
# Component
# ---------------------------------------------------------------------------


class CipherBoxDataSpace(unohelper.Base, XServiceInfo, XInitialization, XPackageEncryption):
    """``XPackageEncryption`` + ``XServiceInfo`` + ``XInitialization`` provider.

    The UNO interface classes are inherited explicitly: PyUNO does not infer interface
    support from duck typing, so without these bases the component is rejected with
    "does not provide a constructor or factory".
    """

    def __init__(self, context=None, smgr=None):
        self._ctx = context
        self._smgr = smgr
        self._key = None
        # Password verifier, stored in the DataSpaceInfo stream on save and read back on
        # load.  oox relies on generateEncryptionKey()'s boolean to reject wrong passwords.
        self._verifier_salt = None
        self._verifier_hash = None
        # Whether the active key was derived from a password that passed verification.
        self._key_verified = False
        # TempFile-backed streams handed to oox: pinned so the backing files outlive us.
        self._streams = []

    # -- XInitialization ------------------------------------------------

    def initialize(self, args):
        context = _find_context(args)
        if context is not None:
            self._ctx = context
        _log("initialize(): context=%s" % (self._ctx is not None))
        return None

    # -- XServiceInfo ---------------------------------------------------

    def getImplementationName(self):
        return IMPL_NAME

    def supportsService(self, name):
        return name == SERVICE_NAME

    def getSupportedServiceNames(self):
        return (SERVICE_NAME,)

    # -- XPackageEncryption ---------------------------------------------

    def createEncryptionData(self, password):
        _log("createEncryptionData(password=%s)" % _mask(password))
        self._key = derive_key(password)
        return (
            _named_value(NV_CRYPTO_TYPE, CRYPTO_TYPE),
            _named_value(NV_KEY, uno.ByteSequence(self._key)),
        )

    def setupEncryption(self, media_enc_data):
        _log("setupEncryption(names=%s)" % _names(media_enc_data))
        password = None
        for nv in media_enc_data or ():
            if getattr(nv, "Name", None) == NV_KEY:
                value = nv.Value
                if value is None:
                    continue
                raw = bytes(value) if not isinstance(value, bytes) else value
                if raw:
                    self._key = raw
                    _log("key recovered from media encryption data (%d bytes)" % len(raw))
                    return True
            elif getattr(nv, "Name", None) == NV_PASSWORD:
                value = nv.Value
                if value is not None:
                    password = value
        if password is not None:
            # oox's save path supplies the password here and never round-trips CipherBoxKey,
            # so the key has to be derived from it -- otherwise the password would be
            # ignored and every file would share the fixed demo key.
            self._key = derive_key(password)
            # Also mint a verifier so that, on load, generateEncryptionKey() can tell oox
            # whether a candidate password is actually right.
            self._verifier_salt, self._verifier_hash = make_verifier(password)
            self._key_verified = True
            _log("key derived from %s (%s); verifier stored"
                 % (NV_PASSWORD, _mask(password)))
            return True
        _log("WARN: neither %s nor %s in media encryption data; using empty-password key"
             % (NV_KEY, NV_PASSWORD))
        self._key = derive_key("")
        return True

    def encrypt(self, x_input_stream):
        plain = _read_all(x_input_stream)
        _log("encrypt(): plaintext %d bytes, key=%s" % (len(plain), self._describe_key()))

        iv = os.urandom(IV_LEN)
        cipher_text = aes_cbc(self._require_key(), iv, plain, encrypt=True)
        payload = _i64(len(plain)) + iv + cipher_text

        streams = (
            _named_value(STREAM_DATASPACEMAP, uno.ByteSequence(data_space_map())),
            _named_value(STREAM_VERSION, uno.ByteSequence(version())),
            _named_value(
                STREAM_DATASPACEINFO,
                uno.ByteSequence(data_space_info(self._verifier_salt, self._verifier_hash)),
            ),
            _named_value(STREAM_TRANSFORMINFO, uno.ByteSequence(transform_info())),
            _named_value(STREAM_ENCRYPTEDPACKAGE, uno.ByteSequence(payload)),
        )
        _log(
            "encrypt(): returning 5 streams, EncryptedPackage %d bytes" % len(payload)
        )
        return streams

    def decrypt(self, x_input_stream, x_output_stream=None):
        # ``rxOutputStream`` is declared [out] in the IDL, but oox passes a caller-owned
        # UNOMemoryStream that the filter later reads back.  UNO [out] params carry no
        # initial value across the bridge, so PyUNO hands this method ``None`` and the
        # caller's stream can never be written to from Python -- see the notes in
        # _seekable_output_stream() and the decrypt() return below.
        try:
            container = _read_all(x_input_stream)
            if len(container) < 8 + IV_LEN:
                _log("decrypt(): container too short (%d bytes)" % len(container))
                return False
            plain_length = int.from_bytes(container[0:8], "little", signed=True)
            iv = container[8 : 8 + IV_LEN]
            cipher_text = container[8 + IV_LEN :]
            plain = aes_cbc(self._require_key(), iv, cipher_text, encrypt=False)
            _log(
                "decrypt(): cipherText %d -> plaintext %d bytes (declared %d), key=%s"
                % (len(cipher_text), len(plain), plain_length, self._describe_key())
            )
            if plain_length >= 0 and plain_length != len(plain):
                _log("decrypt(): WARN declared %d but recovered %d bytes"
                     % (plain_length, len(plain)))
            if x_output_stream is None:
                # [out] param: return it as a trailing element of the result tuple.  The IDL
                # names it ``rxOutputStream`` (singular), so hand back the bare object
                # rather than a 1-element sequence.  It must be XSeekable, because
                # DocumentDecryption::decrypt() queries it for that interface and seeks to 0.
                return True, _seekable_output_stream(
                    self._require_smgr(), plain, self._streams)
            # writeBytes takes an [in] sequence<byte>; a bare bytes object is rejected.
            x_output_stream.writeBytes(uno.ByteSequence(plain))
            x_output_stream.flush()
            return True
        except Exception as exc:  # noqa: BLE001
            _log("decrypt(): FAILED %r" % (exc,))
            _log(traceback.format_exc())
            raise

    def readEncryptionInfo(self, media_enc_data):
        _log("readEncryptionInfo(names=%s)" % _names(media_enc_data))
        # Recover the password verifier that setupEncryption()/encrypt() stored in the
        # DataSpaceInfo stream, so generateEncryptionKey() can validate candidates.
        self._verifier_salt = None
        self._verifier_hash = None
        for nv in media_enc_data or ():
            if getattr(nv, "Name", None) != STREAM_DATASPACEINFO:
                continue
            value = getattr(nv, "Value", None)
            if value is None:
                continue
            raw = value if isinstance(value, bytes) else bytes(bytearray(value))
            self._verifier_salt, self._verifier_hash = _parse_verifier(raw)
            break
        if self._verifier_salt:
            _log("readEncryptionInfo(): verifier recovered from DataSpaceInfo")
        else:
            _log("readEncryptionInfo(): no verifier in file (accept any password)")
        return True

    def generateEncryptionKey(self, password):
        """Derive the key, rejecting a wrong password.

        oox's PasswordVerifier::verifyPassword() calls this and only proceeds to
        createEncryptionData() when it returns true, so returning False here is what makes
        LibreOffice move on from its "VelvetSweatshop" default probe to the real password
        (or to the password prompt).
        """
        _log("generateEncryptionKey(password=%s)" % _mask(password))
        if not verifier_matches(password, self._verifier_salt, self._verifier_hash):
            _log("generateEncryptionKey(): verifier mismatch -> rejecting password")
            return False
        self._key = derive_key(password)
        self._key_verified = True
        return True

    def checkDataIntegrity(self):
        _log("checkDataIntegrity() key_verified=%s" % self._key_verified)
        return bool(self._key_verified)

    # -- internals ------------------------------------------------------

    def _require_smgr(self):
        """Return the service manager of the *real* process context.

        The component loader passes only ``self.ctx.ServiceManager`` to
        ``getComponentFactory``, so this is the object that produces streams the caller can
        actually receive.  Falling back to ``uno.getComponentContext()`` would create a
        second, unrelated component context whose objects fail to marshal back across the
        UNO bridge and arrive as ``None``.
        """
        if self._smgr is None and self._ctx is not None:
            self._smgr = self._ctx.ServiceManager
        if self._smgr is None:
            raise RuntimeError("no XMultiServiceFactory available")
        return self._smgr

    def _require_key(self) -> bytes:
        if self._key is None:
            _log("WARN: no key available, using fixed demo key")
            self._key = derive_key("")
        return self._key

    def _describe_key(self) -> str:
        return "none" if self._key is None else "AES/%dbits" % (len(self._key) * 8)


def _fingerprint(password) -> str:
    """Non-reversible 8-char digest, so logs can identify *which* password arrived
    without ever writing the password itself to disk."""
    if password is None:
        return "none"
    return hashlib.sha256(password.encode("utf-8")).hexdigest()[:8]


def _mask(password) -> str:
    """Render a password for logging without disclosing it.

    Only the length and a short SHA-256 fingerprint are recorded; the raw value is never
    written anywhere.  (An opt-in raw-trace hook existed for debugging, but it persisted
    plaintext passwords to %TEMP% and was removed once the password channel was understood.)
    """
    if password is None:
        return ""
    if password == "":
        return "(empty)"
    return "***len=%d fp=%s***" % (len(password), _fingerprint(password))


def _names(values) -> str:
    if not values:
        return "[]"
    return "[%s]" % ", ".join(str(getattr(v, "Name", v)) for v in values)


class _ComponentFactory(unohelper.Base, XSingleServiceFactory):
    """``XSingleServiceFactory`` handed to the Python component loader."""

    def __init__(self, service_manager=None, reg_key=None):
        self._smgr = service_manager
        self._reg_key = reg_key

    def createInstance(self):
        _log("createInstance()")
        return CipherBoxDataSpace(None, self._smgr)

    def createInstanceWithArguments(self, args):
        _log("createInstanceWithArguments(%d args)" % len(args or ()))
        try:
            return CipherBoxDataSpace(_find_context(args), self._smgr)
        except Exception:  # noqa: BLE001
            _log("createInstanceWithArguments FAILED\n%s" % traceback.format_exc())
            raise


def getComponentFactory(implementationName, service_manager, reg_key):
    """Entry point used by ``program/pythonloader.py`` (``Loader.activate``)."""
    _log("getComponentFactory(%r)" % (implementationName,))
    return _ComponentFactory(service_manager, reg_key)


def __getattr__(name):
    """Factory hook for the Python component loader.

    The loader may look up either the class or a dotted implementation name, so answer any
    public attribute with a factory.  Dunder names must still raise, otherwise Python would
    treat this module as a package (``__path__``) or a wildcard target (``__all__``).
    """
    if name.startswith("_"):
        raise AttributeError(name)
    return _ComponentFactory()
