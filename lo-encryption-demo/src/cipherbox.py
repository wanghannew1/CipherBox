"""PyUNO implementation of ``com.sun.star.packages.XPackageEncryption``.

Registered as service ``com.sun.star.comp.oox.crypto.CipherBoxDataSpace``; oox resolves that
name by prepending ``com.sun.star.comp.oox.crypto.`` to the ``CryptoType`` value returned
from :meth:`CipherBoxDataSpace.createEncryptionData`.

The MS-OFFCRYPTO DataSpaces container layout is reproduced byte-for-byte from the reference
sample (bzzzil/lo_custom_encryption); only the payload cipher is upgraded from XOR to
AES-256-CBC.  AES is obtained from the Windows CNG provider through ``ctypes`` so the
component has no third-party dependency.  All pure cryptography lives in the sibling
module ``cipherbox_crypto`` (no ``uno`` dependency) and is only re-exported here.

``encrypt()`` is fail-closed: it refuses to run unless the key came from a trusted
provenance (the ``CipherBoxKey`` NamedValue, a non-empty ``Password``, or a
verifier-verified ``generateEncryptionKey()``), so an empty/missing password can never
produce "fake ciphertext".  The load/decrypt paths are unchanged.
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import traceback

import uno
import unohelper
from com.sun.star.lang import (
    XInitialization,
    XServiceInfo,
    XSingleServiceFactory,
)
from com.sun.star.packages import XPackageEncryption

# Pure cryptography lives in cipherbox_crypto (no uno dependency) so the Agent-side
# container parser shares this exact implementation.  Only re-exported here; the
# algorithms are unchanged.
from cipherbox_crypto import (  # noqa: E402
    IV_LEN,
    KEY_LEN,
    PBKDF2_ITERATIONS,
    PBKDF2_SALT,
    VERIFIER_HASH_LEN,
    VERIFIER_MAGIC,
    VERIFIER_SALT_LEN,
    VERIFIER_TRAILER_LEN,
    _i64,
    _parse_verifier,
    _pkcs7_pad,
    _pkcs7_unpad,
    aes_cbc,
    derive_key,
    derive_verifier,
    make_verifier,
    verifier_matches,
)

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

# Password-verification block.  oox decides whether a candidate password is correct purely
# from the boolean returned by XPackageEncryption::generateEncryptionKey() -- see
# PasswordVerifier::verifyPassword() in oox/source/core/filterdetect.cxx, which only calls
# createEncryptionData() when that boolean is true.  A component that always returns true
# therefore makes *every* password "correct", which is why LibreOffice's built-in
# "VelvetSweatshop" default probe would always win and the real password was never reached.
# The verifier constants themselves live in cipherbox_crypto (imported above).

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
# MS-OFFCRYPTO DataSpaces container streams
# ---------------------------------------------------------------------------


def _i32(value: int) -> bytes:
    return int(value).to_bytes(4, "little", signed=False)


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
        # Fail-closed gate for encrypt(): True only when the key came from a trusted
        # provenance -- the CipherBoxKey NamedValue, a NON-EMPTY Password, or a
        # verifier-verified generateEncryptionKey().  The empty-password / demo-key
        # fallbacks below leave this False so encrypt() refuses to mint "fake ciphertext".
        self._key_trusted = False
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
        # A non-empty password is a legitimate key provenance; an empty one is not.
        self._key_trusted = bool(password)
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
                    self._key_trusted = True
                    _log("key recovered from media encryption data (%d bytes)" % len(raw))
                    return True
            elif getattr(nv, "Name", None) == NV_PASSWORD:
                value = nv.Value
                if value is not None:
                    password = value
        if password:
            # oox's save path supplies the password here and never round-trips CipherBoxKey,
            # so the key has to be derived from it -- otherwise the password would be
            # ignored and every file would share the fixed demo key.
            self._key = derive_key(password)
            # Also mint a verifier so that, on load, generateEncryptionKey() can tell oox
            # whether a candidate password is actually right.
            self._verifier_salt, self._verifier_hash = make_verifier(password)
            self._key_verified = True
            self._key_trusted = True
            _log("key derived from %s (%s); verifier stored"
                 % (NV_PASSWORD, _mask(password)))
            return True
        # Empty or missing password: the key stays usable for the LOAD/decrypt path but is
        # NOT trusted for encrypt() -- the fail-closed gate refuses to save with it.
        _log("WARN: neither %s nor a non-empty %s in media encryption data; "
             "using empty-password key (decrypt-only, encrypt() will refuse)"
             % (NV_KEY, NV_PASSWORD))
        self._key = derive_key("")
        self._key_trusted = False
        return True

    def encrypt(self, x_input_stream):
        # Fail-closed gate: never mint "fake ciphertext" from an empty/demo key.  Only a
        # key sourced from CipherBoxKey, a non-empty Password, or a verifier-verified
        # generateEncryptionKey() may encrypt; anything else refuses the save outright.
        if not self._key_trusted or self._key is None:
            _log("encrypt(): REFUSED (fail-closed) - key not from a trusted source "
                 "(trusted=%s, present=%s)" % (self._key_trusted, self._key is not None))
            raise RuntimeError(
                "CipherBox fail-closed: no trusted key (CipherBoxKey / non-empty Password / "
                "verified password required); refusing to save fake ciphertext / "
                "\u7f3a\u5c11\u53ef\u4fe1\u5bc6\u94a5\uff0c\u62d2\u7edd\u4ea7\u51fa\u4f2a\u5bc6\u6587"
            )
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
        self._key_trusted = True
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
