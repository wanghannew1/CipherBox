"""End-to-end test of the CipherBoxDataSpace XPackageEncryption component.

Exercises the component exactly the way oox does:
  createEncryptionData() -> encrypt() -> 5 MS-OFFCRYPTO streams -> decrypt() -> plaintext

Runs against a live soffice (see start_soffice.ps1).
"""

import os
import sys
import time

import uno
from com.sun.star.connection import NoConnectException

SERVICE = "com.sun.star.comp.oox.crypto.CipherBoxDataSpace"
URL = "uno:socket,host=127.0.0.1,port=2002;urp;StarOffice.ComponentContext"

T_PASSWORD = "correct horse battery staple"

EXPECTED_STREAMS = [
    "\006DataSpaces/DataSpaceMap",
    "\006DataSpaces/Version",
    "\006DataSpaces/DataSpaceInfo/CipherBoxDataSpace",
    "\006DataSpaces/TransformInfo/CipherBoxTransform/\006Primary",
    "EncryptedPackage",
]

FAILURES = []


def check(label, condition, detail=""):
    if condition:
        print("PASS  %s %s" % (label, detail))
    else:
        print("FAIL  %s %s" % (label, detail))
        FAILURES.append(label)
    return bool(condition)


def connect(timeout=60):
    local = uno.getComponentContext()
    resolver = local.ServiceManager.createInstanceWithContext(
        "com.sun.star.bridge.UnoUrlResolver", local)
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            return resolver.resolve(URL)
        except NoConnectException as exc:
            last = exc
            time.sleep(1)
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(1)
    raise SystemExit("could not connect to soffice: %s" % last)


def as_input_stream(ctx, data):
    return ctx.ServiceManager.createInstanceWithArgumentsAndContext(
        "com.sun.star.io.SequenceInputStream", (uno.ByteSequence(data),), ctx)


def as_bytes(value):
    if isinstance(value, bytes):
        return value
    return bytes(bytearray(value))


def _read_seekable_stream(stream):
    """Drain an XSeekable + XInputStream in place.

    A TempFile-backed output stream implements XSeekable, XOutputStream and XInputStream on
    one object, so the payload is read straight off it: rewind, ask for the length, then
    pull bytes.  Verified contract for this stream (see test/probe_read.py):
      * getLength()                       -> total byte count
      * readBytes(ByteSequence(b""), n)   -> (nBytesRead, aData)   [two args required]
    Note aData is a pyuno ByteSequence, which is NOT a bytes subclass, so the payload must be
    converted with as_bytes() rather than sniffed with isinstance(item, bytes).
    """
    try:
        stream.seek(0)
    except Exception:  # noqa: BLE001
        pass
    try:
        total = int(stream.getLength())
    except Exception:  # noqa: BLE001
        return b""
    chunks = []
    got = 0
    while got < total:
        want = min(64 * 1024, total - got)
        try:
            result = stream.readBytes(uno.ByteSequence(b""), want)
        except Exception:  # noqa: BLE001
            break
        if not isinstance(result, tuple) or len(result) < 2:
            break
        count = int(result[0])
        data = as_bytes(result[1])
        if count <= 0 or not data:
            break
        chunks.append(data[:count])
        got += count
    return b"".join(chunks)


def read_stream(stream):
    """Read a decrypted stream.

    ``decrypt()`` returns a TempFile-backed XOutputStream (it must be XSeekable so oox can
    seek to 0), so the payload is read in place via ``_read_seekable_stream``.
    """
    if hasattr(stream, "getWrittenBytes"):
        try:
            return as_bytes(stream.getWrittenBytes())
        except Exception:  # noqa: BLE001
            pass
    return _read_seekable_stream(stream)


def main():
    ctx = connect()
    smgr = ctx.ServiceManager
    print("connected\n")

    # -- 1. service instantiation ------------------------------------
    try:
        obj = smgr.createInstanceWithContext(SERVICE, ctx)
    except Exception as exc:  # noqa: BLE001
        print("RESULT: FAIL createInstance -> %s: %s" % (type(exc).__name__, exc))
        return 1
    if not check("service instantiated", obj is not None):
        return 1
    print("       %s\n" % (obj,))

    # -- 2. interface support ----------------------------------------
    enc = obj.queryInterface(
        uno.getTypeByName("com.sun.star.packages.XPackageEncryption"))
    check("supports XPackageEncryption", enc is not None)
    info = obj.queryInterface(
        uno.getTypeByName("com.sun.star.lang.XServiceInfo"))
    if check("supports XServiceInfo", info is not None):
        check(
            "  implementationName",
            info.getImplementationName() == "com.sun.star.comp.oox.crypto.IMPL.CipherBoxDataSpace",
            info.getImplementationName(),
        )
        check("  supportedServices", SERVICE in list(info.getSupportedServiceNames()),
              str(list(info.getSupportedServiceNames())))
    if not enc:
        return 1

    # -- 3. createEncryptionData -------------------------------------
    nv = enc.createEncryptionData(T_PASSWORD)
    crypto_type = None
    key_len = 0
    for item in nv:
        if item.Name == "CryptoType":
            crypto_type = item.Value
        if item.Name == "CipherBoxKey":
            key_len = len(as_bytes(item.Value))
    check("CryptoType round-trips through NamedValue", crypto_type == "CipherBoxDataSpace",
          repr(crypto_type))
    check("key is 32 bytes", key_len == 32, "%d" % key_len)
    print()

    # -- 4. encrypt ---------------------------------------------------
    plaintext = b"CipherBox end-to-end payload\x00\x01\x02" + os.urandom(5000)
    streams = enc.encrypt(as_input_stream(ctx, plaintext))
    check("encrypt() returns a sequence", streams is not None and len(streams) == 5,
          "%d streams" % (len(streams) if streams else -1))
    if not streams or len(streams) != 5:
        return 1

    names = [s.Name for s in streams]
    check("stream names match MS-OFFCRYPTO", names == EXPECTED_STREAMS, str(names))

    payloads = {s.Name: as_bytes(s.Value) for s in streams}
    for name in EXPECTED_STREAMS:
        print("       %-52s %5d bytes" % (name, len(payloads[name])))
    print()

    # -- 5. container byte layout ------------------------------------
    dsm = payloads[EXPECTED_STREAMS[0]]
    check("DataSpaceMap size", len(dsm) == 96, "%d" % len(dsm))
    check("DataSpaceMap entry length 0x60", dsm[8:12] == (0x60).to_bytes(4, "little"))
    check("Version size", len(payloads[EXPECTED_STREAMS[1]]) == 76,
          "%d" % len(payloads[EXPECTED_STREAMS[1]]))
    check("DataSpaceInfo size", len(payloads[EXPECTED_STREAMS[2]]) == 48,
          "%d" % len(payloads[EXPECTED_STREAMS[2]]))
    check("TransformInfo size", len(payloads[EXPECTED_STREAMS[3]]) == 184,
          "%d" % len(payloads[EXPECTED_STREAMS[3]]))
    check("TransformLength field", payloads[EXPECTED_STREAMS[3]][0:4] == (88).to_bytes(4, "little"))

    pkg = payloads["EncryptedPackage"]
    declared = int.from_bytes(pkg[0:8], "little", signed=True)
    check("EncryptedPackage declares plaintext length", declared == len(plaintext),
          "%d vs %d" % (declared, len(plaintext)))
    check("EncryptedPackage IV present", len(pkg) > 8 + 16)
    check("ciphertext is block aligned", (len(pkg) - 24) % 16 == 0,
          "%d" % (len(pkg) - 24))
    check("ciphertext differs from plaintext", pkg[24:] != plaintext)
    print()

    # -- 6. decrypt (same process state, as oox reload would do) ----
    enc.setupEncryption(nv)
    # `rxOutputStream` is an [out] param: PyUNO never delivers it to the callee, so the
    # component returns it as the trailing element of the result tuple.
    result = enc.decrypt(as_input_stream(ctx, pkg), ())
    ok = result[0] if isinstance(result, tuple) else result
    out = result[1] if isinstance(result, tuple) and len(result) > 1 else None
    check("decrypt() returns true", bool(ok), str(result)[:60])
    # Tolerate either IDL shape: a bare XOutputStream or a one-element sequence.
    if out is not None and not (hasattr(out, "getWrittenBytes")
                                or hasattr(out, "getInputStream")):
        out = out[0] if len(out) else None
    check("decrypt() yields an output stream", out is not None, str(out)[:60])
    if out is None:
        return 1

    recovered = read_stream(out)
    check("round-trip plaintext is byte-identical", recovered == plaintext,
          "%d bytes" % len(recovered))
    if recovered != plaintext:
        for i, (a, b) in enumerate(zip(recovered, plaintext)):
            if a != b:
                print("       first difference at offset %d: %r vs %r" % (i, a, b))
                break

    print()
    if FAILURES:
        print("RESULT: FAIL (%d) -> %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("RESULT: PASS (full encrypt/decrypt round trip)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
