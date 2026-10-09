"""Probe PyUNO calling conventions for readBytes and for [out] parameters."""

import sys
import time

import uno
from com.sun.star.connection import NoConnectException

URL = "uno:socket,host=127.0.0.1,port=2002;urp;StarOffice.ComponentContext"


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
    raise SystemExit("could not connect: %s" % last)


def main():
    ctx = connect()
    payload = bytes(range(256)) * 4  # 1024 bytes
    stream = ctx.ServiceManager.createInstanceWithArgumentsAndContext(
        "com.sun.star.io.SequenceInputStream", (uno.ByteSequence(payload),), ctx)
    print("available() =", stream.available())
    print()

    # Convention A: bytearray in place
    try:
        buf = bytearray(64)
        res = stream.readBytes(buf, 64)
        print("A bytearray      -> ret=%r  buf[:8]=%s" % (res, list(buf[:8])))
    except Exception as exc:  # noqa: BLE001
        print("A bytearray      -> EXC %s: %s" % (type(exc).__name__, exc))

    # Convention B: bytes in place
    try:
        buf2 = bytes(64)
        res2 = stream.readBytes(buf2, 64)
        print("B bytes          -> ret=%r" % (res2,))
    except Exception as exc:  # noqa: BLE001
        print("B bytes          -> EXC %s: %s" % (type(exc).__name__, exc))

    # Convention C: uno.ByteSequence
    try:
        buf3 = uno.ByteSequence(64)
        res3 = stream.readBytes(buf3, 64)
        print("C ByteSequence   -> ret=%r" % (res3,))
    except Exception as exc:  # noqa: BLE001
        print("C ByteSequence   -> EXC %s: %s" % (type(exc).__name__, exc))

    # Convention D: single-argument readSomeBytes
    try:
        res4 = stream.readSomeBytes(32)
        print("D readSomeBytes  -> %r  len=%s" % (
            res4, len(res4) if hasattr(res4, "__len__") else "n/a"))
    except Exception as exc:  # noqa: BLE001
        print("D readSomeBytes  -> EXC %s: %s" % (type(exc).__name__, exc))

    # Does the component's encrypt() see a full read?  Check decrypt arity too.
    obj = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.comp.oox.crypto.CipherBoxDataSpace", ctx)
    enc = obj.queryInterface(
        uno.getTypeByName("com.sun.star.packages.XPackageEncryption"))
    print()
    for label, args in (("decrypt(x, ())", 1), ("decrypt(x, None)", 1), ("decrypt(x)", 0)):
        try:
            if label == "decrypt(x)":
                out = enc.decrypt(
                    ctx.ServiceManager.createInstanceWithArgumentsAndContext(
                        "com.sun.star.io.SequenceInputStream",
                        (uno.ByteSequence(bytes(64)),), ctx))
            elif label == "decrypt(x, ())":
                out = enc.decrypt(
                    ctx.ServiceManager.createInstanceWithArgumentsAndContext(
                        "com.sun.star.io.SequenceInputStream",
                        (uno.ByteSequence(bytes(64)),), ctx), ())
            else:
                out = enc.decrypt(
                    ctx.ServiceManager.createInstanceWithArgumentsAndContext(
                        "com.sun.star.io.SequenceInputStream",
                        (uno.ByteSequence(bytes(64)),), ctx), None)
            print("%-16s -> OK %r" % (label, str(out)[:70]))
        except Exception as exc:  # noqa: BLE001
            print("%-16s -> EXC %s: %s" % (label, type(exc).__name__, str(exc)[:70]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
