"""Check whether the CipherBoxDataSpace UNO component is registered and loadable.

Connects to the running service soffice via its UNO named pipe (see
../start_soffice.ps1) and asks the *process* service manager for
com.sun.star.comp.oox.crypto.CipherBoxDataSpace -- the exact name oox builds from
the CryptoType returned by createEncryptionData().

The result is honest: "RESULT: OK service instantiated" only means the component
instantiates.  The overall exit code additionally requires XPackageEncryption and
XServiceInfo to be non-null and encrypt() -- driven the way oox drives it on
save, via setupEncryption() with a test password -- to return exactly the five
MS-OFFCRYPTO container streams (no EncryptionInfo stream; that belongs to
LibreOffice's built-in agile encryption, not this engine).
"""

import sys
import time

import uno
from com.sun.star.beans import NamedValue
from com.sun.star.connection import NoConnectException

SERVICE = "com.sun.star.comp.oox.crypto.CipherBoxDataSpace"
IMPL = "com.sun.star.comp.oox.crypto.IMPL.CipherBoxDataSpace"
URL = "uno:pipe,name=cipherbox-service;urp;StarOffice.ComponentContext"

T_PASSWORD = "correct horse battery staple"

EXPECTED_STREAMS = [
    "\006DataSpaces/DataSpaceMap",
    "\006DataSpaces/Version",
    "\006DataSpaces/DataSpaceInfo/CipherBoxDataSpace",
    "\006DataSpaces/TransformInfo/CipherBoxTransform/\006Primary",
    "EncryptedPackage",
]


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


def named(name, value):
    n = NamedValue()
    n.Name = name
    n.Value = value
    return n


def main():
    ctx = connect()
    smgr = ctx.ServiceManager
    print("connected; service manager =", smgr)

    try:
        obj = smgr.createInstanceWithContext(SERVICE, ctx)
    except Exception as exc:  # noqa: BLE001
        print("RESULT: FAIL createInstance ->", type(exc).__name__, exc)
        return 1

    if obj is None:
        print("RESULT: FAIL createInstance returned None")
        return 1

    print("RESULT: OK service instantiated ->", obj)

    enc = obj.queryInterface(
        uno.getTypeByName("com.sun.star.packages.XPackageEncryption"))
    print("  XPackageEncryption  :", "yes" if enc else "no")
    info = obj.queryInterface(
        uno.getTypeByName("com.sun.star.lang.XServiceInfo"))
    if info:
        print("  implementationName  :", info.getImplementationName())
        print("  supportedServices   :", list(info.getSupportedServiceNames()))
    else:
        print("  XServiceInfo        : no")

    if enc is None or info is None:
        print("RESULT: FAIL XPackageEncryption/XServiceInfo is null "
              "(XPackageEncryption=%s, XServiceInfo=%s)"
              % (enc is not None, info is not None))
        return 1

    # Exercise the container-format writers the way oox does on save: drive
    # encrypt() through setupEncryption() with a test password (the writer
    # route test_password_verify.py pins down), not the no-password route.
    enc.setupEncryption((
        named("CryptoType", "CipherBoxDataSpace"),
        named("Password", T_PASSWORD),
    ))
    streams = enc.encrypt(_asInputStream(ctx, b"CipherBox demo payload"))
    names = [s.Name for s in streams] if streams else None
    print("  encrypt() streams   :", names)
    if names != EXPECTED_STREAMS:
        print("RESULT: FAIL encrypt() stream names %r do not match the "
              "expected 5 MS-OFFCRYPTO streams %r" % (names, EXPECTED_STREAMS))
        return 1
    for s in streams:
        v = s.Value
        print("      %-52s %d bytes" % (s.Name, len(v) if hasattr(v, "__len__") else -1))
    print("RESULT: OK encrypt() returned the 5 expected container streams")
    return 0


def _asInputStream(ctx, data):
    return ctx.ServiceManager.createInstanceWithArgumentsAndContext(
        "com.sun.star.io.SequenceInputStream", (uno.ByteSequence(data),), ctx)


if __name__ == "__main__":
    sys.exit(main())
