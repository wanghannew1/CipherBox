"""Check whether the CipherBoxDataSpace Java UNO component is registered and loadable.

Connects to a running soffice via UNO socket and asks the *process* service manager
for com.sun.star.comp.oox.crypto.CipherBoxDataSpace -- the exact name oox builds from
the CryptoType returned by createEncryptionData().
"""

import sys
import time

import uno
from com.sun.star.connection import NoConnectException

SERVICE = "com.sun.star.comp.oox.crypto.CipherBoxDataSpace"
IMPL = "com.sun.star.comp.oox.crypto.IMPL.CipherBoxDataSpace"
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
    raise SystemExit("could not connect to soffice: %s" % last)


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

    enc = uno.queryInterface(
        uno.getTypeByName("com.sun.star.packages.XPackageEncryption"), obj)
    print("  XPackageEncryption  :", "yes" if enc else "no")
    info = uno.queryInterface(
        uno.getTypeByName("com.sun.star.lang.XServiceInfo"), obj)
    if info:
        print("  implementationName  :", info.getImplementationName())
        print("  supportedServices   :", list(info.getSupportedServiceNames()))
    else:
        print("  XServiceInfo        : no")

    if not enc:
        return 1

    # Exercise the container-format writers directly, without touching a document.
    streams = enc.encrypt(_asInputStream(ctx, b"CipherBox demo payload"))
    print("  encrypt() streams   :", [s.Name for s in streams])
    for s in streams:
        v = s.Value
        print("      %-52s %d bytes" % (s.Name, len(v) if hasattr(v, "__len__") else -1))
    return 0


def _asInputStream(ctx, data):
    return ctx.ServiceManager.createInstanceWithArgumentsAndContext(
        "com.sun.star.io.SequenceInputStream", (uno.ByteSequence(data),), ctx)


if __name__ == "__main__":
    sys.exit(main())
