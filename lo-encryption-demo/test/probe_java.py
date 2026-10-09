"""Probe whether the Java virtual machine can be started inside this soffice process."""

import sys
import time

import uno

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
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(1)
    raise SystemExit("could not connect: %s" % last)


def main():
    ctx = connect()
    smgr = ctx.ServiceManager

    for svc in ("com.sun.star.java.JavaVirtualMachine",
                "com.sun.star.loader.Java2",
                "com.sun.star.script.provider.MasterScriptProviderFactory"):
        try:
            obj = smgr.createInstanceWithContext(svc, ctx)
            print("%-52s -> %s" % (svc, "OK" if obj else "None"))
        except Exception as exc:  # noqa: BLE001
            print("%-52s -> %s: %s" % (svc, type(exc).__name__, exc))

    # The Java loader component itself (javaloaderlo.dll) - is the native side alive?
    try:
        obj = smgr.createInstanceWithContext("com.sun.star.loader.SharedLibrary", ctx)
        print("%-52s -> %s" % ("com.sun.star.loader.SharedLibrary", "OK" if obj else "None"))
    except Exception as exc:  # noqa: BLE001
        print("com.sun.star.loader.SharedLibrary -> %s: %s" % (type(exc).__name__, exc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
