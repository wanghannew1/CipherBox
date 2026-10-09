"""Step 0 connect probe: resolve the running probe soffice over its named pipe.

Proves the CONNECT side of UNO pipe transport: a real bridge with real remote
calls (ServiceManager XServiceInfo + Desktop instantiation), not just a pipe
handle.  Run with the LibreOffice-bundled python.  Watchdogged by the caller
(child process killed after <=20s).
"""

import sys
import time

import uno

URL = "uno:pipe,name=cipherbox-probe;urp;StarOffice.ComponentContext"


def main():
    local = uno.getComponentContext()
    resolver = local.ServiceManager.createInstanceWithContext(
        "com.sun.star.bridge.UnoUrlResolver", local)
    deadline = time.time() + 15
    last = None
    ctx = None
    while time.time() < deadline:
        try:
            ctx = resolver.resolve(URL)
            break
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(1)
    if ctx is None:
        print("CONNECT: FAIL %s: %s" % (type(last).__name__, last))
        return 1

    print("CONNECT: SUCCESS", URL)
    smgr = ctx.ServiceManager
    print("REMOTE: ServiceManager =", smgr)
    info = smgr.queryInterface(
        uno.getTypeByName("com.sun.star.lang.XServiceInfo"))
    if info is not None:
        print("REMOTE: ServiceManager implementationName =",
              info.getImplementationName())
    else:
        print("REMOTE: ServiceManager exposes no XServiceInfo (still a live remote object)")
    desktop = smgr.createInstanceWithContext(
        "com.sun.star.frame.Desktop", ctx)
    print("REMOTE: Desktop createInstanceWithContext ->",
          "OK" if desktop is not None else "None")
    if desktop is None:
        print("PROBE: FAIL remote call returned None")
        return 1
    print("PROBE: OK real UNO bridge over named pipe")
    return 0


if __name__ == "__main__":
    sys.exit(main())
