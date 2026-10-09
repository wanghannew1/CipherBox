"""QA probe: single resolve attempt against the service pipe (cipherbox-service).

Fast-fails with the transport-level exception when the pipe is not listening.
Watchdogged by the caller (child process killed after <=20s).
"""

import sys

import uno

URL = "uno:pipe,name=cipherbox-service;urp;StarOffice.ComponentContext"


def main():
    local = uno.getComponentContext()
    resolver = local.ServiceManager.createInstanceWithContext(
        "com.sun.star.bridge.UnoUrlResolver", local)
    try:
        resolver.resolve(URL)
        print("RESOLVE: OK", URL)
        return 0
    except Exception as exc:  # noqa: BLE001
        print("RESOLVE: FAIL %s: %s" % (type(exc).__name__, exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
