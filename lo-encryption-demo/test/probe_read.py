"""Determine exactly how to read back a TempFile-backed output stream in PyUNO.

The e2e round-trip currently reads 0 bytes, so the seekable-stream read path used by
test_e2e._read_seekable_stream() is wrong somewhere.  This probe writes known bytes, then
tries every plausible read strategy and reports which one actually returns the payload.
"""

import sys

import uno

URL = "uno:socket,host=127.0.0.1,port=2002;urp;StarOffice.ComponentContext"
PAYLOAD = b"ABCDEFGHIJKLMNOP"


def main():
    local = uno.getComponentContext()
    resolver = local.ServiceManager.createInstanceWithContext(
        "com.sun.star.bridge.UnoUrlResolver", local)
    ctx = resolver.resolve(URL)
    smgr = ctx.ServiceManager

    temp = smgr.createInstanceWithContext("com.sun.star.io.TempFile", ctx)
    temp.RemoveFile = False
    out = temp.getOutputStream()
    out.writeBytes(uno.ByteSequence(PAYLOAD))
    out.flush()
    print("wrote %d bytes" % len(PAYLOAD))

    print("\n-- getLength on the output stream --")
    try:
        print("  getLength() = %r" % (out.getLength(),))
    except Exception as exc:  # noqa: BLE001
        print("  getLength() failed: %r" % (exc,))

    print("\n-- URI / properties --")
    for prop in ("Uri", "URL"):
        try:
            print("  %s = %r" % (prop, getattr(temp, prop)))
        except Exception as exc:  # noqa: BLE001
            print("  %s -> %r" % (prop, exc))

    print("\n-- read strategies --")
    # 1. seek(0) then getLength
    out.seek(0)
    try:
        print("  after seek(0): getLength() = %r" % (out.getLength(),))
    except Exception as exc:  # noqa: BLE001
        print("  after seek(0): getLength() failed: %r" % (exc,))

    # 2. readBytes arity sweep
    for label, call in (
        ("readBytes(16)", lambda: out.readBytes(16)),
        ("readBytes(b'', 16)", lambda: out.readBytes(uno.ByteSequence(b""), 16)),
        ("readBytes(bytes(16), 16)", lambda: out.readBytes(bytes(16), 16)),
    ):
        try:
            res = call()
            print("  %-28s -> %r" % (label, res))
        except Exception as exc:  # noqa: BLE001
            print("  %-28s -> FAILED %r" % (label, exc))

    # 3. the XInputStream route
    print("\n-- via getInputStream() --")
    try:
        inp = out.getInputStream()
        print("  available() = %r" % (inp.available(),))
        for label, call in (
            ("inp.readBytes(16)", lambda: inp.readBytes(16)),
            ("inp.readBytes(b'', 16)", lambda: inp.readBytes(uno.ByteSequence(b""), 16)),
        ):
            try:
                print("  %-28s -> %r" % (label, call()))
            except Exception as exc:  # noqa: BLE001
                print("  %-28s -> FAILED %r" % (label, exc))
    except Exception as exc:  # noqa: BLE001
        print("  getInputStream failed: %r" % (exc,))

    print("\n-- via temp.getInputStream() on the TempFile itself --")
    try:
        inp2 = temp.getInputStream()
        print("  available() = %r" % (inp2.available(),))
        try:
            print("  inp2.readBytes(16) -> %r" % (inp2.readBytes(16),))
        except Exception as exc:  # noqa: BLE001
            print("  inp2.readBytes(16) FAILED %r" % (exc,))
    except Exception as exc:  # noqa: BLE001
        print("  failed: %r" % (exc,))
    return 0


if __name__ == "__main__":
    sys.exit(main())
