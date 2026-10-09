"""What does a TempFile output stream actually expose in PyUNO?

oox requires the [out] stream from decrypt() to be XOutputStream AND XSeekable (it calls
seek(0)).  The e2e test additionally needs to read the plaintext back.  Probe a
com.sun.star.io.TempFile output stream and report which interfaces/methods are visible, so
the decrypt() fix and the test read helper are written against reality rather than guesses.
"""

import os
import sys

import uno

URL = "uno:socket,host=127.0.0.1,port=2002;urp;StarOffice.ComponentContext"


def main():
    local = uno.getComponentContext()
    resolver = local.ServiceManager.createInstanceWithContext(
        "com.sun.star.bridge.UnoUrlResolver", local)
    ctx = resolver.resolve(URL)
    smgr = ctx.ServiceManager

    tf = smgr.createInstanceWithContext("com.sun.star.io.TempFile", ctx)
    print("TempFile created: %s" % (tf is not None))
    print("  RemoveFile default = %r" % getattr(tf, "RemoveFile", "<none>"))
    out = tf.getOutputStream()
    print("  getOutputStream() -> %s" % (out is not None,))
    for meth in ("writeBytes", "flush", "close", "seek", "tell", "getLength",
                 "getWrittenBytes", "getInputStream", "readBytes", "available",
                 "getRemainingBytes", "truncate", "getPos"):
        print("    has %-16s : %s" % (meth, hasattr(out, meth)))
    # Is it an XSeekable?  Try a seek round-trip.
    try:
        out.seek(0)
        print("  seek(0) OK")
    except Exception as exc:  # noqa: BLE001
        print("  seek(0) FAILED: %r" % (exc,))
    # Write a few bytes and try to read them back.
    out.writeBytes(uno.ByteSequence(b"hello-probe"))
    out.flush()
    try:
        out.seek(0)
        data = out.readBytes(b"")
        print("  readBytes after seek(0) -> %r" % bytes(data[0]))
    except Exception as exc:  # noqa: BLE001
        print("  readBytes after seek(0) failed: %r" % (exc,))
    return 0


if __name__ == "__main__":
    sys.exit(main())
