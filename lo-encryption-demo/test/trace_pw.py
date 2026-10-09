"""Focused repro: save one docx with our engine, reload it, trace every password oox hands us."""

import os
import sys

import uno
from com.sun.star.beans import NamedValue, PropertyValue

URL = "uno:socket,host=127.0.0.1,port=2002;urp;StarOffice.ComponentContext"
PW = "correct horse battery staple"
CRYPTO_TYPE = "CipherBoxDataSpace"


def pv(name, value):
    p = PropertyValue()
    p.Name = name
    p.Value = value
    return p


def nv(name, value):
    n = NamedValue()
    n.Name = name
    n.Value = value
    return n


def main():
    path = os.path.join(os.environ.get("TEMP", "."), "cipherbox-trace.docx")
    if os.path.exists(path):
        os.remove(path)

    local = uno.getComponentContext()
    resolver = local.ServiceManager.createInstanceWithContext(
        "com.sun.star.bridge.UnoUrlResolver", local)
    ctx = resolver.resolve(URL)
    desktop = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.Desktop", ctx)

    enc = uno.Any("[]com.sun.star.beans.NamedValue",
                  (nv("CryptoType", CRYPTO_TYPE), nv("Password", PW)))
    doc = desktop.loadComponentFromURL("private:factory/swriter", "_blank", 0, ())
    doc.Text.setString("trace me")
    doc.storeToURL(uno.systemPathToFileUrl(path),
                   (pv("FilterName", "MS Word 2007 XML"),
                    pv("Password", PW),
                    pv("EncryptionData", enc)))
    doc.close(False)
    print("saved %d bytes" % os.path.getsize(path))

    reopened = desktop.loadComponentFromURL(
        uno.systemPathToFileUrl(path), "_blank", 0, (pv("Password", PW),))
    print("reopened text: %r" % (reopened.Text.getString()[:40],))
    reopened.close(False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
