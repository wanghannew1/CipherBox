"""Decisive test of the 'upstream substitutes VelvetSweatshop' theory.

Prediction if the theory holds: encrypting with the password "VelvetSweatshop" makes
generateEncryptionKey("VelvetSweatshop") derive the *same* key that setupEncryption used at
save time, so the custom round trip succeeds -- and the media descriptor password becomes
irrelevant on load.

If it still fails, something other than the password channel is broken.
"""

import os
import sys

import uno
from com.sun.star.beans import NamedValue, PropertyValue

URL = "uno:socket,host=127.0.0.1,port=2002;urp;StarOffice.ComponentContext"
CRYPTO_TYPE = "CipherBoxDataSpace"
OUT = os.path.join(os.environ.get("TEMP", "."), "cipherbox-ctrl")
DEFAULT_PW = "VelvetSweatshop"  # LibreOffice's hardcoded default password
OTHER_PW = "correct horse battery staple"


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


def save_custom(desktop, filename, password):
    path = os.path.join(OUT, filename)
    if os.path.exists(path):
        os.remove(path)
    doc = desktop.loadComponentFromURL("private:factory/swriter", "_blank", 0, ())
    doc.Text.setString("DEFAULTPWMARKER")
    enc = uno.Any("[]com.sun.star.beans.NamedValue",
                  (nv("CryptoType", CRYPTO_TYPE), nv("Password", password)))
    args = [pv("FilterName", "MS Word 2007 XML"), pv("Password", password),
            pv("EncryptionData", enc)]
    doc.storeToURL(uno.systemPathToFileUrl(path), tuple(args))
    doc.close(False)
    return path


def load(desktop, path, password):
    args = () if password is None else (pv("Password", password),)
    try:
        doc = desktop.loadComponentFromURL(uno.systemPathToFileUrl(path), "_blank", 0, args)
    except Exception as exc:  # noqa: BLE001
        return "<error %s>" % type(exc).__name__
    if doc is None:
        return "<None refused>"
    try:
        return doc.Text.getString()[:24]
    finally:
        doc.close(False)


def main():
    if not os.path.isdir(OUT):
        os.makedirs(OUT)
    local = uno.getComponentContext()
    resolver = local.ServiceManager.createInstanceWithContext(
        "com.sun.star.bridge.UnoUrlResolver", local)
    ctx = resolver.resolve(URL)
    desktop = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.Desktop", ctx)

    d = save_custom(desktop, "defaultpw.docx", DEFAULT_PW)
    o = save_custom(desktop, "otherpw.docx", OTHER_PW)

    print("encrypted with '%s':" % DEFAULT_PW)
    print("  load w/ same pw   -> %r" % load(desktop, d, DEFAULT_PW))
    print("  load w/ other pw  -> %r" % load(desktop, d, OTHER_PW))
    print("  load w/ no pw     -> %r" % load(desktop, d, None))
    print("encrypted with '%s':" % OTHER_PW)
    print("  load w/ same pw   -> %r" % load(desktop, o, OTHER_PW))
    return 0


if __name__ == "__main__":
    sys.exit(main())
