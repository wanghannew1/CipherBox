"""Control experiment: does media-descriptor Password reach oox *built-in* decryption on load?

If built-in agile encryption reloads with the correct text, then the media-descriptor load
args are fine and something specific to the custom XPackageEncryption path is substituting
LibreOffice's default password ("VelvetSweatshop").  If built-in also fails, our load args
are simply wrong.
"""

import os
import sys

import uno
from com.sun.star.beans import NamedValue, PropertyValue

URL = "uno:socket,host=127.0.0.1,port=2002;urp;StarOffice.ComponentContext"
PW = "correct horse battery staple"
WRONG = "wrong password entirely"
CRYPTO_TYPE = "CipherBoxDataSpace"
OUT = os.path.join(os.environ.get("TEMP", "."), "cipherbox-ctrl")


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


def named_seq(items):
    return uno.Any("[]com.sun.star.beans.NamedValue", tuple(items))


def crypto_enc():
    return named_seq((nv("CryptoType", CRYPTO_TYPE), nv("Password", PW)))


def save(desktop, filename, custom):
    path = os.path.join(OUT, filename)
    if os.path.exists(path):
        os.remove(path)
    doc = desktop.loadComponentFromURL("private:factory/swriter", "_blank", 0, ())
    doc.Text.setString("CONTROLMARKER")
    args = [pv("FilterName", "MS Word 2007 XML"), pv("Password", PW)]
    if custom:
        args.append(pv("EncryptionData", crypto_enc()))
    doc.storeToURL(uno.systemPathToFileUrl(path), tuple(args))
    doc.close(False)
    return path


def load(desktop, path, password):
    try:
        doc = desktop.loadComponentFromURL(
            uno.systemPathToFileUrl(path), "_blank", 0, (pv("Password", password),))
    except Exception as exc:  # noqa: BLE001
        return "<error %s>" % type(exc).__name__
    if doc is None:
        return "<None refused>"
    try:
        text = doc.Text.getString()[:24]
    finally:
        doc.close(False)
    return text


def main():
    if not os.path.isdir(OUT):
        os.makedirs(OUT)
    local = uno.getComponentContext()
    resolver = local.ServiceManager.createInstanceWithContext(
        "com.sun.star.bridge.UnoUrlResolver", local)
    ctx = resolver.resolve(URL)
    desktop = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.Desktop", ctx)

    builtin = save(desktop, "builtin.docx", custom=False)
    custom = save(desktop, "custom.docx", custom=True)

    def is_ole(path):
        with open(path, "rb") as fh:
            return fh.read(8) == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

    print("builtin encrypted (OLE)   : %s" % is_ole(builtin))
    print("custom  encrypted (OLE)   : %s" % is_ole(custom))
    print("builtin + correct pw      : %r" % load(desktop, builtin, PW))
    print("builtin + wrong   pw      : %r" % load(desktop, builtin, WRONG))
    print("custom  + correct pw      : %r" % load(desktop, custom, PW))
    print("custom  + wrong   pw      : %r" % load(desktop, custom, WRONG))
    return 0


if __name__ == "__main__":
    sys.exit(main())
