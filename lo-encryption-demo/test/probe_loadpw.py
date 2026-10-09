"""Which load-arg shape actually delivers the password to a custom XPackageEncryption engine?

Observed: saving works (engine gets the real password), but on reload the engine only ever
receives LibreOffice'"'"'s hardcoded default "VelvetSweatshop".  So probe the candidates oox/Sfx
might read the load password from and report which one makes the engine see the real value.
"""

import os
import sys

import uno
from com.sun.star.beans import NamedValue, PropertyValue

URL = "uno:socket,host=127.0.0.1,port=2002;urp;StarOffice.ComponentContext"
TRACE = os.path.join(os.environ.get("TEMP", "."), "cipherbox-pw-trace.txt")
PW = "correct horse battery staple"
CRYPTO_TYPE = "CipherBoxDataSpace"
PATH = os.path.join(os.environ.get("TEMP", "."), "cipherbox-loadpw.docx")


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


def prop_seq(items):
    return uno.Any("[]com.sun.star.beans.PropertyValue", tuple(items))


def named_seq(items):
    return uno.Any("[]com.sun.star.beans.NamedValue", tuple(items))


def crypto_enc():
    return named_seq((nv("CryptoType", CRYPTO_TYPE), nv("Password", PW)))


def save_encrypted(desktop):
    if os.path.exists(PATH):
        os.remove(PATH)
    doc = desktop.loadComponentFromURL("private:factory/swriter", "_blank", 0, ())
    doc.Text.setString("loadpw probe")
    args = [
        pv("FilterName", "MS Word 2007 XML"),
        pv("Password", PW),
        pv("EncryptionData", crypto_enc()),
    ]
    doc.storeToURL(uno.systemPathToFileUrl(PATH), tuple(args))
    doc.close(False)


def read_trace():
    try:
        with open(TRACE, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


def probe(desktop, label, args):
    open(TRACE, "w").close()
    text = ""
    try:
        doc = desktop.loadComponentFromURL(
            uno.systemPathToFileUrl(PATH), "_blank", 0, tuple(args))
        if doc is not None:
            text = doc.Text.getString()[:28]
            doc.close(False)
    except Exception as exc:
        text = "<error %s>" % type(exc).__name__
    seen = sorted({ln.split("raw=")[-1] for ln in read_trace().splitlines() if "raw=" in ln})
    hit = any(PW in s for s in seen)
    short = ",".join(s[:18] for s in seen) or "(nothing)"
    print("%-32s ok=%-6s engine_saw=%-40s text=%r" % (label, hit, short, text))


def main():
    local = uno.getComponentContext()
    resolver = local.ServiceManager.createInstanceWithContext(
        "com.sun.star.bridge.UnoUrlResolver", local)
    ctx = resolver.resolve(URL)
    desktop = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.Desktop", ctx)

    save_encrypted(desktop)

    probe(desktop, "A media Password", [pv("Password", PW)])
    probe(desktop, "B Password+EncryptionData",
          [pv("Password", PW), pv("EncryptionData", crypto_enc())])
    probe(desktop, "C FilterData Password",
          [pv("FilterData", prop_seq([pv("Password", PW)]))])
    grab = prop_seq([pv("password", PW)])
    probe(desktop, "D Password+GrabBag",
          [pv("Password", PW), pv("PasswordGrabBag", grab)])
    probe(desktop, "E nothing (baseline)", [])
    return 0


if __name__ == "__main__":
    sys.exit(main())
