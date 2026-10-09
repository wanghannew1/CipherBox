"""Real-document test: does oox actually drive CipherBoxDataSpace on save/reload?

Trigger discovered empirically (see probe_encrypt.py): oox selects a *custom*
XPackageEncryption engine from the media descriptor property `EncryptionData`, a
`sequence<NamedValue>` containing `CryptoType`.  `FilterData: EncryptFile/Password` is
ignored for this purpose, and a bare media `Password` selects LibreOffice's own built-in
agile encryption instead.

ODF is intentionally excluded per requirement.
"""

import os
import sys
import time

import uno
from com.sun.star.beans import NamedValue, PropertyValue

URL = "uno:socket,host=127.0.0.1,port=2002;urp;StarOffice.ComponentContext"
OUT_DIR = os.path.join(os.environ.get("TEMP", "."), "cipherbox-docs")
COMPONENT_LOG = os.path.join(os.environ.get("TEMP", "."), "cipherbox-encryption.log")

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
PASSWORD = "correct horse battery staple"
WRONG_PASSWORD = "wrong password entirely"
CRYPTO_TYPE = "CipherBoxDataSpace"
CONTENT = "CipherBox round trip marker 4711"

FORMATS = [
    ("docx", "MS Word 2007 XML", "private:factory/swriter", "writer", True),
    ("xlsx", "Calc MS Excel 2007 XML", "private:factory/scalc", "calc", True),
    ("pptx", "Impress MS PowerPoint 2007 XML", "private:factory/simpress", "impress", True),
    ("doc", "MS Word 97", "private:factory/swriter", "writer", False),
    ("xls", "MS Excel 97", "private:factory/scalc", "calc", False),
    ("ppt", "MS PowerPoint 97", "private:factory/simpress", "impress", False),
]

FAILURES = []


def check(label, condition, detail=""):
    print("%s  %s %s" % ("PASS" if condition else "FAIL", label, detail))
    if not condition:
        FAILURES.append(label)
    return bool(condition)


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


def connect(timeout=60):
    local = uno.getComponentContext()
    resolver = local.ServiceManager.createInstanceWithContext(
        "com.sun.star.bridge.UnoUrlResolver", local)
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            return resolver.resolve(URL)
        except Exception as exc:
            last = exc
            time.sleep(1)
    raise SystemExit("could not connect to soffice: %s" % last)


def set_content(doc, kind):
    if kind == "writer":
        doc.Text.setString(CONTENT)
    elif kind == "calc":
        doc.Sheets.getByIndex(0).getCellByPosition(0, 0).setString(CONTENT)
    elif kind == "impress":
        page = doc.getDrawPages().getByIndex(0)
        shape = doc.createInstance("com.sun.star.presentation.TitleTextShape")
        page.add(shape)
        shape.setString(CONTENT)


def get_content(doc, kind):
    if kind == "writer":
        return doc.Text.getString()
    if kind == "calc":
        return doc.Sheets.getByIndex(0).getCellByPosition(0, 0).getString()
    page = doc.getDrawPages().getByIndex(0)
    for i in range(page.getCount()):
        shape = page.getByIndex(i)
        if hasattr(shape, "getString"):
            return shape.getString()
    return ""


def read_log():
    try:
        with open(COMPONENT_LOG, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def has_marker(raw):
    """CFB stores directory entry names as UTF-16LE, stream contents as raw bytes."""
    return (b"CipherBoxDataSpace" in raw
            or "CipherBoxDataSpace".encode("utf-16-le") in raw)


def run_one(ctx, desktop, ext, filter_name, factory, kind, use_hook):
    print("\n--- %s (%s) %s ---" % (
        ext, filter_name, "custom XPackageEncryption" if use_hook else "built-in crypto"))
    path = os.path.join(OUT_DIR, "sample.%s" % ext)
    if os.path.exists(path):
        os.remove(path)

    args = [pv("FilterName", filter_name), pv("Password", PASSWORD)]
    if use_hook:
        args.append(pv("EncryptionData", uno.Any(
            "[]com.sun.star.beans.NamedValue",
            (nv("CryptoType", CRYPTO_TYPE), nv("Password", PASSWORD)))))

    log_before = len(read_log())
    doc = desktop.loadComponentFromURL(factory, "_blank", 0, ())
    set_content(doc, kind)
    doc.storeToURL(uno.systemPathToFileUrl(path), tuple(args))
    doc.close(False)
    log_after = read_log()

    if not check("%s: file written" % ext, os.path.exists(path)):
        return
    with open(path, "rb") as fh:
        raw = fh.read()

    check("%s: is an OLE/CFB container" % ext, raw[:8] == OLE_MAGIC,
          "%d bytes, magic=%s" % (len(raw), raw[:8].hex()))
    check("%s: EncryptedPackage present" % ext,
          (b"EncryptedPackage" in raw
           or "EncryptedPackage".encode("utf-16-le") in raw))

    if use_hook:
        check("%s: our encrypt() ran" % ext, "encrypt()" in log_after[log_before:],
              "component log %d -> %d bytes" % (log_before, len(log_after)))
        check("%s: key derived from password" % ext,
              "key derived from Password" in log_after[log_before:])
        check("%s: container names CipherBoxDataSpace" % ext, has_marker(raw))
    else:
        print("SKIP  %s: built-in encryption, CipherBox hook not applicable" % ext)

    before_reload = len(read_log())
    reopened = desktop.loadComponentFromURL(
        uno.systemPathToFileUrl(path), "_blank", 0, (pv("Password", PASSWORD),))
    if not check("%s: reloads with correct password" % ext, reopened is not None):
        return
    if use_hook:
        check("%s: our decrypt() ran on reload" % ext,
              "decrypt():" in read_log()[before_reload:])
    got = get_content(reopened, kind)
    check("%s: content survives round trip" % ext, CONTENT in got, repr(got[:50]))
    reopened.close(False)

    if use_hook:
        denied = desktop.loadComponentFromURL(
            uno.systemPathToFileUrl(path), "_blank", 0,
            (pv("Password", WRONG_PASSWORD),))
        check("%s: wrong password is rejected" % ext, denied is None)
        if denied is not None:
            denied.close(False)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    ctx = connect()
    desktop = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.Desktop", ctx)
    for ext, filter_name, factory, kind, use_hook in FORMATS:
        try:
            run_one(ctx, desktop, ext, filter_name, factory, kind, use_hook)
        except Exception as exc:
            print("ERROR %s: %r" % (ext, exc))
            FAILURES.append("%s raised" % ext)
    print()
    if FAILURES:
        print("RESULT: FAIL (%d) -> %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("RESULT: PASS (6 formats saved, encrypted and reloaded)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
