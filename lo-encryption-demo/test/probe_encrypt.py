"""Find the media-descriptor shape that makes oox select our XPackageEncryption.

`FilterData: EncryptFile/Password` did NOT trigger encryption (component log stayed empty), so
try the other candidates oox consults on export: a plain media `Password`, and a media
`EncryptionData` NamedValue sequence carrying `CryptoType` (which is how oox names a custom
XPackageEncryption engine).
"""

import os
import sys
import time

import uno
from com.sun.star.beans import NamedValue, PropertyValue
from com.sun.star.connection import NoConnectException

URL = "uno:socket,host=127.0.0.1,port=2002;urp;StarOffice.ComponentContext"
OUT_DIR = os.path.join(os.environ.get("TEMP", "."), "cipherbox-probe")
COMPONENT_LOG = os.path.join(os.environ.get("TEMP", "."), "cipherbox-encryption.log")
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
PW = "correct horse battery staple"
CRYPTO_TYPE = "CipherBoxDataSpace"


def pv(name, value):
    p = PropertyValue()
    p.Name = name
    p.Value = value
    return p


def _named(name, value):
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
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(1)
    raise SystemExit("could not connect: %s" % last)


def log_size():
    try:
        return os.path.getsize(COMPONENT_LOG)
    except OSError:
        return 0


def named_seq(items):
    return uno.Any("[]com.sun.star.beans.NamedValue", tuple(items))


def try_variant(desktop, label, args_extra):
    path = os.path.join(OUT_DIR, "probe.docx")
    if os.path.exists(path):
        os.remove(path)
    before = log_size()
    doc = desktop.loadComponentFromURL("private:factory/swriter", "_blank", 0, ())
    doc.Text.setString("probe")
    try:
        doc.storeToURL(uno.systemPathToFileUrl(path), args_extra)
    finally:
        doc.close(False)
    after = log_size()
    if not os.path.exists(path):
        print("%-46s NO FILE" % label)
        return
    with open(path, "rb") as fh:
        raw = fh.read()
    print("%-46s %6d B  magic=%s  ourMarker=%-5s  componentLog %d->%d"
          % (label, len(raw), raw[:8].hex(), b"CipherBoxDataSpace" in raw, before, after))


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    ctx = connect()
    desktop = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.Desktop", ctx)
    fn = pv("FilterName", "MS Word 2007 XML")

    try_variant(desktop, "1 FilterData{EncryptFile,Password}",
                (fn, pv("FilterData", uno.Any("[]com.sun.star.beans.PropertyValue",
                 (pv("EncryptFile", True), pv("Password", PW))))))

    try_variant(desktop, "2 media Password",
                (fn, pv("Password", PW)))

    try_variant(desktop, "3 media Password+EncryptionData{CryptoType}",
                (fn, pv("Password", PW),
                 pv("EncryptionData", named_seq((
                     _named("CryptoType", CRYPTO_TYPE),
                     _named("Password", PW))))))

    try_variant(desktop, "4 media EncryptionData{CryptoType,Password}",
                (fn, pv("EncryptionData", named_seq((
                     _named("CryptoType", CRYPTO_TYPE),
                     _named("Password", PW))))))

    try_variant(desktop, "5 media Password+EncryptionData+Alg",
                (fn, pv("Password", PW),
                 pv("EncryptionData", named_seq((
                     _named("CryptoType", CRYPTO_TYPE),
                     _named("Password", PW),
                     _named("AlgorithmName", "CipherBox"),
                     _named("KeySize", 256))))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
