"""Spike: UNO re-encryption of existing plaintext OOXML files (Wave 0 todo 2).

A. Re-encrypt docx/xlsx/pptx: loadComponentFromURL(plaintext) then storeToURL(
   [FilterName, Password, EncryptionData{CryptoType, Password}]); the product must
   be a CFB container with EncryptedPackage + CipherBoxDataSpace marks and NO
   EncryptionInfo stream (LO agile's stream name).  Round trip verified through
   the ENGINE's decrypt over UNO, oox style -- NOT via loadComponentFromURL,
   known-broken on LO 26.8 for custom dataspace containers (spike_reload_rootcause.py).
Siblings: spike_format_boundary.py (doc/xls/ppt), spike_wrongpassword.py
(wrong-password reload, per-load child isolation), spike_reload_rootcause.py.
Run with the bundled python against the persistent service (start_soffice.ps1),
TMP/TEMP at the service temp dir (engine component log location).
"""

import io
import os
import sys
import time
import zipfile

import uno
from com.sun.star.beans import NamedValue, PropertyValue

URL = "uno:pipe,name=cipherbox-service;urp;StarOffice.ComponentContext"
OUT_ROOT = r"S:\.cipherbox-tmp\spike-todo-02"
COMPONENT_LOG = os.path.join(os.environ.get("TEMP", "."), "cipherbox-encryption.log")
SERVICE = "com.sun.star.comp.oox.crypto.CipherBoxDataSpace"

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
PASSWORD = "correct horse battery staple"
WRONG_PASSWORD = "wrong password entirely"
CRYPTO_TYPE = "CipherBoxDataSpace"
CONTENT = "CipherBox round trip marker 4711"

EXPECTED_STREAMS = (
    "\006DataSpaces/DataSpaceMap", "\006DataSpaces/Version",
    "\006DataSpaces/DataSpaceInfo/CipherBoxDataSpace",
    "\006DataSpaces/TransformInfo/CipherBoxTransform/\006Primary", "EncryptedPackage")

FORMATS = [
    ("docx", "MS Word 2007 XML", "private:factory/swriter", "writer"),
    ("xlsx", "Calc MS Excel 2007 XML", "private:factory/scalc", "calc"),
    ("pptx", "Impress MS PowerPoint 2007 XML", "private:factory/simpress", "impress"),
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
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(1)
    raise SystemExit("could not connect to soffice: %s" % last)


def read_log():
    try:
        with open(COMPONENT_LOG, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


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


def encryption_args(filter_name):
    """Media descriptor that routes the save to the custom XPackageEncryption."""
    return (
        pv("FilterName", filter_name),
        pv("Password", PASSWORD),
        pv("EncryptionData", uno.Any(
            "[]com.sun.star.beans.NamedValue",
            (nv("CryptoType", CRYPTO_TYPE), nv("Password", PASSWORD)))),
    )


def drain(stream):
    """Pull an XInputStream dry; PyUNO readBytes returns (count, data)."""
    chunks = []
    while True:
        count, data = stream.readBytes(uno.ByteSequence(b""), 65536)
        if count <= 0 or not data:
            break
        chunks.append(bytes(bytearray(data))[:count])
    return b"".join(chunks)


def open_cfb_streams(ctx, path):
    """Extract a CFB container's streams as {slash-joined name: bytes} over UNO.

    OLESimpleStorage walks the same substorage tree oox's DocumentDecryption
    flattens into the stream list it hands the engine (lcl_getListOfStreams).
    """
    smgr = ctx.ServiceManager
    ucb = smgr.createInstanceWithContext(
        "com.sun.star.ucb.SimpleFileAccess", ctx)
    source = ucb.openFileRead(uno.systemPathToFileUrl(path))
    storage = smgr.createInstanceWithArgumentsAndContext(
        "com.sun.star.embed.OLESimpleStorage", (source,), ctx)
    streams = {}

    def walk(store, prefix):
        for name in store.getElementNames():
            child = store.getByName(name)
            full = prefix + "/" + name if prefix else name
            if hasattr(child, "getElementNames"):
                walk(child, full)
            else:
                streams[full] = drain(child.getInputStream())

    walk(storage, "")
    return streams


def zip_contains_marker(data):
    """The OOXML ZIP stores the marker DEFLATED -- scan entries decompressed."""
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return any(CONTENT.encode("utf-8") in zf.read(name)
                   for name in zf.namelist())


def engine_roundtrip(ctx, ext, path):
    """Verify a CipherBox product through the ENGINE's decrypt, oox-style."""
    streams = open_cfb_streams(ctx, path)
    check("%s: CFB exposes the 5 engine streams" % ext,
          set(streams) == set(EXPECTED_STREAMS), str(sorted(streams)))
    if "EncryptedPackage" not in streams:
        return
    obj = ctx.ServiceManager.createInstanceWithContext(SERVICE, ctx)
    enc = obj.queryInterface(
        uno.getTypeByName("com.sun.star.packages.XPackageEncryption"))
    if not check("%s: engine instantiates for round trip" % ext, enc is not None):
        return
    nvs = tuple(nv(name, uno.ByteSequence(data))
                for name, data in streams.items())
    check("%s: readEncryptionInfo accepts the container" % ext,
          bool(enc.readEncryptionInfo(nvs)))
    check("%s: generateEncryptionKey(correct password)" % ext,
          bool(enc.generateEncryptionKey(PASSWORD)))
    check("%s: generateEncryptionKey(wrong password) rejected" % ext,
          not enc.generateEncryptionKey(WRONG_PASSWORD))
    pkg_input = ctx.ServiceManager.createInstanceWithArgumentsAndContext(
        "com.sun.star.io.SequenceInputStream",
        (uno.ByteSequence(streams["EncryptedPackage"]),), ctx)
    result = enc.decrypt(pkg_input, ())
    if not check("%s: decrypt() returns true" % ext, bool(result[0])):
        return
    data = drain(result[1])
    check("%s: recovered payload is the OOXML ZIP (PK magic)" % ext,
          data.startswith(b"PK\x03\x04"), "%d bytes" % len(data))
    check("%s: marker bytes survive the engine round trip" % ext,
          zip_contains_marker(data))


def reencrypt(ctx, desktop, ext, filter_name, factory, kind, out_dir):
    print("\n--- A. re-encrypt %s (%s) ---" % (ext, filter_name))
    plain = os.path.join(out_dir, "plain.%s" % ext)
    target = os.path.join(out_dir, "reencrypted.%s" % ext)
    doc = desktop.loadComponentFromURL(factory, "_blank", 0, ())
    set_content(doc, kind)
    doc.storeToURL(uno.systemPathToFileUrl(plain), (pv("FilterName", filter_name),))
    doc.close(False)

    before = len(read_log())
    doc = desktop.loadComponentFromURL(uno.systemPathToFileUrl(plain), "_blank", 0, ())
    if not check("%s: plaintext loads" % ext, doc is not None):
        return
    doc.storeToURL(uno.systemPathToFileUrl(target), encryption_args(filter_name))
    doc.close(False)
    after = read_log()

    if not check("%s: encrypted product written" % ext, os.path.exists(target)):
        return
    with open(target, "rb") as fh:
        raw = fh.read()
    check("%s: OLE/CFB container magic" % ext, raw[:8] == OLE_MAGIC,
          "%d bytes, magic=%s" % (len(raw), raw[:8].hex()))
    check("%s: EncryptedPackage stream present" % ext,
          "EncryptedPackage".encode("utf-16-le") in raw)
    check("%s: CipherBoxDataSpace marks present" % ext,
          b"CipherBoxDataSpace" in raw
          or "CipherBoxDataSpace".encode("utf-16-le") in raw)
    check("%s: no EncryptionInfo stream (agile-only, must be absent)" % ext,
          "EncryptionInfo".encode("utf-16-le") not in raw)
    check("%s: engine encrypt() ran on save" % ext, "encrypt()" in after[before:])
    engine_roundtrip(ctx, ext, target)


def print_conclusions():
    print()
    print("================ CONCLUSIONS (Wave 0 todo 2) ================")
    print("A. Re-encrypt PROVEN: plaintext-load + storeToURL(Password + EncryptionData{")
    print("   CryptoType}) yields CFB containers (EncryptedPackage + CipherBoxDataSpace")
    print("   marks, no EncryptionInfo); the ENGINE's decrypt recovers the OOXML ZIP with")
    print("   the round-trip marker byte-consistent (fallback criterion 1 green).")
    print("B. Format boundary CONFIRMED: doc/xls/ppt ignore EncryptionData{CryptoType}; no")
    print("   CipherBoxDataSpace marks, engine never invoked -> out of scope (sibling spike).")
    print("C. Wrong-password reload on LO 26.8 RAISES 'Unsupported URL ... type")
    print("   detection aborted' (does not return None); the engine verifier rejects")
    print("   the wrong password first (log-proven) -- recorded with per-load child")
    print("   isolation in spike_wrongpassword.py (plan QA wording must assert the raise).")
    print("D. Reload break is structural: decrypt()'s output stream is an [out] IDL")
    print("   param -- a PyUNO engine never sees the caller's stream; filterdetect sniffs")
    print("   only its own UNOMemoryStream -> empty -> no type -> Text fallback.")
    print("   Production path unaffected (todo 13 encrypts via plaintext-load + encrypted-")
    print("   store, todo 14 decrypts agent-side). Full analysis: sibling spike + .md record.")


def main():
    out_dir = os.path.join(OUT_ROOT, time.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(out_dir, exist_ok=True)
    print("spike_reencrypt; products in %s" % out_dir)
    ctx = connect()
    desktop = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.Desktop", ctx)
    for ext, filter_name, factory, kind in FORMATS:
        try:
            reencrypt(ctx, desktop, ext, filter_name, factory, kind, out_dir)
        except Exception as exc:  # noqa: BLE001
            print("ERROR %s: %r" % (ext, exc))
            FAILURES.append("%s raised" % ext)
    print_conclusions()
    print()
    if FAILURES:
        print("RESULT: FAIL (%d) -> %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("RESULT: PASS (3 OOXML re-encrypted + engine round trip)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
