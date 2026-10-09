"""Spike: binary-format boundary of the custom CipherBoxDataSpace engine (todo 2).

Question 3 of the plan's todo 2 acceptance: for .doc/.xls/.ppt, does
storeToURL with EncryptionData{CryptoType:"CipherBoxDataSpace"} route the
custom XPackageEncryption engine at all?  The plan expected it does NOT
(test_documents.py L33-35 use_hook=False; the custom engine assumed to
cover OOXML only) -- the measurement FALSIFIED that expectation: with
EncryptionData{CryptoType} in the media descriptor, the binary filters
route the custom engine too (the storage-level encryption layer is
format-agnostic).  This spike records the actual boundary with byte
inspection, the engine component log delta, and an engine-decrypt round
trip on each product.

Method per format: fresh plaintext via private:factory + marker +
storeToURL(FilterName), then loadComponentFromURL(plaintext) +
storeToURL(target, [FilterName, Password, EncryptionData{CryptoType,
Password}]) -- the exact same media descriptor that routes the custom
engine for docx/xlsx/pptx (spike_reencrypt.py) -- then: product bytes
(OLE magic, EncryptedPackage, CipherBoxDataSpace marks, no EncryptionInfo),
engine log delta (encrypt() ran), and the ENGINE's decrypt recovering the
whole inner binary office file (OLE magic + marker).

Run with LibreOffice's bundled python against the persistent service (see
../start_soffice.ps1); TMP/TEMP must point at the service temp dir so the
engine component log read here is the one the service writes.
"""

import os
import sys
import time

import uno
from com.sun.star.beans import NamedValue, PropertyValue

URL = "uno:pipe,name=cipherbox-service;urp;StarOffice.ComponentContext"
OUT_ROOT = r"S:\.cipherbox-tmp\spike-todo-02"
COMPONENT_LOG = os.path.join(os.environ.get("TEMP", "."), "cipherbox-encryption.log")
SERVICE = "com.sun.star.comp.oox.crypto.CipherBoxDataSpace"

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
PASSWORD = "correct horse battery staple"
CRYPTO_TYPE = "CipherBoxDataSpace"
CONTENT = "CipherBox round trip marker 4711"

EXPECTED_STREAMS = (
    "\006DataSpaces/DataSpaceMap", "\006DataSpaces/Version",
    "\006DataSpaces/DataSpaceInfo/CipherBoxDataSpace",
    "\006DataSpaces/TransformInfo/CipherBoxTransform/\006Primary", "EncryptedPackage")

FORMATS = [
    ("doc", "MS Word 97", "private:factory/swriter", "writer"),
    ("xls", "MS Excel 97", "private:factory/scalc", "calc"),
    ("ppt", "MS PowerPoint 97", "private:factory/simpress", "impress"),
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
    """Media descriptor that routes the custom engine for OOXML formats."""
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
    """Extract a CFB container's streams as {slash-joined name: bytes} over UNO."""
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


def engine_roundtrip(ctx, ext, path):
    """Verify a binary-format CipherBox product through the ENGINE's decrypt."""
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
    pkg_input = ctx.ServiceManager.createInstanceWithArgumentsAndContext(
        "com.sun.star.io.SequenceInputStream",
        (uno.ByteSequence(streams["EncryptedPackage"]),), ctx)
    result = enc.decrypt(pkg_input, ())
    if not check("%s: decrypt() returns true" % ext, bool(result[0])):
        return
    data = drain(result[1])
    check("%s: recovered payload is the inner binary office file (OLE magic)" % ext,
          data.startswith(OLE_MAGIC), "%d bytes" % len(data))
    check("%s: marker bytes survive the engine round trip" % ext,
          CONTENT.encode("utf-8") in data or CONTENT.encode("utf-16-le") in data)


def boundary(ctx, desktop, ext, filter_name, factory, kind, out_dir):
    print("\n--- B. format boundary %s (%s) + EncryptionData{CryptoType} ---" % (
        ext, filter_name))
    plain = os.path.join(out_dir, "plain.%s" % ext)
    target = os.path.join(out_dir, "binencrypted.%s" % ext)
    doc = desktop.loadComponentFromURL(factory, "_blank", 0, ())
    set_content(doc, kind)
    doc.storeToURL(uno.systemPathToFileUrl(plain), (pv("FilterName", filter_name),))
    doc.close(False)
    if not check("%s: plaintext written" % ext, os.path.exists(plain)):
        return

    before = len(read_log())
    error = None
    doc = desktop.loadComponentFromURL(uno.systemPathToFileUrl(plain), "_blank", 0, ())
    try:
        doc.storeToURL(uno.systemPathToFileUrl(target), encryption_args(filter_name))
    except Exception as exc:  # noqa: BLE001
        error = "%s: %s" % (type(exc).__name__, exc)
    finally:
        doc.close(False)
    after = read_log()
    if error is not None:
        print("NOTE  %s: storeToURL raised %r" % (ext, error))
    if not check("%s: product written" % ext, os.path.exists(target)):
        return
    with open(target, "rb") as fh:
        raw = fh.read()
    marks = b"CipherBoxDataSpace" in raw or "CipherBoxDataSpace".encode("utf-16-le") in raw
    engine_ran = "encrypt()" in after[before:]
    print("  %s: %d bytes, OLE magic=%s, EncryptedPackage=%s, "
          "CipherBoxDataSpace marks=%s, EncryptionInfo=%s, engine encrypt() ran=%s"
          % (ext, len(raw), raw[:8] == OLE_MAGIC,
             "EncryptedPackage".encode("utf-16-le") in raw, marks,
             "EncryptionInfo".encode("utf-16-le") in raw, engine_ran))
    check("%s: custom engine IS routed via EncryptionData{CryptoType} "
          "(plan's expected boundary falsified)" % ext, marks and engine_ran)
    engine_roundtrip(ctx, ext, target)


def main():
    out_dir = os.path.join(OUT_ROOT, time.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(out_dir, exist_ok=True)
    print("spike_format_boundary; products in %s" % out_dir)
    ctx = connect()
    desktop = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.Desktop", ctx)
    for ext, filter_name, factory, kind in FORMATS:
        try:
            boundary(ctx, desktop, ext, filter_name, factory, kind, out_dir)
        except Exception as exc:  # noqa: BLE001
            print("ERROR %s: %r" % (ext, exc))
            FAILURES.append("%s raised" % ext)
    print()
    print("CONCLUSION: the plan's expected binary-format boundary is FALSIFIED:")
    print("doc/xls/ppt with EncryptionData{CryptoType} DO route the custom")
    print("CipherBoxDataSpace engine (CipherBox CFB products, engine encrypt() ran,")
    print("engine-decrypt round trip recovers the inner binary office file with the")
    print("marker). The storage-level encryption layer is format-agnostic; the")
    print("use_hook=False premise came from the Password-only path (built-in crypto),")
    print("not from the EncryptionData path. The real boundary is the RELOAD path,")
    print("broken for ALL custom-dataspace containers regardless of format (see")
    print("spike_reload_rootcause.py) -- which the production path never uses.")
    print("The doc/xls/ppt out-of-scope decision rests on a falsified technical")
    print("premise and needs the orchestrator's re-decision with this evidence.")
    print()
    if FAILURES:
        print("RESULT: FAIL (%d) -> %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("RESULT: PASS (doc/xls/ppt DO route the custom engine; "
          "boundary premise falsified with byte + round-trip evidence)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
