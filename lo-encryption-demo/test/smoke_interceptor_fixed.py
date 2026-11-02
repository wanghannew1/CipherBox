"""Smoke: FIXED force_encrypt interceptor (plan todo 17/18 minimal subset).

Under the LO bundled python against the persistent headless service (pipe
``cipherbox-service``):  S1 registers the FIXED interceptor on a fresh Writer
frame from THIS process (spike P5 pattern) and dispatches ``.uno:SaveAs`` to
a ``.docx`` target -> product must be CFB (OLE magic), medium switched,
encrypt audit with a real content sha256.  S2 (fresh connection) decrypts
the product through the ENGINE with the same password (wrong one rejected)
and recovers the marker-carrying OOXML ZIP.  S3 (fresh connection) dispatches
``.uno:ExportToPDF`` -> export_plaintext audit fires with a real sha256.

Reconnect-per-operation (e2e_full pattern); outcome assertions read disk.
Artifacts: ``S:\\.cipherbox-tmp\\smoke-interceptor\\``.  Run from repo root:
``& 'C:\\Program Files\\LibreOffice\\program\\python.exe' ^
 lo-encryption-demo\\test\\smoke_interceptor_fixed.py``
"""

# allow: SIZE_OK -- task mandates ONE smoke file holding three scenarios
# (forced SaveAs, engine round trip, export audit); every helper is a
# proven-copied UNO verification primitive (e2e_full/spike pattern) and every
# check() is an acceptance assertion; there is no dead code to cut.

import io
import os
import sys
import time
import zipfile

import uno
from com.sun.star.beans import NamedValue, PropertyValue

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "src"))

import force_encrypt  # noqa: E402  (fixed interceptor under test)

URL = "uno:pipe,name=cipherbox-service;urp;StarOffice.ComponentContext"
OUT_DIR = r"S:\.cipherbox-tmp\smoke-interceptor"
ENGINE_LOG = r"S:\.cipherbox-tmp\service\cipherbox-encryption.log"
ENGINE_SERVICE = "com.sun.star.comp.oox.crypto.CipherBoxDataSpace"
FILTER_DOCX = "MS Word 2007 XML"
FILTER_PDF = "writer_pdf_Export"
FACTORY_WRITER = "private:factory/swriter"
PASSWORD = "smoke interceptor password 2602"
MARKER = "CipherBox smoke interceptor marker %d" % int(time.time())

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
OOXML_MAGIC = b"PK\x03\x04"

EXPECTED_STREAMS = (
    "\x06DataSpaces/DataSpaceMap", "\x06DataSpaces/Version",
    "\x06DataSpaces/DataSpaceInfo/CipherBoxDataSpace",
    "\x06DataSpaces/TransformInfo/CipherBoxTransform/\x06Primary",
    "EncryptedPackage")

FAILURES = []


def check(label, condition, detail=""):
    print("%s  %s %s" % ("PASS" if condition else "FAIL", label, detail), flush=True)
    if not condition:
        FAILURES.append(label)
    return bool(condition)


def note(label, detail):
    print("NOTE  %s -- %s" % (label, detail), flush=True)


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


def connect(timeout=60.0):
    """Bounded UNO readiness probe (e2e_full pattern)."""
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
    raise SystemExit("could not connect to soffice pipe: %s" % last)


def engine_log():
    try:
        with open(ENGINE_LOG, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


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
    """Extract a CFB container's streams as {name: bytes} over UNO (e2e_full)."""
    smgr = ctx.ServiceManager
    ucb = smgr.createInstanceWithContext("com.sun.star.ucb.SimpleFileAccess", ctx)
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


def zip_has_marker(data):
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return any(MARKER.encode("utf-8") in zf.read(name) for name in zf.namelist())


def engine_roundtrip(ctx, label, path):
    """Verify the CFB product through the ENGINE's decrypt (oox-style)."""
    streams = open_cfb_streams(ctx, path)
    if not check("%s: CFB exposes the 5 engine streams" % label,
                 set(streams) == set(EXPECTED_STREAMS), str(sorted(streams))):
        return
    obj = ctx.ServiceManager.createInstanceWithContext(ENGINE_SERVICE, ctx)
    enc = obj.queryInterface(
        uno.getTypeByName("com.sun.star.packages.XPackageEncryption"))
    if not check("%s: engine instantiates" % label, enc is not None):
        return
    nvs = tuple(nv(name, uno.ByteSequence(data)) for name, data in streams.items())
    check("%s: readEncryptionInfo accepts the container" % label,
          bool(enc.readEncryptionInfo(nvs)))
    check("%s: generateEncryptionKey(SMOKE password) accepted" % label,
          bool(enc.generateEncryptionKey(PASSWORD)))
    check("%s: generateEncryptionKey(wrong password) rejected" % label,
          not enc.generateEncryptionKey("wrong smoke password entirely"))
    pkg_input = ctx.ServiceManager.createInstanceWithArgumentsAndContext(
        "com.sun.star.io.SequenceInputStream",
        (uno.ByteSequence(streams["EncryptedPackage"]),), ctx)
    result = enc.decrypt(pkg_input, ())
    ok = result[0] if isinstance(result, tuple) else result
    if not check("%s: decrypt() returns true" % label, bool(ok)):
        return
    out = result[1] if isinstance(result, tuple) and len(result) > 1 else None
    if out is None:
        check("%s: decrypt() yields an output stream" % label, False)
        return
    data = drain(out)
    check("%s: recovered payload is the OOXML ZIP (PK magic)" % label,
          data.startswith(OOXML_MAGIC), "%d bytes" % len(data))
    check("%s: marker survives the engine round trip" % label, zip_has_marker(data))


def release_and_close(interceptor, doc):
    for closer in (interceptor.release, lambda: doc.close(False)):
        try:
            closer()
        except Exception:  # noqa: BLE001  (bridge may be gone; disk tells truth)
            pass


def _sha_hex_ok(value):
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def scenario_forced_saveas():
    """S1: forced .uno:SaveAs to a .docx target must produce CFB ciphertext."""
    target = os.path.join(OUT_DIR, "smoke-forced.docx")
    if os.path.exists(target):
        os.remove(target)
    audits = []
    ctx = connect()
    desktop = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.Desktop", ctx)
    doc = desktop.loadComponentFromURL(FACTORY_WRITER, "_blank", 0, ())
    doc.Text.setString(MARKER)
    frame = doc.CurrentController.Frame
    log_before = len(engine_log())
    interceptor = force_encrypt.register_on_frame(
        frame, lambda: PASSWORD,
        audit_reporter=lambda a, h, kv, ok: audits.append((a, h, kv, ok)))
    helper = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.DispatchHelper", ctx)
    helper.executeDispatch(frame, ".uno:SaveAs", "", 0, (
        pv("URL", uno.systemPathToFileUrl(target)),
        pv("FilterName", FILTER_DOCX)))

    encrypt_audits = [a for a in audits if a[0] == "encrypt"]
    check("S1 encrypt audit fired exactly once", len(encrypt_audits) == 1,
          str(audits))
    if encrypt_audits:
        check("S1 encrypt audit carries a real content sha256 (64 hex)",
              _sha_hex_ok(encrypt_audits[0][1]), "hash=%r" % encrypt_audits[0][1])
        check("S1 encrypt audit ok=True", encrypt_audits[0][3] is True)
    try:
        check("S1 doc medium switched to the target (real SaveAs semantics)",
              doc.getLocation() == uno.systemPathToFileUrl(target),
              "location=%r" % doc.getLocation())
        check("S1 doc unmodified after forced SaveAs", not doc.isModified())
    except Exception as exc:  # noqa: BLE001  (bridge may die across operations)
        note("S1 in-memory assertions skipped", repr(exc))
    release_and_close(interceptor, doc)
    if os.path.exists(ENGINE_LOG):
        check("S1 engine encrypt() ran during forced SaveAs",
              "encrypt()" in engine_log()[log_before:])
    else:
        note("S1 engine log missing at", ENGINE_LOG)

    if not check("S1 product written", os.path.exists(target), target):
        return None
    with open(target, "rb") as fh:
        raw = fh.read()
    check("S1 product starts with OLE/CFB magic", raw[:8] == OLE_MAGIC,
          "%d bytes, magic=%s" % (len(raw), raw[:8].hex()))
    check("S1 product is NOT plaintext OOXML (no PK magic)",
          not raw.startswith(OOXML_MAGIC), "magic=%s" % raw[:8].hex())
    return target


def scenario_export_audit():
    """S3: .uno:ExportToPDF must fire the export_plaintext audit hook."""
    audits = []
    ctx = connect()
    desktop = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.Desktop", ctx)
    doc = desktop.loadComponentFromURL(FACTORY_WRITER, "_blank", 0, ())
    doc.Text.setString(MARKER)
    frame = doc.CurrentController.Frame
    interceptor = force_encrypt.register_on_frame(
        frame, lambda: PASSWORD,
        audit_reporter=lambda a, h, kv, ok: audits.append((a, h, kv, ok)))
    helper = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.DispatchHelper", ctx)
    pdf = os.path.join(OUT_DIR, "smoke-export.pdf")
    # URL pre-set: spike P8's proven anti-hang shape for the ExportToPDF slot.
    helper.executeDispatch(frame, ".uno:ExportToPDF", "", 0, (
        pv("URL", uno.systemPathToFileUrl(pdf)),
        pv("FilterName", FILTER_PDF)))

    export_audits = [a for a in audits if a[0] == "export_plaintext"]
    check("S3 export_plaintext audit fired for .uno:ExportToPDF",
          len(export_audits) == 1, str(audits))
    if export_audits:
        check("S3 export audit carries a real content sha256 (64 hex)",
              _sha_hex_ok(export_audits[0][1]), "hash=%r" % export_audits[0][1])
        check("S3 export audit ok=True", export_audits[0][3] is True)
    if os.path.exists(pdf):
        with open(pdf, "rb") as fh:
            head = fh.read(5)
        note("S3 PDF product written", "%d bytes, magic=%r" % (os.path.getsize(pdf), head))
    else:
        note("S3 PDF product not written headless (P8: picker-bound slot)",
             "the audit hook firing is the assertion under test")
    release_and_close(interceptor, doc)


def sweep_smoke_docs():
    """Close any smoke document left open (marker-scoped, run-unique)."""
    try:
        ctx = connect(timeout=15.0)
    except SystemExit:
        note("cleanup skipped", "service unreachable")
        return
    desktop = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.Desktop", ctx)
    enum = desktop.getComponents().createEnumeration()
    doomed = []
    while enum.hasMoreElements():
        comp = enum.nextElement()
        try:
            if MARKER in comp.Text.getString():
                doomed.append(comp)
        except Exception:  # noqa: BLE001  (non-Writer components have no .Text)
            pass
    for comp in doomed:
        try:
            comp.close(False)
        except Exception:  # noqa: BLE001
            pass
    print("cleanup closed %d smoke doc(s)" % len(doomed), flush=True)


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    print("smoke_interceptor_fixed; artifacts in %s" % OUT_DIR, flush=True)
    target = None
    try:
        target = scenario_forced_saveas()
    except Exception as exc:  # noqa: BLE001
        print("ERROR S1 raised: %r" % (exc,), flush=True)
        FAILURES.append("S1 raised")
    if target is not None and os.path.exists(target):
        try:
            engine_roundtrip(connect(), "S2", target)
        except Exception as exc:  # noqa: BLE001
            print("ERROR S2 raised: %r" % (exc,), flush=True)
            FAILURES.append("S2 raised")
    else:
        check("S2 product exists for engine verification", False, repr(target))
    try:
        scenario_export_audit()
    except Exception as exc:  # noqa: BLE001
        print("ERROR S3 raised: %r" % (exc,), flush=True)
        FAILURES.append("S3 raised")
    sweep_smoke_docs()
    print(flush=True)
    if FAILURES:
        print("RESULT: FAIL (%d) -> %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("RESULT: PASS (forced SaveAs CFB product + engine decrypt round trip "
          "+ export audit)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
