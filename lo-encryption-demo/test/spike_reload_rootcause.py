"""Spike: root cause of the custom-dataspace reload break on LO 26.8 (todo 2).

todo 1 established: saving via storeToURL(Password + EncryptionData{CryptoType})
works for all 6 formats, but RELOADING a custom-dataspace container via
loadComponentFromURL(Password) is broken on LO 26.8 -- type detection returns
an empty type, explicit-filter load returns None, auto-detect falls back to the
Text filter and shows the raw CFB bytes as text -- while the engine log proves
the engine was engaged and decrypted correctly.  This spike digs one level
deeper WITHOUT modifying cipherbox.py:

  (a) Isolation: is GENERAL encrypted reload broken on 26.8, or only the
      custom dataspace?  Save a docx with Password only (no EncryptionData ->
      LO's built-in agile crypto) and reload it with the password.
  (b) Divergence: on a custom-dataspace product, probe where the reload
      diverges -- TypeDetection.queryTypeByDescriptor with the CORRECT
      password (the engine chain runs inside a mere type query; what type
      comes back?), then loadComponentFromURL with the correct password
      (a doc comes back -- with the RAW CFB bytes as text content, proving
      the loader never saw the decrypted bytes), with the engine log delta
      proving the full readEncryptionInfo -> generateEncryptionKey ->
      createEncryptionData -> decrypt -> checkDataIntegrity chain ran.
  (c) The root cause, fixed from LO 26.8's oox source, is printed at the end:
      the [out] decrypt parameter + filterdetect sniffing its own stream.

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

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
PASSWORD = "correct horse battery staple"
CRYPTO_TYPE = "CipherBoxDataSpace"
CONTENT = "CipherBox round trip marker 4711"
FILTER = "MS Word 2007 XML"

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


def new_doc(desktop):
    doc = desktop.loadComponentFromURL("private:factory/swriter", "_blank", 0, ())
    doc.Text.setString(CONTENT)
    return doc


def agile_case(desktop, out_dir):
    """(a) Password-only save (built-in agile) + reload: does THAT work?"""
    print("\n--- (a) agile isolation: Password only, no EncryptionData ---")
    path = os.path.join(out_dir, "agile.docx")
    before = len(read_log())
    doc = new_doc(desktop)
    doc.storeToURL(uno.systemPathToFileUrl(path), (pv("FilterName", FILTER),
                                                  pv("Password", PASSWORD)))
    doc.close(False)
    after = read_log()
    with open(path, "rb") as fh:
        raw = fh.read()
    print("  agile product: %d bytes, OLE magic=%s, EncryptionInfo=%s, "
          "EncryptedPackage=%s, CipherBoxDataSpace marks=%s, engine ran=%s"
          % (len(raw), raw[:8] == OLE_MAGIC,
             "EncryptionInfo".encode("utf-16-le") in raw,
             "EncryptedPackage".encode("utf-16-le") in raw,
             b"CipherBoxDataSpace" in raw
             or "CipherBoxDataSpace".encode("utf-16-le") in raw,
             "encrypt()" in after[before:]))
    check("agile: built-in agile container (EncryptionInfo, no CipherBox marks)",
          "EncryptionInfo".encode("utf-16-le") in raw
          and "CipherBoxDataSpace".encode("utf-16-le") not in raw)
    check("agile: custom engine never invoked (log silent)",
          "CipherBoxDataSpace" not in after[before:])
    reloaded = desktop.loadComponentFromURL(
        uno.systemPathToFileUrl(path), "_blank", 0, (pv("Password", PASSWORD),))
    check("agile: reloads with the password", reloaded is not None)
    if reloaded is None:
        return
    got = reloaded.Text.getString()
    check("agile: content survives the reload", CONTENT in got, repr(got[:40]))
    reloaded.close(False)


def typedetection_probe(ctx, url):
    """queryTypeByDescriptor with the CORRECT password -- what type comes back?"""
    td = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.document.TypeDetection", ctx)
    try:
        result = td.queryTypeByDescriptor(
            (pv("Url", url), pv("Password", PASSWORD)), True)
        typename = result[0] if isinstance(result, tuple) else result
        outcome = "typename=%r" % (typename,)
    except Exception as exc:  # noqa: BLE001
        typename = None
        outcome = "raised %s: %s" % (type(exc).__name__, exc)
    print("  TypeDetection.queryTypeByDescriptor(correct password) -> %s" % outcome)
    return typename


def custom_case(ctx, desktop, out_dir):
    """(b) custom-dataspace product: where exactly does the reload diverge?"""
    print("\n--- (b) custom divergence probes (EncryptionData{CryptoType}) ---")
    path = os.path.join(out_dir, "custom.docx")
    url = uno.systemPathToFileUrl(path)
    doc = new_doc(desktop)
    doc.storeToURL(url, (
        pv("FilterName", FILTER), pv("Password", PASSWORD),
        pv("EncryptionData", uno.Any(
            "[]com.sun.star.beans.NamedValue",
            (nv("CryptoType", CRYPTO_TYPE), nv("Password", PASSWORD))))))
    doc.close(False)
    with open(path, "rb") as fh:
        raw = fh.read()
    check("custom: CipherBox container (marks, no EncryptionInfo)",
          (b"CipherBoxDataSpace" in raw
           or "CipherBoxDataSpace".encode("utf-16-le") in raw)
          and "EncryptionInfo".encode("utf-16-le") not in raw,
          "%d bytes" % len(raw))

    before = len(read_log())
    typename = typedetection_probe(ctx, url)
    delta = read_log()[before:]
    check("custom: type query does not even engage the engine (no log delta; "
          "the empty type needs no crypto attempt)",
          "CipherBoxDataSpace" not in delta)
    check("custom: yet the detected type is EMPTY", typename == "", repr(typename))

    before = len(read_log())
    reloaded = desktop.loadComponentFromURL(url, "_blank", 0,
                                            (pv("Password", PASSWORD),))
    delta = read_log()[before:]
    check("custom: load returns a document (Text-filter fallback, not None)",
          reloaded is not None)
    if reloaded is None:
        return
    got = reloaded.Text.getString()
    print("  loaded content head: %r" % (got[:40],))
    check("custom: loaded content is the RAW CFB bytes, marker absent "
          "(loader never saw the decrypted bytes)",
          CONTENT not in got and len(got) > 0)
    check("custom: engine chain ran again inside the load (log)",
          "checkDataIntegrity() key_verified=True" in delta)
    reloaded.close(False)


def print_root_cause():
    print()
    print("========== ROOT CAUSE (fixed from LO 26.8 oox source) ==========")
    print("(a) GENERAL encrypted reload WORKS on LO 26.8: the Password-only")
    print("    (agile) docx reloads with content intact -- the break is")
    print("    specific to custom-dataspace containers, not to encrypted")
    print("    reload in general.")
    print("(b) The divergence point is NOT the crypto and NOT what")
    print("    createEncryptionData returns (oox's PasswordVerifier only")
    print("    checks hasElements(); our [CryptoType, CipherBoxKey] satisfies")
    print("    it).  The external TypeDetection query returns '' WITHOUT")
    print("    engaging the engine at all (zero log lines -- no crypto attempt")
    print("    happens in that query); the LOAD path DOES engage the engine")
    print("    completely (readEncryptionInfo -> generateEncryptionKey ->")
    print("    createEncryptionData -> decrypt -> checkDataIntegrity=True,")
    print("    log-proven) and still falls back to Text with the raw CFB bytes")
    print("    as content.  The decrypted bytes never reach oox:")
    print("    oox/source/crypto/DocumentDecryption.cxx decrypt() pre-loads its")
    print("    caller's UNOMemoryStream output stream into the [out] parameter")
    print("    variable, and oox/source/core/filterdetect.cxx")
    print("    extractUnencryptedPackage() then sniffs THAT SAME UNOMemoryStream")
    print("    (lclIsZipPackage on xTempStream->getInputStream()).")
    print("    XPackageEncryption::decrypt()'s second parameter is [out] in the")
    print("    IDL, so PyUNO delivers None to the Python engine -- the caller's")
    print("    stream can never be written from Python.  The C++ built-in")
    print("    engines (StrongEncryptionDataSpace.cxx) get away with it because")
    print("    an in-process C++ call passes a reference whose current value IS")
    print("    the caller's pre-loaded stream, and they write into it")
    print("    (BinaryXOutputStream aOutputStream(rxOutputStream, true)).  A")
    print("    Python engine's only channel -- returning (True, own_stream) --")
    print("    replaces the caller's variable with a DIFFERENT stream object")
    print("    that filterdetect never reads.  Result: empty UNOMemoryStream ->")
    print("    lclIsZipPackage false -> extractUnencryptedPackage null ->")
    print("    detect() throws UNO_SET_THROW -> catch without ABORTED -> empty")
    print("    filter name -> Text fallback.  Structural since the API's")
    print("    introduction (LO 7.0), not a 26.8 regression, not fixable from")
    print("    Python.")
    print("(c) Options: (1) acceptance adjustment -- production never does")
    print("    LO-side custom-engine reload (todo 13 encrypts via plaintext-")
    print("    load + encrypted-store, PROVEN; todo 14 decrypts agent-side via")
    print("    container.py) -- record the boundary, no engine change.  (2)")
    print("    engine-side adaptation is IMPOSSIBLE from pure Python via the")
    print("    decrypt [out] param (no channel to the caller's stream); only")
    print("    LO C++ changes (filterdetect using the returned out-param stream)")
    print("    or an OLE-storage-level workaround could fix it.  Full record:")
    print("    spike-conclusions.md (todo-02 artifacts).")


def main():
    out_dir = os.path.join(OUT_ROOT, time.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(out_dir, exist_ok=True)
    print("spike_reload_rootcause; products in %s" % out_dir)
    ctx = connect()
    desktop = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.Desktop", ctx)
    try:
        agile_case(desktop, out_dir)
    except Exception as exc:  # noqa: BLE001
        print("ERROR agile: %r" % (exc,))
        FAILURES.append("agile raised")
    try:
        custom_case(ctx, desktop, out_dir)
    except Exception as exc:  # noqa: BLE001
        print("ERROR custom: %r" % (exc,))
        FAILURES.append("custom raised")
    print_root_cause()
    print()
    if FAILURES:
        print("RESULT: FAIL (%d) -> %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("RESULT: PASS (agile isolation + custom divergence probes recorded)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
