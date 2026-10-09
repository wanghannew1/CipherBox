"""Validate the encrypted artifact itself, bypassing the oox load path.

Findings so far: for a file saved with Password="VelvetSweatshop" the custom engine now
decrypts cleanly (declared length == recovered length), yet loadComponentFromURL() returns
the same odd text for both a successful and a failed decrypt.  So either

  (a) my save/encrypt path produces a payload that is not the original .docx, or
  (b) the crypto is right and the problem is in how oox consumes the returned stream.

This test settles it: read EncryptedPackage straight out of the OLE container via the UNO
StorageFactory, decrypt it offline with the documented key derivation, and check whether the
plaintext is a real ZIP containing the marker.  No filter, no document model, no guessing.
"""

import os
import sys
import zipfile

sys.path.insert(0, r"C:\code\cipherbox\lo-encryption-demo\src")

import uno  # noqa: E402
from com.sun.star.beans import NamedValue, PropertyValue  # noqa: E402

URL = "uno:socket,host=127.0.0.1,port=2002;urp;StarOffice.ComponentContext"
CRYPTO_TYPE = "CipherBoxDataSpace"
OUT = os.path.join(os.environ.get("TEMP", "."), "cipherbox-ctrl")
PW = "VelvetSweatshop"
MARKER = "DEFAULTPWMARKER"


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
    doc.Text.setString(MARKER)
    enc = uno.Any("[]com.sun.star.beans.NamedValue",
                  (nv("CryptoType", CRYPTO_TYPE), nv("Password", password)))
    doc.storeToURL(uno.systemPathToFileUrl(path),
                   (pv("FilterName", "MS Word 2007 XML"), pv("Password", password),
                    pv("EncryptionData", enc)))
    doc.close(False)
    return path


def read_stream_bytes(stream):
    """Read an XInputStream fully: readBytes(aData, n) -> (nRead, aData)."""
    total = int(stream.getLength())
    out = []
    got = 0
    while got < total:
        want = min(64 * 1024, total - got)
        n, data = stream.readBytes(uno.ByteSequence(b""), want)
        if n <= 0:
            break
        out.append(bytes(bytearray(data))[:n])
        got += n
    return b"".join(out)


def main():
    if not os.path.isdir(OUT):
        os.makedirs(OUT)
    local = uno.getComponentContext()
    resolver = local.ServiceManager.createInstanceWithContext(
        "com.sun.star.bridge.UnoUrlResolver", local)
    ctx = resolver.resolve(URL)
    smgr = ctx.ServiceManager
    desktop = smgr.createInstanceWithContext("com.sun.star.frame.Desktop", ctx)

    path = save_custom(desktop, "artifact.docx", PW)
    print("saved: %s (%d bytes on disk)" % (path, os.path.getsize(path)))

    # Re-open the OLE container and pull EncryptedPackage out by hand.
    sf = smgr.createInstanceWithContext("com.sun.star.embed.StorageFactory", ctx)
    storage = sf.createInstanceWithArguments(
        (pv("URL", uno.systemPathToFileUrl(path)),
         pv("OpenMode", 1),  # ElementModes.READ
         pv("RepairMode", False)))
    sub = storage.openStorageElement("EncryptionInfo", 1)
    streams = list(sub.getElementNames())
    print("EncryptionInfo streams: %s" % (streams,))
    for name in streams:
        el = sub.openStreamElement(name, 1)
        print("  %s -> %d bytes" % (name, el.getInputStream().getLength()))
    sub.close()

    pkg_stream = storage.openStreamElement("EncryptedPackage", 1)
    blob = read_stream_bytes(pkg_stream.getInputStream())
    print("EncryptedPackage: %d bytes" % len(blob))
    print("  header: len=%d iv=%s" % (
        int.from_bytes(blob[0:8], "little", signed=True), blob[8:24].hex()))

    import cipherbox  # the component module, for the documented key derivation
    key = cipherbox.derive_key(PW)
    print("  derive_key(%r)[:8] = %s" % (PW, key[:8].hex()))
    plain = cipherbox.aes_cbc(key, blob[8:24], blob[24:], encrypt=False)
    print("  decrypted %d bytes" % len(plain))
    print("  first 4 bytes: %r (ZIP magic is b'PK\\x03\\x04')" % (plain[:4],))

    if plain[:4] != b"PK\x03\x04":
        print("VERDICT: payload is NOT a ZIP -> save/encrypt path is wrong (case a)")
        return 1
    zpath = path + ".plain.zip"
    with open(zpath, "wb") as handle:
        handle.write(plain)
    with zipfile.ZipFile(zpath) as zf:
        names = zf.namelist()
        print("  zip entries: %d, has document.xml: %s"
              % (len(names), "word/document.xml" in names))
        doc_xml = zf.read("word/document.xml").decode("utf-8", "replace")
    print("  MARKER present in word/document.xml: %s" % (MARKER in doc_xml,))
    print("VERDICT: crypto output is a valid docx ZIP -> case (a) ruled out; "
          "the fault is in the oox load path (case b)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
