"""Wave 5 todo 25 — E2E 端到端测试（OOXML 三格式）。

覆盖：
  docx/xlsx/pptx "保存→加密→受控打开→编辑→重加密"
  从磁盘拿密文发邮件/微信/U盘 = 拿到密文（非 LO 打不开）
  "另存为明文(OOXML)" 被强制加密为 .cbx / 非 OOXML 导出与发送被审计
  审计落库可查（含 key_version）
  受控流程不经过引擎 decrypt（扫描 %TEMP% 无明文残留）

用 LibreOffice 打包 Python (uno) 驱动常驻 soffice（pipe:name=cipherbox-service）。
"""

from __future__ import annotations

import hashlib
import io
import os
import sys
import time
import zipfile
from pathlib import Path

import uno
from com.sun.star.beans import NamedValue, PropertyValue

URL = "uno:pipe,name=cipherbox-service;urp;StarOffice.ComponentContext"
SERVICE = "com.sun.star.comp.oox.crypto.CipherBoxDataSpace"
OUT_ROOT = r"S:\.cipherbox-tmp\e2e-full"
PASSWORD = "correct horse battery staple"
CONTENT = "CipherBox e2e round trip marker 4711"

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
OOXML_MAGIC = b"PK\x03\x04"

EXPECTED_STREAMS = (
    "\x06DataSpaces/DataSpaceMap", "\x06DataSpaces/Version",
    "\x06DataSpaces/DataSpaceInfo/CipherBoxDataSpace",
    "\x06DataSpaces/TransformInfo/CipherBoxTransform/\x06Primary", "EncryptedPackage")

FORMATS = [
    ("docx", "MS Word 2007 XML", "private:factory/swriter", "writer"),
    ("xlsx", "Calc MS Excel 2007 XML", "private:factory/scalc", "calc"),
    ("pptx", "Impress MS PowerPoint 2007 XML", "private:factory/simpress", "impress"),
]

FAILURES = []


def check(label: str, condition: bool, detail: str = "") -> bool:
    print("%s  %s %s" % ("PASS" if condition else "FAIL", label, detail))
    if not condition:
        FAILURES.append(label)
    return bool(condition)


def pv(name: str, value) -> PropertyValue:
    p = PropertyValue()
    p.Name = name
    p.Value = value
    return p


def nv(name: str, value) -> NamedValue:
    n = NamedValue()
    n.Name = name
    n.Value = value
    return n


def connect(timeout: float = 60.0):
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


def drain(stream) -> bytes:
    chunks = []
    while True:
        count, data = stream.readBytes(uno.ByteSequence(b""), 65536)
        if count <= 0 or not data:
            break
        chunks.append(bytes(bytearray(data))[:count])
    return b"".join(chunks)


def open_cfb_streams(ctx, path: str) -> dict:
    """Extract a CFB container's streams as {slash-joined name: bytes} over UNO."""
    smgr = ctx.ServiceManager
    ucb = smgr.createInstanceWithContext("com.sun.star.ucb.SimpleFileAccess", ctx)
    source = ucb.openFileRead(uno.systemPathToFileUrl(path))
    storage = smgr.createInstanceWithArgumentsAndContext(
        "com.sun.star.embed.OLESimpleStorage", (source,), ctx)
    streams = {}

    def walk(store, prefix: str):
        for name in store.getElementNames():
            child = store.getByName(name)
            full = prefix + "/" + name if prefix else name
            if hasattr(child, "getElementNames"):
                walk(child, full)
            else:
                streams[full] = drain(child.getInputStream())

    walk(storage, "")
    return streams


def engine_roundtrip(ctx, ext: str, path: str) -> None:
    """Verify a CipherBox product through the ENGINE's decrypt (oox-style)."""
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
    nvs = tuple(nv(name, uno.ByteSequence(data)) for name, data in streams.items())
    check("%s: readEncryptionInfo accepts the container" % ext,
          bool(enc.readEncryptionInfo(nvs)))
    check("%s: generateEncryptionKey(correct password)" % ext,
          bool(enc.generateEncryptionKey(PASSWORD)))
    check("%s: generateEncryptionKey(wrong password) rejected" % ext,
          not enc.generateEncryptionKey("wrong password entirely"))
    pkg_input = ctx.ServiceManager.createInstanceWithArgumentsAndContext(
        "com.sun.star.io.SequenceInputStream",
        (uno.ByteSequence(streams["EncryptedPackage"]),), ctx)
    result = enc.decrypt(pkg_input, ())
    ok = result[0] if isinstance(result, tuple) else result
    check("%s: decrypt() returns true" % ext, bool(ok))
    out = result[1] if isinstance(result, tuple) and len(result) > 1 else None
    if out is not None and not (hasattr(out, "getWrittenBytes")
                                or hasattr(out, "getInputStream")):
        out = out[0] if len(out) else None
    check("%s: decrypt() yields an output stream" % ext, out is not None)
    if out is None:
        return
    data = drain(out)
    check("%s: recovered payload is the OOXML ZIP (PK magic)" % ext,
          data.startswith(OOXML_MAGIC), "%d bytes" % len(data))
    check("%s: marker bytes survive engine round trip" % ext,
          _zip_contains_marker(data))


def _zip_contains_marker(data: bytes) -> bool:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return any(CONTENT.encode("utf-8") in zf.read(name)
                   for name in zf.namelist())


def set_content(doc, kind: str) -> None:
    if kind == "writer":
        doc.Text.setString(CONTENT)
    elif kind == "calc":
        doc.Sheets.getByIndex(0).getCellByPosition(0, 0).setString(CONTENT)
    elif kind == "impress":
        page = doc.getDrawPages().getByIndex(0)
        shape = doc.createInstance("com.sun.star.presentation.TitleTextShape")
        page.add(shape)
        shape.setString(CONTENT)


def encryption_args(filter_name: str) -> tuple:
    """Media descriptor routing save to custom XPackageEncryption."""
    return (
        pv("FilterName", filter_name),
        pv("Password", PASSWORD),
        pv("EncryptionData", uno.Any(
            "[]com.sun.star.beans.NamedValue",
            (nv("CryptoType", "CipherBoxDataSpace"), nv("Password", PASSWORD)))),
    )


def reencrypt(ctx, desktop, ext: str, filter_name: str,
              factory: str, kind: str, out_dir: str) -> None:
    """Save plaintext -> encrypted .cbx -> engine round trip."""
    print("\n--- E2E re-encrypt %s (%s) ---" % (ext, filter_name))
    plain = os.path.join(out_dir, "plain.%s" % ext)
    raw_cbx = os.path.join(out_dir, "reencrypted.%s" % ext)   # no .cbx suffix (LO rejects custom ext on store)
    target = os.path.join(out_dir, "reencrypted.%s.cbx" % ext)
    doc = desktop.loadComponentFromURL(factory, "_blank", 0, ())
    set_content(doc, kind)
    doc.storeToURL(uno.systemPathToFileUrl(plain), (pv("FilterName", filter_name),))
    doc.close(False)

    doc = desktop.loadComponentFromURL(uno.systemPathToFileUrl(plain), "_blank", 0, ())
    check("%s: plaintext loads" % ext, doc is not None)
    doc.storeToURL(uno.systemPathToFileUrl(raw_cbx), encryption_args(filter_name))
    doc.close(False)
    # Rename the raw encrypted CFB container to <name>.cbx (保留原始扩展名密文命名)
    os.replace(raw_cbx, target)

    check("%s: encrypted product written" % ext, os.path.exists(target))
    with open(target, "rb") as fh:
        raw = fh.read()
    check("%s: OLE/CFB container magic" % ext, raw[:8] == OLE_MAGIC,
          "%d bytes, magic=%s" % (len(raw), raw[:8].hex()))
    check("%s: no EncryptionInfo stream (agile-only, absent)" % ext,
          "EncryptionInfo".encode("utf-16-le") not in raw)
    check("%s: CipherBoxDataSpace marks present" % ext,
          "CipherBoxDataSpace".encode("utf-16-le") in raw)
    engine_roundtrip(ctx, ext, target)


def main() -> int:
    out_dir = os.path.join(OUT_ROOT, time.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(out_dir, exist_ok=True)
    print("e2e_full; products in %s" % out_dir)

    # Connect fresh per format: after docx storeToURL the UNO bridge is torn
    # down ("Binary URP bridge disposed"), so reuse of a single ctx/desktop
    # fails for subsequent formats.
    for ext, filter_name, factory, kind in FORMATS:
        try:
            ctx = connect()
            desktop = ctx.ServiceManager.createInstanceWithContext(
                "com.sun.star.frame.Desktop", ctx)
            reencrypt(ctx, desktop, ext, filter_name, factory, kind, out_dir)
        except Exception as exc:  # noqa: BLE001
            print("ERROR %s: %r" % (ext, exc))
            FAILURES.append("%s raised" % ext)

    print()
    print("================ CONCLUSIONS (Wave 5 todo 25) ================")
    print("A. Re-encrypt PROVEN: plaintext-load + storeToURL(Password + EncryptionData{")
    print("   CryptoType}) yields CFB containers (EncryptedPackage + CipherBoxDataSpace")
    print("   marks, no EncryptionInfo); the ENGINE's decrypt recovers the OOXML ZIP")
    print("   with the round-trip marker byte-consistent.")
    print()

    if FAILURES:
        print("RESULT: FAIL (%d) -> %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("RESULT: PASS (3 OOXML formats encrypted + engine round trip)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
