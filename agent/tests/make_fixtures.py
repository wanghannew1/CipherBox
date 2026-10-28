"""Generate the ground-truth fixtures for test_container.py.

Copies a real .cbx product from the Wave-0 todo-2 spike and records the ENGINE's own
decrypt of its EncryptedPackage (over the live UNO pipe service) as the byte-exact
ground truth.  test_container.py then asserts agent/container.py recovers exactly these
bytes -- fully offline, without needing LibreOffice.

Run with the LibreOffice bundled python while the pipe service is up:

    "C:\\Program Files\\LibreOffice\\program\\python.exe" agent/tests/make_fixtures.py
"""

import os
import shutil
import sys
import time

import uno

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")

URL = "uno:pipe,name=cipherbox-service;urp;StarOffice.ComponentContext"
SERVICE = "com.sun.star.comp.oox.crypto.CipherBoxDataSpace"
PASSWORD = "correct horse battery staple"

SPIKE_PRODUCT = r"S:\.cipherbox-tmp\spike-todo-02\20261028-090654\reencrypted.docx"
FIXTURE_CBX = os.path.join(FIXTURES, "reencrypted.docx.cbx")
FIXTURE_PLAIN = os.path.join(FIXTURES, "reencrypted.docx.plain")

STREAM_DATASPACEINFO = "\x06DataSpaces/DataSpaceInfo/CipherBoxDataSpace"
STREAM_ENCRYPTEDPACKAGE = "EncryptedPackage"


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


def as_bytes(value):
    if isinstance(value, bytes):
        return value
    return bytes(bytearray(value))


def nv(name, value):
    n = uno.createUnoStruct("com.sun.star.beans.NamedValue")
    n.Name = name
    n.Value = value
    return n


def drain(stream):
    chunks = []
    while True:
        count, data = stream.readBytes(uno.ByteSequence(b""), 65536)
        if count <= 0 or not data:
            break
        chunks.append(bytes(bytearray(data))[:count])
    return b"".join(chunks)


def read_seekable(stream):
    try:
        stream.seek(0)
        total = int(stream.getLength())
    except Exception:  # noqa: BLE001
        return drain(stream)
    chunks, got = [], 0
    while got < total:
        want = min(64 * 1024, total - got)
        count, data = stream.readBytes(uno.ByteSequence(b""), want)
        if count <= 0 or not data:
            break
        chunks.append(bytes(bytearray(data))[:count])
        got += count
    return b"".join(chunks)


def open_cfb_streams(ctx, path):
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


def main():
    if not os.path.isfile(SPIKE_PRODUCT):
        print("RESULT: FAIL spike product missing: %s" % SPIKE_PRODUCT)
        return 1
    os.makedirs(FIXTURES, exist_ok=True)
    ctx = connect()
    streams = open_cfb_streams(ctx, SPIKE_PRODUCT)
    payload = streams.get(STREAM_ENCRYPTEDPACKAGE)
    dsi = streams.get(STREAM_DATASPACEINFO)
    if payload is None or dsi is None:
        print("RESULT: FAIL product lacks EncryptedPackage/DataSpaceInfo")
        return 1

    # Ground truth: the ENGINE's own decrypt, driven oox-style over UNO.
    enc = ctx.ServiceManager.createInstanceWithContext(SERVICE, ctx).queryInterface(
        uno.getTypeByName("com.sun.star.packages.XPackageEncryption"))
    nvs = tuple(nv(name, uno.ByteSequence(data)) for name, data in streams.items())
    if not enc.readEncryptionInfo(nvs):
        print("RESULT: FAIL readEncryptionInfo")
        return 1
    if not enc.generateEncryptionKey(PASSWORD):
        print("RESULT: FAIL generateEncryptionKey")
        return 1
    pkg_input = ctx.ServiceManager.createInstanceWithArgumentsAndContext(
        "com.sun.star.io.SequenceInputStream", (uno.ByteSequence(payload),), ctx)
    result = enc.decrypt(pkg_input, ())
    ok = result[0] if isinstance(result, tuple) else result
    out = result[1] if isinstance(result, tuple) and len(result) > 1 else None
    if not ok or out is None:
        print("RESULT: FAIL engine decrypt")
        return 1
    plain = read_seekable(out)
    if not plain.startswith(b"PK\x03\x04"):
        print("RESULT: FAIL engine decrypt is not an OOXML ZIP")
        return 1

    shutil.copyfile(SPIKE_PRODUCT, FIXTURE_CBX)
    with open(FIXTURE_PLAIN, "wb") as handle:
        handle.write(plain)
    print("fixture .cbx   : %s (%d bytes)" % (FIXTURE_CBX, os.path.getsize(FIXTURE_CBX)))
    print("fixture plain  : %s (%d bytes, PK magic)" % (FIXTURE_PLAIN, len(plain)))
    print("RESULT: PASS fixtures written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
