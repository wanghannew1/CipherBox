"""Spike: actual LO 26.8 behavior of a wrong-password reload (Wave 0 todo 2 QA).

The plan's QA-failure criterion for todo 2 says "wrong-password reload ->
assert None/rejection".  todo 1's baseline observed a raise ("Unsupported
URL ... type detection aborted"); this spike pins the actual behavior with
per-load child-process isolation: each loadComponentFromURL(wrong password)
runs in a child process (this script re-invoked as `--wrongpw <path>`)
under a hard kill cap, because oox's requestAndVerifyDocPassword proceeds
to an interactive password request after the verifier rejections, and a
blocking call inside the spike's own process would wedge it -- in a child,
a block is a recordable outcome ("HUNG") instead.

Method per format (docx, xlsx): generate a fresh CipherBox product
(factory -> marker -> storeToURL with Password + EncryptionData{CryptoType}),
byte-check it is a real CipherBox CFB container, then reload it with a wrong
password in the kill-able child; record the child's outcome (raise / None /
hang) plus the engine-side verifier rejection in the component log.

Run with LibreOffice's bundled python against the persistent service (see
../start_soffice.ps1); TMP/TEMP must point at the service temp dir so the
engine component log read here is the one the service writes.
"""

import os
import subprocess
import sys
import time

import uno
from com.sun.star.beans import NamedValue, PropertyValue

URL = "uno:pipe,name=cipherbox-service;urp;StarOffice.ComponentContext"
OUT_ROOT = r"S:\.cipherbox-tmp\spike-todo-02"
COMPONENT_LOG = os.path.join(os.environ.get("TEMP", "."), "cipherbox-encryption.log")

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
PASSWORD = "correct horse battery staple"
WRONG_PASSWORD = "wrong password entirely"
CRYPTO_TYPE = "CipherBoxDataSpace"
CONTENT = "CipherBox round trip marker 4711"
KILL_CAP_SEC = 20

FORMATS = [
    ("docx", "MS Word 2007 XML", "private:factory/swriter", "writer"),
    ("xlsx", "Calc MS Excel 2007 XML", "private:factory/scalc", "calc"),
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


def encryption_args(filter_name):
    return (
        pv("FilterName", filter_name),
        pv("Password", PASSWORD),
        pv("EncryptionData", uno.Any(
            "[]com.sun.star.beans.NamedValue",
            (nv("CryptoType", CRYPTO_TYPE), nv("Password", PASSWORD)))),
    )


def bundled_python_exe():
    """The spawnable bundled python.

    Inside LibreOffice's bundled python, sys.executable points at the
    python-core-<version> DIRECTORY (e.g. .../program/python-core-3.13.15),
    not at an executable -- CreateProcess on it fails with WinError 5.  The
    spawnable launcher is python.exe in the program directory next to it.
    """
    if os.path.isfile(sys.executable) and sys.executable.lower().endswith(".exe"):
        return sys.executable
    return os.path.join(os.path.dirname(sys.executable), "python.exe")


def wrongpw_child(target):
    """Child mode: one wrong-password load, then print the outcome and exit."""
    ctx = connect()
    desktop = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.Desktop", ctx)
    outcome = "loaded a document (NOT rejected!)"
    try:
        doc = desktop.loadComponentFromURL(
            uno.systemPathToFileUrl(target), "_blank", 0,
            (pv("Password", WRONG_PASSWORD),))
        if doc is None:
            outcome = "returned None"
        else:
            doc.close(False)
    except Exception as exc:  # noqa: BLE001
        outcome = "raised %s: %s" % (type(exc).__name__, exc)
    print("WRONGPW_OUTCOME: %s" % outcome)
    return 0


def child_wrongpw(target):
    """Spawn the child and enforce the kill cap; return (output, hung)."""
    try:
        proc = subprocess.run(
            [bundled_python_exe(), __file__, "--wrongpw", target],
            capture_output=True, text=True, timeout=KILL_CAP_SEC)
        return proc.stdout + proc.stderr, False
    except subprocess.TimeoutExpired as exc:
        return (exc.stdout or "") + (exc.stderr or ""), True


def wrong_password_case(desktop, ext, filter_name, factory, kind, out_dir):
    print("\n--- C. wrong-password reload %s (isolated child, %ds kill cap) ---" % (
        ext, KILL_CAP_SEC))
    target = os.path.join(out_dir, "wrongpw.%s" % ext)
    doc = desktop.loadComponentFromURL(factory, "_blank", 0, ())
    set_content(doc, kind)
    doc.storeToURL(uno.systemPathToFileUrl(target), encryption_args(filter_name))
    doc.close(False)
    if not check("%s: CipherBox product written" % ext, os.path.exists(target)):
        return
    with open(target, "rb") as fh:
        raw = fh.read()
    check("%s: product is a CipherBox CFB container" % ext,
          raw[:8] == OLE_MAGIC
          and "EncryptedPackage".encode("utf-16-le") in raw
          and (b"CipherBoxDataSpace" in raw
               or "CipherBoxDataSpace".encode("utf-16-le") in raw),
          "%d bytes" % len(raw))

    before = len(read_log())
    output, hung = child_wrongpw(target)
    after = read_log()
    outcome = "HUNG (no return within %ds; child killed)" % KILL_CAP_SEC
    for line in output.splitlines():
        if line.startswith("WRONGPW_OUTCOME:"):
            outcome = line[len("WRONGPW_OUTCOME:"):].strip()
    print("  %s: loadComponentFromURL(wrong password) -> %s" % (ext, outcome))
    check("%s: wrong password does not open the document" % ext,
          hung or outcome.startswith("raised") or outcome == "returned None",
          outcome[:100])
    check("%s: engine verifier rejected the wrong password (log)" % ext,
          "verifier mismatch -> rejecting password" in after[before:])


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--wrongpw":
        return wrongpw_child(sys.argv[2])
    out_dir = os.path.join(OUT_ROOT, time.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(out_dir, exist_ok=True)
    print("spike_wrongpassword; products in %s" % out_dir)
    ctx = connect()
    desktop = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.Desktop", ctx)
    for ext, filter_name, factory, kind in FORMATS:
        try:
            wrong_password_case(desktop, ext, filter_name, factory, kind, out_dir)
        except Exception as exc:  # noqa: BLE001
            print("ERROR %s: %r" % (ext, exc))
            FAILURES.append("%s raised" % ext)
    print()
    print("CONCLUSION: wrong-password reload never opens the document; the actual")
    print("form recorded above per format (raise / None / hang), with the engine-")
    print("side verifier rejecting the wrong password first (log-proven). Plan QA")
    print("wording: assert not-opened; the observed form on this build feeds the")
    print("plan's QA wording (full record: spike-conclusions.md, todo-02 artifacts).")
    print()
    if FAILURES:
        print("RESULT: FAIL (%d) -> %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("RESULT: PASS (wrong-password reload recorded for docx + xlsx)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
