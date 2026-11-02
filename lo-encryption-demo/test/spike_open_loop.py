"""Spike: controlled open closed loop + .cbx association prerequisites (Wave 0 todo 3).

Proves, against a LIVE environment (persistent pipe service + throwaway controlled
GUI instances on a dedicated profile inside the S: volume):

  fixture     : create a marker plaintext docx on the service and encrypt it via
                storeToURL(EncryptionData{CryptoType:"CipherBoxDataSpace", Password})
                -> S:\\.cipherbox-tmp\\spike-todo-03\\fixture\\spike-marker.docx.cbx
  closedloop N: engine-API decrypt() to S:\\.cipherbox-tmp\\<uuid>\\spike-marker.docx
                (NEVER loadComponentFromURL on a .cbx -- structurally broken on
                LO 26.8, see todo-02 conclusions), launch an independent controlled
                GUI soffice (--norestore, controlled profile, own pipe, TMP=TEMP at
                the session dir), load the temp plaintext through OUR controlled
                pipe, hold the returned XModel, attach XCloseListener + XEventListener,
                drive model.close(False) programmatically with a bounded poll (<=2s),
                kill the controlled PIDs, re-encrypt via the service, verify CFB
                magic + engine-decrypt marker survival, delete the temp, assert no
                plaintext residue.
  stateA      : default-profile (employee) LO running -> controlled instance still
                starts/runs independently (both GUI processes coexist).
  stateB      : second controlled launch with the SAME profile -> single-instance
                handover (second launcher exits; only one soffice.bin for that
                profile; the handed document arrives in instance #1).
  stateC      : close ONLY the document window (Start Center stays, process alive)
                -> doc-level close detection fires (notifyClosing) while the
                process keeps running.
  stateD      : Restart Manager enumerability -- ctypes RmStartSession /
                RmRegisterResources / RmGetList.  Self-test first (register a file
                THIS process holds open exclusively -> expect our own PID), then
                LO's temp doc + .~lock.# while a controlled instance holds the doc.
  adversarial : bounded doc-close wait -- a never-closed document must time out
                with a clear error and nothing left hung.
  qafailure   : kill the controlled process mid-session -> residual temp EXISTS ->
                next-run sweep (session-record based) re-encrypts-or-cleans without
                silent loss.

Each phase is a separate bounded invocation (runner lesson: no single command may
exceed 120 s; outputs go straight to files via Start-Process redirection).

Run with the bundled python: C:\\Program Files\\LibreOffice\\program\\python.exe.
"""

import json
import os
import re
import subprocess
import sys
import time
import uuid
import ctypes
from ctypes import wintypes

import uno
import unohelper
from com.sun.star.beans import NamedValue, PropertyValue
from com.sun.star.util import XCloseListener

SERVICE = "com.sun.star.comp.oox.crypto.CipherBoxDataSpace"
SERVICE_URL = "uno:pipe,name=cipherbox-service;urp;StarOffice.ComponentContext"
CONTROLLED_PIPE = "cipherbox-controlled-spike3"
CONTROLLED_URL = ("uno:pipe,name=%s;urp;StarOffice.ComponentContext" % CONTROLLED_PIPE)
CONTROLLED_PROFILE_DIR = r"S:\.cipherbox-profile\controlled"
CONTROLLED_PROFILE_URL = "file:///S:/.cipherbox-profile/controlled"
CONTROLLED_PROFILE_RX = re.compile(r"cipherbox-profile[/\\]controlled")
SERVICE_PROFILE_RX = re.compile(r"cipherbox-profile[/\\]service")

SOFFICE = r"C:\Program Files\LibreOffice\program\soffice.exe"

TMP_ROOT = r"S:\.cipherbox-tmp"
WORK_ROOT = os.path.join(TMP_ROOT, "spike-todo-03")
FIXTURE_DIR = os.path.join(WORK_ROOT, "fixture")
FIXTURE_BASENAME = "spike-marker.docx"
FIXTURE_CBX = os.path.join(FIXTURE_DIR, FIXTURE_BASENAME + ".cbx")
ENGINE_LOG = os.path.join(TMP_ROOT, "service", "cipherbox-encryption.log")
SESSION_STORE = os.path.join(WORK_ROOT, "sessions")

PASSWORD = "correct horse battery staple"
CRYPTO_TYPE = "CipherBoxDataSpace"
MARKER = "CipherBox open-loop marker 4711"
FILTER_DOCX = "MS Word 2007 XML"

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

POLL_INTERVAL = 1.0          # <= 2 s per plan
DOC_CLOSE_TIMEOUT = 30.0     # main loop bound
ADVERSARIAL_TIMEOUT = 8.0    # bounded-wait proof bound
PIPE_READY_TIMEOUT = 45.0

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


# ---------------------------------------------------------------------------
# UNO plumbing (service + controlled)
# ---------------------------------------------------------------------------

def connect(url, timeout=60.0):
    local = uno.getComponentContext()
    resolver = local.ServiceManager.createInstanceWithContext(
        "com.sun.star.bridge.UnoUrlResolver", local)
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            return resolver.resolve(url)
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(1)
    raise RuntimeError("could not connect to %s: %s" % (url, last))


def desktop_of(ctx):
    return ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.Desktop", ctx)


def encryption_args(filter_name=FILTER_DOCX):
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


def read_seekable(stream):
    """Read a TempFile-backed XSeekable+XInputStream (engine decrypt output)."""
    try:
        stream.seek(0)
    except Exception:  # noqa: BLE001
        pass
    try:
        total = int(stream.getLength())
    except Exception:  # noqa: BLE001
        return drain(stream)
    chunks = []
    got = 0
    while got < total:
        want = min(64 * 1024, total - got)
        result = stream.readBytes(uno.ByteSequence(b""), want)
        if not isinstance(result, tuple) or len(result) < 2:
            break
        count = int(result[0])
        data = bytes(bytearray(result[1]))
        if count <= 0 or not data:
            break
        chunks.append(data[:count])
        got += count
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


def engine_decrypt_cbx(ctx, cbx_path, password=PASSWORD):
    """Decrypt a .cbx through the ENGINE API (readEncryptionInfo ->
    generateEncryptionKey -> decrypt); returns the recovered plaintext bytes.

    NEVER loadComponentFromURL on a .cbx: custom-dataspace reload is structurally
    broken on LO 26.8 (todo-02 root cause)."""
    streams = open_cfb_streams(ctx, cbx_path)
    if "EncryptedPackage" not in streams:
        raise RuntimeError("no EncryptedPackage stream in %s" % cbx_path)
    obj = ctx.ServiceManager.createInstanceWithContext(SERVICE, ctx)
    enc = obj.queryInterface(
        uno.getTypeByName("com.sun.star.packages.XPackageEncryption"))
    if enc is None:
        raise RuntimeError("engine does not expose XPackageEncryption")
    nvs = tuple(nv(name, uno.ByteSequence(data))
                for name, data in streams.items())
    if not enc.readEncryptionInfo(nvs):
        raise RuntimeError("readEncryptionInfo rejected %s" % cbx_path)
    if not enc.generateEncryptionKey(password):
        raise RuntimeError("generateEncryptionKey rejected the password")
    pkg_input = ctx.ServiceManager.createInstanceWithArgumentsAndContext(
        "com.sun.star.io.SequenceInputStream",
        (uno.ByteSequence(streams["EncryptedPackage"]),), ctx)
    result = enc.decrypt(pkg_input, ())
    ok = result[0] if isinstance(result, tuple) else result
    out = result[1] if isinstance(result, tuple) and len(result) > 1 else None
    if not ok or out is None:
        raise RuntimeError("engine decrypt() failed")
    return read_seekable(out)


def zip_contains_marker(data, marker=MARKER):
    """OOXML stores content DEFLATED -- scan entries decompressed."""
    import io
    import zipfile
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return any(marker.encode("utf-8") in zf.read(name)
                   for name in zf.namelist())


def engine_log_len():
    try:
        return os.path.getsize(ENGINE_LOG)
    except OSError:
        return 0


def engine_log_tail(offset):
    try:
        with open(ENGINE_LOG, "r", errors="replace") as fh:
            fh.seek(offset)
            return fh.read()
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Process management (controlled GUI instances ONLY -- never the service)
# ---------------------------------------------------------------------------

def soffice_processes():
    """Return [(pid, name, commandline)] for every soffice.exe/soffice.bin."""
    out = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "Get-CimInstance Win32_Process -Filter \"Name='soffice.exe' OR Name='soffice.bin'\""
         " | ForEach-Object { '{0}|{1}|{2}' -f $_.ProcessId, $_.Name, $_.CommandLine }"],
        capture_output=True, text=True, timeout=30).stdout
    procs = []
    for line in out.splitlines():
        line = line.strip()
        if "|" not in line:
            continue
        pid, name, cmd = line.split("|", 2)
        try:
            procs.append((int(pid), name, cmd))
        except ValueError:
            continue
    return procs


def controlled_pids():
    return sorted(pid for pid, _name, cmd in soffice_processes()
                  if CONTROLLED_PROFILE_RX.search(cmd))


def employee_pids():
    return sorted(pid for pid, _name, cmd in soffice_processes()
                  if not CONTROLLED_PROFILE_RX.search(cmd)
                  and not SERVICE_PROFILE_RX.search(cmd))


def service_pids():
    return sorted(pid for pid, _name, cmd in soffice_processes()
                  if SERVICE_PROFILE_RX.search(cmd))


def pid_alive(pid):
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "if (Get-Process -Id %d -ErrorAction SilentlyContinue) { 'ALIVE' } else { 'GONE' }" % pid],
            capture_output=True, text=True, timeout=15).stdout.strip()
        return out == "ALIVE"
    except Exception:  # noqa: BLE001
        return False


def kill_pid(pid):
    subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                   capture_output=True, timeout=15)
    deadline = time.time() + 15
    while time.time() < deadline and pid_alive(pid):
        time.sleep(0.5)
    return not pid_alive(pid)


def launch_controlled(session_dir, extra_args=(), pipe=CONTROLLED_PIPE):
    """Launch an independent controlled GUI soffice; returns the launcher Popen."""
    env = dict(os.environ)
    env["TMP"] = session_dir
    env["TEMP"] = session_dir
    args = [
        SOFFICE,
        "--norestore",
        "-env:UserInstallation=" + CONTROLLED_PROFILE_URL,
        '--accept=pipe,name=%s;urp;' % pipe,
    ] + list(extra_args)
    proc = subprocess.Popen(args, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return proc


def wait_controlled_pipe(url=CONTROLLED_URL, timeout=PIPE_READY_TIMEOUT):
    """Bounded pipe-readiness poll; returns the remote context."""
    return connect(url, timeout=timeout)


# ---------------------------------------------------------------------------
# Document close detection (XCloseListener + XEventListener)
# ---------------------------------------------------------------------------

class DocCloseListener(unohelper.Base, XCloseListener):
    """notifyClosing (doc actually closing) + disposing (object gone)."""

    def __init__(self):
        self.closed = False
        self.disposed = False
        self.events = []

    def queryClosing(self, event, gets_ownership):
        pass

    def notifyClosing(self, event):
        self.closed = True
        self.events.append("notifyClosing")

    def disposing(self, event):
        self.disposed = True
        self.events.append("disposing")


def wait_doc_close(listener, timeout=DOC_CLOSE_TIMEOUT):
    """Bounded poll for the doc-close event (<=2 s interval per plan)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if listener.closed or listener.disposed:
            return True, time.time() - (deadline - timeout)
        time.sleep(min(POLL_INTERVAL, max(0.05, deadline - time.time())))
    raise TimeoutError(
        "doc-close event did not arrive within %.1f s (bounded poll, interval %.1f s)"
        % (timeout, POLL_INTERVAL))


def _component_url(comp):
    try:
        return comp.getURL() or ""
    except Exception:  # noqa: BLE001
        return ""


def wait_start_center(desktop, timeout=30.0):
    """Bounded poll for the Start Center frame (the URL-less component).

    Without it, closing the only document quits the whole application and the
    bridge dies mid-close (observed in cycle 1) -- the agent must wait for it."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        enum = desktop.Components.createEnumeration()
        while enum.hasMoreElements():
            if _component_url(enum.nextElement()) == "":
                return True
        time.sleep(POLL_INTERVAL)
    return False


def wait_controller(model, timeout=10.0):
    """Bounded poll for the document controller (close vetoes while it is not up)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if model.getCurrentController() is not None:
                return True
        except Exception:  # noqa: BLE001
            pass
        time.sleep(0.5)
    return False


def close_doc_bounded(model, listener, timeout=DOC_CLOSE_TIMEOUT):
    """Drive model.close(False) programmatically, bounded.

    Retries controller vetoes (CloseVetoException 'Controller disagree' while the
    view is still initializing) and treats a bridge-disposed-during-close as a
    process-exit close.  Returns (status, elapsed):
      'closed-event'    -- XCloseListener/XEventListener fired
      'process-exited'  -- bridge died during close (last doc quit the app)
    """
    started = time.time()
    deadline = started + timeout
    bridge_died = False
    vetoed = 0
    while True:
        try:
            model.close(False)
            break
        except Exception as exc:  # noqa: BLE001
            name = type(exc).__name__
            if "Disposed" in name:
                bridge_died = True
                break
            if "CloseVeto" in name or "disagree" in str(exc):
                vetoed += 1
                if time.time() > deadline:
                    raise TimeoutError(
                        "close vetoed for %.1f s (%d vetoes)" % (timeout, vetoed))
                time.sleep(POLL_INTERVAL)
                continue
            raise
    if vetoed:
        print("  close_doc_bounded: %d controller veto(es) retried" % vetoed)
    if bridge_died:
        print("  close_doc_bounded: bridge disposed during close -> process exited")
        return "process-exited", time.time() - started
    fired, _elapsed = wait_doc_close(listener, timeout=max(0.1, deadline - time.time()))
    if not fired:
        raise TimeoutError("doc-close event missing after clean close()")
    return "closed-event", time.time() - started


# ---------------------------------------------------------------------------
# Re-encrypt + residue checks
# ---------------------------------------------------------------------------

def reencrypt_via_service(svc_ctx, plain_path, cbx_path):
    """Plaintext load on the headless service + encrypted storeToURL."""
    desktop = desktop_of(svc_ctx)
    doc = desktop.loadComponentFromURL(
        uno.systemPathToFileUrl(plain_path), "_blank", 0, ())
    if doc is None:
        raise RuntimeError("service failed to load plaintext %s" % plain_path)
    log_before = engine_log_len()
    doc.storeToURL(uno.systemPathToFileUrl(cbx_path), encryption_args())
    doc.close(False)
    return engine_log_tail(log_before)


def verify_cbx(svc_ctx, cbx_path, expect_marker=True):
    """CFB magic + engine-decrypt marker -- misleading_success_output defense."""
    with open(cbx_path, "rb") as fh:
        raw = fh.read(8)
    if raw != OLE_MAGIC:
        return False, "not a CFB container (magic=%s)" % raw.hex()
    payload = engine_decrypt_cbx(svc_ctx, cbx_path)
    if expect_marker and not zip_contains_marker(payload):
        return False, "engine-decrypted payload lacks the marker"
    return True, payload


def residue_scan(roots, needle):
    """Find any file under roots whose name contains needle."""
    hits = []
    for root in roots:
        for dirpath, _dirs, files in os.walk(root):
            for name in files:
                if needle in name:
                    hits.append(os.path.join(dirpath, name))
    return hits


def _rmtree(path):
    """Remove a whole session dir (temp doc + LO lu*.tmp scratch + locks)."""
    import shutil
    def _onerror(func, p, _exc):
        try:
            os.chmod(p, 0o666)
            func(p)
        except OSError:
            pass
    if os.path.isdir(path):
        shutil.rmtree(path, onerror=_onerror)
    return not os.path.exists(path)


# ---------------------------------------------------------------------------
# Phases
# ---------------------------------------------------------------------------

def phase_fixture():
    os.makedirs(FIXTURE_DIR, exist_ok=True)
    ctx = connect(SERVICE_URL)
    desktop = desktop_of(ctx)
    build = os.path.join(FIXTURE_DIR, "build")
    os.makedirs(build, exist_ok=True)
    plain = os.path.join(build, FIXTURE_BASENAME)

    doc = desktop.loadComponentFromURL("private:factory/swriter", "_blank", 0, ())
    doc.Text.setString(MARKER)
    doc.storeToURL(uno.systemPathToFileUrl(plain), (pv("FilterName", FILTER_DOCX),))
    doc.close(False)
    check("fixture: marker plaintext docx written", os.path.exists(plain))

    log_before = engine_log_len()
    doc = desktop.loadComponentFromURL(
        uno.systemPathToFileUrl(plain), "_blank", 0, ())
    check("fixture: plaintext reloads on service", doc is not None)
    doc.storeToURL(uno.systemPathToFileUrl(FIXTURE_CBX), encryption_args())
    doc.close(False)
    tail = engine_log_tail(log_before)

    check("fixture: .cbx written", os.path.exists(FIXTURE_CBX), FIXTURE_CBX)
    with open(FIXTURE_CBX, "rb") as fh:
        raw = fh.read()
    check("fixture: OLE/CFB magic", raw[:8] == OLE_MAGIC, raw[:8].hex())
    check("fixture: EncryptedPackage mark",
          "EncryptedPackage".encode("utf-16-le") in raw)
    check("fixture: no EncryptionInfo stream (agile-only)",
          "EncryptionInfo".encode("utf-16-le") not in raw)
    check("fixture: engine encrypt() ran on save", "encrypt()" in tail)

    payload = engine_decrypt_cbx(ctx, FIXTURE_CBX)
    check("fixture: engine decrypt() round trip returns PK payload",
          payload.startswith(b"PK\x03\x04"), "%d bytes" % len(payload))
    check("fixture: marker survives engine decrypt", zip_contains_marker(payload))

    for name in os.listdir(build):
        os.remove(os.path.join(build, name))
    os.rmdir(build)
    check("fixture: build plaintext removed", not os.path.exists(plain))
    return not FAILURES


def _decrypt_to_session(svc_ctx, session_dir):
    """Engine-API decrypt of the fixture into the session dir; returns tmp path."""
    tmp_path = os.path.join(session_dir, FIXTURE_BASENAME)
    payload = engine_decrypt_cbx(svc_ctx, FIXTURE_CBX)
    with open(tmp_path, "wb") as fh:
        fh.write(payload)
    return tmp_path, payload


def _open_doc(ctrl_url, tmp_path):
    """Connect to the controlled pipe, wait for the Start Center (else closing
    the only doc quits the app), load the doc, wait for its controller, attach
    listeners.  Returns (ctx, model, listener)."""
    ctx = wait_controlled_pipe(ctrl_url)
    desktop = desktop_of(ctx)
    if not wait_start_center(desktop, timeout=30.0):
        raise RuntimeError("Start Center frame never appeared (bounded 30 s)")
    model = desktop.loadComponentFromURL(
        uno.systemPathToFileUrl(tmp_path), "_blank", 0, ())
    if model is None:
        raise RuntimeError("controlled instance returned no model")
    wait_controller(model, timeout=10.0)
    time.sleep(1)  # let the view finish initializing (close-veto window)
    listener = DocCloseListener()
    model.addCloseListener(listener)
    return ctx, model, listener


def _open_and_close_doc(ctrl_url, tmp_path, close_timeout=DOC_CLOSE_TIMEOUT,
                        close=True):
    """Full open+close cycle.  With close=False the doc is left open."""
    ctx, model, listener = _open_doc(ctrl_url, tmp_path)
    if not close:
        return ctx, model, listener, None
    status, elapsed = close_doc_bounded(model, listener, timeout=close_timeout)
    print("  close status=%s elapsed=%.2fs events=%s"
          % (status, elapsed, listener.events))
    return ctx, model, listener, elapsed


def _residue_assertions(session_dir, tag):
    lock_hits = residue_scan([session_dir], ".~lock.")
    plain_hits = residue_scan([session_dir], FIXTURE_BASENAME)
    check("%s: session dir fully clean (no plaintext, no lock)" % tag,
          not lock_hits and not plain_hits,
          "leftovers=%s" % (lock_hits + plain_hits))
    if os.path.isdir(session_dir):
        check("%s: session dir removed" % tag, False,
              "still present: %s" % session_dir)
    profile_hits = residue_scan([CONTROLLED_PROFILE_DIR], FIXTURE_BASENAME) \
        if os.path.isdir(CONTROLLED_PROFILE_DIR) else []
    check("%s: no plaintext copy under controlled profile (backup/autorecovery)" % tag,
          not profile_hits, "hits=%s" % profile_hits)


def phase_closedloop(cycle):
    session_dir = os.path.join(TMP_ROOT, str(uuid.uuid4()))
    os.makedirs(session_dir)
    tag = "closedloop(cycle %s)" % cycle
    print("%s: session dir %s" % (tag, session_dir))
    svc_ctx = connect(SERVICE_URL)
    baseline_pids = set(controlled_pids())
    launcher = None
    try:
        tmp_path, payload = _decrypt_to_session(svc_ctx, session_dir)
        import hashlib
        orig_sha = hashlib.sha256(payload).hexdigest()
        check("%s: engine-API decrypt to temp plaintext" % tag,
              os.path.exists(tmp_path) and payload.startswith(b"PK\x03\x04"),
              "%d bytes sha256=%s" % (len(payload), orig_sha[:12]))

        launcher = launch_controlled(session_dir)
        ctrl = None
        listener = None
        elapsed = None
        try:
            ctrl, _model, listener, elapsed = _open_and_close_doc(
                CONTROLLED_URL, tmp_path)
        finally:
            pids = [p for p in controlled_pids() if p not in baseline_pids]
            print("%s: controlled PIDs to terminate: %s" % (tag, pids))
            for pid in pids:
                check("%s: controlled PID %d terminated" % (tag, pid),
                      kill_pid(pid))
        check("%s: doc-close event fired (XCloseListener/XEventListener)" % tag,
              listener is not None and (listener.closed or listener.disposed),
              "events=%s elapsed=%.2fs" % (listener.events if listener else None,
                                           elapsed or -1))
        check("%s: close wait was bounded (<=%.0fs)" % (tag, DOC_CLOSE_TIMEOUT),
              elapsed is not None and elapsed <= DOC_CLOSE_TIMEOUT)

        log_before = engine_log_len()
        reencrypt_via_service(svc_ctx, tmp_path, FIXTURE_CBX)
        tail = engine_log_tail(log_before)
        check("%s: engine encrypt() ran on re-encrypt" % tag, "encrypt()" in tail)
        ok, new_payload = verify_cbx(svc_ctx, FIXTURE_CBX)
        check("%s: re-encrypted .cbx = CFB + engine-decrypt marker" % tag, ok)
        # LO re-saves regenerate the ZIP (entry timestamps), so byte-identity is
        # NOT expected; the honest check is PK magic + marker survival.
        check("%s: re-encrypted payload is an OOXML ZIP with the marker" % tag,
              new_payload.startswith(b"PK\x03\x04") and zip_contains_marker(new_payload),
              "%d bytes (orig %d, sha %s)" % (len(new_payload), len(payload),
                                              orig_sha[:12]))

        os.remove(tmp_path)
        _rmtree(session_dir)
        _residue_assertions(session_dir, tag)
    finally:
        # Safety net: never leave a controlled instance behind.
        for pid in [p for p in controlled_pids() if p not in baseline_pids]:
            kill_pid(pid)
        if launcher is not None and launcher.poll() is None:
            try:
                launcher.terminate()
            except Exception:  # noqa: BLE001
                pass
    return not FAILURES


def phase_state_a():
    """Employee default-profile LO running -> controlled instance independent."""
    tag = "stateA"
    pre_employee = set(employee_pids())
    pre_controlled = set(controlled_pids())
    env = dict(os.environ)
    session_dir = os.path.join(TMP_ROOT, str(uuid.uuid4()))
    os.makedirs(session_dir)
    env["TMP"] = session_dir
    env["TEMP"] = session_dir
    employee = subprocess.Popen(
        [SOFFICE, "--norestore"], env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("%s: employee LO launcher PID %d (default profile)" % (tag, employee.pid))
    try:
        deadline = time.time() + 45
        new_employee = set()
        while time.time() < deadline:
            new_employee = set(employee_pids()) - pre_employee
            if new_employee:
                break
            time.sleep(1)
        check("%s: employee default-profile LO running" % tag,
              bool(new_employee), "pids=%s" % sorted(new_employee))

        launcher = launch_controlled(session_dir)
        try:
            deadline = time.time() + 45
            new_controlled = set()
            while time.time() < deadline:
                new_controlled = set(controlled_pids()) - pre_controlled
                if new_controlled:
                    break
                time.sleep(1)
            check("%s: controlled instance started alongside employee LO" % tag,
                  bool(new_controlled), "pids=%s" % sorted(new_controlled))
            ctx = wait_controlled_pipe(CONTROLLED_URL, timeout=45)
            check("%s: controlled pipe resolves while employee LO runs" % tag,
                  ctx is not None)
            still = set(employee_pids()) & new_employee
            check("%s: employee LO still alive (independent of controlled)" % tag,
                  bool(still), "pids=%s" % sorted(still))
            check("%s: shared service untouched" % tag,
                  bool(service_pids()), "pids=%s" % service_pids())
        finally:
            for pid in set(controlled_pids()) - pre_controlled:
                kill_pid(pid)
            if launcher.poll() is None:
                try:
                    launcher.terminate()
                except Exception:  # noqa: BLE001
                    pass
    finally:
        for pid in set(employee_pids()) - pre_employee:
            print("%s: closing employee PID %d" % (tag, pid))
            kill_pid(pid)
        if employee.poll() is None:
            try:
                employee.terminate()
            except Exception:  # noqa: BLE001
                pass
        _rmtree(session_dir)
    check("%s: no controlled/employee residue" % tag,
          not (set(controlled_pids()) - pre_controlled)
          and not (set(employee_pids()) - pre_employee))
    return not FAILURES


def phase_state_b():
    """Second controlled launch with the SAME profile -> single-instance handover."""
    tag = "stateB"
    session_dir = os.path.join(TMP_ROOT, str(uuid.uuid4()))
    os.makedirs(session_dir)
    pre = set(controlled_pids())
    first = launch_controlled(session_dir)
    try:
        ctx = wait_controlled_pipe(CONTROLLED_URL, timeout=45)
        first_pids = set(controlled_pids()) - pre
        check("%s: first controlled instance up" % tag, bool(first_pids),
              "pids=%s" % sorted(first_pids))
        first_bins = len(first_pids)

        def doc_count():
            comps = desktop_of(ctx).Components.createEnumeration()
            count = 0
            while comps.hasMoreElements():
                comps.nextElement()
                count += 1
            return count

        before_docs = doc_count()
        print("%s: docs open in instance #1 before handover: %d" % (tag, before_docs))

        # Second launch, SAME profile: hand it a document; single-instance must
        # delegate to instance #1 and exit.
        tmp_path, _payload = _decrypt_to_session(connect(SERVICE_URL), session_dir)
        second = launch_controlled(session_dir, extra_args=[tmp_path])
        exited = False
        deadline = time.time() + 30
        while time.time() < deadline:
            if second.poll() is not None:
                exited = True
                break
            time.sleep(1)
        check("%s: second launcher exited (delegated)" % tag, exited,
              "exit code=%s" % (second.returncode if exited else "still running"))
        # Poll for the handed document to land in instance #1 (bounded).
        after_docs = before_docs
        deadline = time.time() + 20
        while time.time() < deadline:
            after_docs = doc_count()
            if after_docs > before_docs:
                break
            time.sleep(1)
        after_pids = set(controlled_pids()) - pre
        check("%s: still exactly one soffice.bin set for the controlled profile" % tag,
              len(after_pids) == first_bins,
              "before=%s after=%s" % (sorted(first_pids), sorted(after_pids)))
        check("%s: handed document arrived in instance #1 (single-instance handover)" % tag,
              after_docs > before_docs, "docs %d -> %d" % (before_docs, after_docs))
        print("%s: VERDICT single-instance handover CONFIRMED -> agent must serialize"
              % tag)
    finally:
        for pid in set(controlled_pids()) - pre:
            kill_pid(pid)
        _rmtree(session_dir)
        if first.poll() is None:
            try:
                first.terminate()
            except Exception:  # noqa: BLE001
                pass
    return not FAILURES


def phase_state_c():
    """Close ONLY the document window; Start Center stays; doc-level detection fires."""
    tag = "stateC"
    session_dir = os.path.join(TMP_ROOT, str(uuid.uuid4()))
    os.makedirs(session_dir)
    pre = set(controlled_pids())
    launcher = launch_controlled(session_dir)
    try:
        svc_ctx = connect(SERVICE_URL)
        tmp_path, _payload = _decrypt_to_session(svc_ctx, session_dir)
        ctx, _model, listener, elapsed = _open_and_close_doc(
            CONTROLLED_URL, tmp_path)
        check("%s: doc-level close detection fired on doc-window close" % tag,
              listener.closed or listener.disposed,
              "events=%s elapsed=%.2fs" % (listener.events, elapsed))
        alive = [p for p in (set(controlled_pids()) - pre) if pid_alive(p)]
        check("%s: Start Center STAYS: controlled process alive after doc close" % tag,
              bool(alive), "alive pids=%s" % alive)
        try:
            desktop_of(ctx).Components.createEnumeration()
            check("%s: controlled pipe still answers (Start Center session alive)" % tag,
                  True)
        except Exception as exc:  # noqa: BLE001
            check("%s: controlled pipe still answers" % tag, False, repr(exc))
        print("%s: VERDICT doc-close detection = model event, NOT process exit;"
              " process-outlives-document explicitly proven" % tag)
    finally:
        for pid in set(controlled_pids()) - pre:
            kill_pid(pid)
        _rmtree(session_dir)
        if launcher.poll() is None:
            try:
                launcher.terminate()
            except Exception:  # noqa: BLE001
                pass
    return not FAILURES


# -- Restart Manager (state D) -----------------------------------------------

CCH_RM_MAX_APP_NAME = 255
CCH_RM_MAX_SVC_NAME = 63
CCH_RM_SESSION_KEY = 32
ERROR_MORE_DATA = 234


class RM_UNIQUE_PROCESS(ctypes.Structure):
    _fields_ = [("dwProcessId", wintypes.DWORD),
                ("ProcessStartTime", wintypes.FILETIME)]


class RM_PROCESS_INFO(ctypes.Structure):
    _fields_ = [("Process", RM_UNIQUE_PROCESS),
                ("strAppName", wintypes.WCHAR * (CCH_RM_MAX_APP_NAME + 1)),
                ("strServiceShortName", wintypes.WCHAR * (CCH_RM_MAX_SVC_NAME + 1)),
                ("ApplicationType", ctypes.c_int),
                ("AppStatus", wintypes.ULONG),
                ("TSSessionId", wintypes.ULONG),
                ("bRestartable", wintypes.BOOL)]


def rm_list_users(files):
    """RmStartSession -> RmRegisterResources -> RmGetList; returns [(pid, app)]."""
    dll = ctypes.WinDLL("rstrtmgr.dll")
    handle = wintypes.DWORD()
    key = ctypes.create_unicode_buffer(CCH_RM_SESSION_KEY + 1)
    rc = dll.RmStartSession(ctypes.byref(handle), 0, key)
    if rc != 0:
        raise OSError("RmStartSession failed: %d" % rc)
    try:
        arr = (wintypes.LPCWSTR * len(files))(*files)
        rc = dll.RmRegisterResources(handle, len(files), arr, 0, None, 0, None)
        if rc != 0:
            raise OSError("RmRegisterResources failed: %d" % rc)
        needed = wintypes.UINT(0)
        count = wintypes.UINT(0)
        reasons = wintypes.DWORD()
        rc = dll.RmGetList(handle, ctypes.byref(needed), ctypes.byref(count),
                           None, ctypes.byref(reasons))
        if rc == ERROR_MORE_DATA:
            infos = (RM_PROCESS_INFO * needed.value)()
            count = wintypes.UINT(needed.value)
            rc = dll.RmGetList(handle, ctypes.byref(needed), ctypes.byref(count),
                               infos, ctypes.byref(reasons))
        elif rc == 0:
            infos = []
        if rc != 0:
            raise OSError("RmGetList failed: %d" % rc)
        return [(info.Process.dwProcessId, info.strAppName) for info in infos]
    finally:
        dll.RmEndSession(handle)


def rm_self_test():
    """Register a file THIS process holds open exclusively; expect our own PID."""
    tag = "stateD/self-test"
    probe = os.path.join(WORK_ROOT, "rm-selftest.bin")
    os.makedirs(WORK_ROOT, exist_ok=True)
    with open(probe, "wb") as fh:
        fh.write(b"cipherbox rm self test")
    kernel32 = ctypes.WinDLL("kernel32.dll")
    create = kernel32.CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                       wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                       wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    invalid = wintypes.HANDLE(-1).value
    handle = create(probe, 0x80000000 | 0x40000000, 0, None, 3, 0x80, None)
    if handle == invalid or handle is None:
        raise OSError("CreateFileW failed")
    try:
        users = rm_list_users([probe])
        mine = os.getpid()
        check("%s: own process returned by RmGetList" % tag,
              any(pid == mine for pid, _app in users),
              "users=%s own pid=%d" % (users, mine))
    finally:
        kernel32.CloseHandle(handle)
        os.remove(probe)


def phase_state_d():
    tag = "stateD"
    rm_self_test()
    session_dir = os.path.join(TMP_ROOT, str(uuid.uuid4()))
    os.makedirs(session_dir)
    pre = set(controlled_pids())
    launcher = launch_controlled(session_dir)
    try:
        svc_ctx = connect(SERVICE_URL)
        tmp_path, _payload = _decrypt_to_session(svc_ctx, session_dir)
        # Load the doc and KEEP it open.
        ctx, _model, _listener, _ = _open_and_close_doc(
            CONTROLLED_URL, tmp_path, close=False)
        lock = os.path.join(session_dir, ".~lock.%s#" % FIXTURE_BASENAME)
        check("%s: LO lock file present while doc open" % tag,
              os.path.exists(lock), lock)
        time.sleep(2)  # let LO settle its handles

        targets = [tmp_path] + ([lock] if os.path.exists(lock) else [])
        users = rm_list_users(targets)
        ctrl = sorted(set(controlled_pids()) - pre)
        print("%s: RM users of [doc%s] via S: path: %s"
              % (tag, "+lock" if len(targets) > 1 else "", users))
        print("%s: controlled soffice PIDs: %s" % (tag, ctrl))
        lo_hit = any(pid in ctrl for pid, _app in users)
        print("%s: VERDICT active-LO handle enumerable by RM: %s"
              % (tag, "YES" if lo_hit else "NO (0 LO pids returned)"))

        # Cross-check with the resolved (non-subst) path too.
        real = os.path.realpath(tmp_path)
        if real.lower() != tmp_path.lower():
            users_real = rm_list_users([real])
            print("%s: RM users of doc via resolved path %s: %s"
                  % (tag, real, users_real))
        print("%s: todo-12 stale-lock rule: RM returning 0 processes must stay in"
              " the 'cannot determine' branch (never delete an active lock)" % tag)
    finally:
        for pid in set(controlled_pids()) - pre:
            kill_pid(pid)
        _rmtree(session_dir)
        if launcher.poll() is None:
            try:
                launcher.terminate()
            except Exception:  # noqa: BLE001
                pass
    return not FAILURES


def phase_adversarial():
    """A never-closed document must time out with a clear error, nothing hung."""
    tag = "adversarial-hung"
    session_dir = os.path.join(TMP_ROOT, str(uuid.uuid4()))
    os.makedirs(session_dir)
    pre = set(controlled_pids())
    launcher = launch_controlled(session_dir)
    started = time.time()
    try:
        svc_ctx = connect(SERVICE_URL)
        tmp_path, _payload = _decrypt_to_session(svc_ctx, session_dir)
        _ctx, _model, listener, _ = _open_and_close_doc(
            CONTROLLED_URL, tmp_path, close=False)
        timed_out = False
        try:
            wait_doc_close(listener, timeout=ADVERSARIAL_TIMEOUT)
        except TimeoutError as exc:
            timed_out = True
            elapsed = time.time() - started
            print("%s: bounded wait raised cleanly: %s" % (tag, exc))
            print("%s: elapsed %.1f s (bound %.1f s)" % (tag, elapsed, ADVERSARIAL_TIMEOUT))
        check("%s: never-closed doc times out with clear error" % tag, timed_out)
    finally:
        for pid in set(controlled_pids()) - pre:
            kill_pid(pid)
        _rmtree(session_dir)
        if launcher.poll() is None:
            try:
                launcher.terminate()
            except Exception:  # noqa: BLE001
                pass
    leftovers = set(controlled_pids()) - pre
    check("%s: nothing left hung after timeout" % tag, not leftovers,
          "leftovers=%s" % sorted(leftovers))
    return not FAILURES


def phase_qa_failure():
    """Kill the controlled process mid-session -> residual temp; sweep recovers."""
    tag = "qafailure"
    session_id = str(uuid.uuid4())
    session_dir = os.path.join(TMP_ROOT, session_id)
    os.makedirs(session_dir)
    os.makedirs(SESSION_STORE, exist_ok=True)
    pre = set(controlled_pids())
    svc_ctx = connect(SERVICE_URL)
    tmp_path, payload = _decrypt_to_session(svc_ctx, session_dir)
    import hashlib
    record = {
        "session": session_id,
        "cbx_path": FIXTURE_CBX,
        "tmp_path": tmp_path,
        "orig_sha256": hashlib.sha256(payload).hexdigest(),
        "ts": time.time(),
    }
    record_path = os.path.join(SESSION_STORE, session_id + ".json")
    with open(record_path, "w", encoding="ascii") as fh:
        json.dump(record, fh)
    print("%s: session record persisted: %s" % (tag, record_path))

    launcher = launch_controlled(session_dir)
    try:
        _ctx, _model, _listener, _ = _open_and_close_doc(
            CONTROLLED_URL, tmp_path, close=False)
        pids = sorted(set(controlled_pids()) - pre)
        for pid in pids:
            kill_pid(pid)  # QA failure: hard-kill mid-session, doc still open
        gone = all(not pid_alive(pid) for pid in pids)
        check("%s: controlled process killed mid-session" % tag, gone,
              "pids=%s" % pids)
    finally:
        if launcher.poll() is None:
            try:
                launcher.terminate()
            except Exception:  # noqa: BLE001
                pass

    check("%s: residual temp plaintext EXISTS after kill (no silent loss)" % tag,
          os.path.exists(tmp_path), tmp_path)
    lock = os.path.join(session_dir, ".~lock.%s#" % FIXTURE_BASENAME)
    print("%s: stale lock residue after kill: %s (exists=%s)"
          % (tag, lock, os.path.exists(lock)))

    # -- next-run sweep simulation (session-record based re-encrypt-or-clean) --
    print("%s: sweep start" % tag)
    with open(record_path, "r", encoding="ascii") as fh:
        rec = json.load(fh)
    if os.path.exists(rec["tmp_path"]):
        import hashlib
        with open(rec["tmp_path"], "rb") as fh:
            current = hashlib.sha256(fh.read()).hexdigest()
        check("%s: sweep: residual temp matches session record hash" % tag,
              current == rec["orig_sha256"])
        reencrypt_via_service(svc_ctx, rec["tmp_path"], rec["cbx_path"])
        ok, _payload = verify_cbx(svc_ctx, rec["cbx_path"])
        check("%s: sweep: re-encrypted .cbx verified (CFB + engine marker)" % tag, ok)
        os.remove(rec["tmp_path"])
        for stale in residue_scan([session_dir], ".~lock."):
            print("%s: sweep: removing stale lock %s" % (tag, stale))
            os.remove(stale)
    _rmtree(session_dir)
    os.remove(record_path)
    check("%s: sweep: session dir + record cleaned" % tag,
          not os.path.exists(session_dir) and not os.path.exists(record_path))
    check("%s: sweep: no plaintext residue anywhere under session scope" % tag,
          not residue_scan([TMP_ROOT], session_id))
    return not FAILURES


PHASES = {
    "fixture": phase_fixture,
    "closedloop": phase_closedloop,
    "stateA": phase_state_a,
    "stateB": phase_state_b,
    "stateC": phase_state_c,
    "stateD": phase_state_d,
    "adversarial": phase_adversarial,
    "qafailure": phase_qa_failure,
}


def main(argv):
    if len(argv) < 2 or argv[1] not in PHASES:
        print("usage: spike_open_loop.py <%s> [cycle]" % "|".join(PHASES))
        return 2
    name = argv[1]
    print("spike_open_loop phase=%s pid=%d time=%s"
          % (name, os.getpid(), time.strftime("%Y-%m-%d %H:%M:%S")))
    print("service pids (must stay untouched): %s" % service_pids())
    started = time.time()
    try:
        if name == "closedloop":
            ok = phase_closedloop(argv[2] if len(argv) > 2 else "1")
        else:
            ok = PHASES[name]()
    except Exception as exc:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        check("phase raised", False, repr(exc))
        ok = False
    print("service pids at end (must equal start): %s" % service_pids())
    print("elapsed %.1f s" % (time.time() - started))
    if not ok or FAILURES:
        print("RESULT: FAIL (%d) -> %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    print("RESULT: PASS (%s)" % name)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
