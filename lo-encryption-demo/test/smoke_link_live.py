"""Live smoke: force_encrypt interceptor + uno_link_worker on a REAL LO instance.

Run ONLY via run_smoke_link.ps1 (bundled LO python, per-phase watchdog,
dedicated headless instance -- pipe cipherbox-smoke6, own temp profile with the
CipherBoxDataSpace engine registered via components.rdb + unorc; BOTH engine
modules deployed).  Fresh instance per phase (stale-state guard); ciphertext is
verified by OLE magic + engine-API decrypt round trip, never by "dispatch
returned".  Hang-risky dispatches are NOT probed here by design: the with-key
dialog SaveAs (picker-bound, P8 lesson) belongs to the GUI smoke on the deploy
env -- the headless value is decision-branch evidence, collected in P4/P5
without any dialog.

Phases (handoff 2026-11-16 priority 1 -- LO live smoke):
  P1 frames   URP bridge frame identity idempotency: repeated Desktop.Frames
              enumeration yields identical client proxies ("is" -- the dedup
              premise of uno_link_worker._register_new_frames) on THIS build.
  P2 saveas   forced .uno:SaveAs (URL arg, .docx target) -> CFB product on
              disk, encrypt audit ok with real content sha256, engine
              encrypt() ran, engine decrypt round trip recovers the marker,
              source plaintext untouched, medium switched.
  P3 ctrls    in-place .uno:Save on the session temp plaintext -> delegated
              UNCHANGED: file stays plaintext ZIP, edit persisted, NO encrypt
              audit, engine did not run (the Ctrl+S corruption fix, real LO).
  P4 dialog   dialog-flow .uno:SaveAs (no URL arg) routes into forced-encrypt
              and FAIL-CLOSES with key=None: audit ok=False, no dialog
              reached, nothing written.
  P5 guard    SaveAs target INSIDE the guarded session temp dir is refused
              (temp-escape rule): audit ok=False, no file written.
  P6 worker   the real LinkWorker against the real instance: registered
              (>=1 pre-existing frame) BEFORE loaded (todo 14 hard ordering),
              new-frame watcher picks up a mid-session doc, target close ends
              the session cleanly (crashed=False), temp plaintext untouched.
"""

import argparse
import hashlib
import io
import os
import sys
import threading
import time
import zipfile

import uno

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.join(_HERE, "..", "src"),                 # force_encrypt
           os.path.abspath(os.path.join(_HERE, "..", ".."))):  # agent package
    if _p not in sys.path:
        sys.path.insert(0, _p)

import force_encrypt  # noqa: E402
from spike_reencrypt import (  # noqa: E402  (proven UNO verification helpers)
    EXPECTED_STREAMS, OLE_MAGIC, SERVICE, drain, nv, open_cfb_streams, pv)

PASSWORD = "smoke link live password 2616"
FACTORY_WRITER = "private:factory/swriter"
FILTER_DOCX = "MS Word 2007 XML"
OOXML_MAGIC = b"PK\x03\x04"

FAILURES = []


def out(line):
    print(line, flush=True)


def check(label, condition, detail=""):
    out("%s  %s %s" % ("PASS" if condition else "FAIL", label, detail))
    if not condition:
        FAILURES.append(label)
    return bool(condition)


def note(label, detail):
    out("NOTE  %s -- %s" % (label, detail))


def connect(url, timeout=30.0):
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
    raise SystemExit("could not connect to smoke instance: %s" % last)


def desktop_of(ctx):
    return ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.Desktop", ctx)


def enumerate_frames(desktop):
    # XFrames.queryFrames -- the live-proven channel (spike P4); Frames has NO
    # createEnumeration on a real desktop.
    flag = uno.getConstantByName("com.sun.star.frame.FrameSearchFlag.ALL")
    return list(desktop.getFrames().queryFrames(flag))


def new_writer_doc(desktop, text):
    doc = desktop.loadComponentFromURL(FACTORY_WRITER, "_blank", 0, ())
    doc.Text.setString(text)
    return doc


def store_plain_docx(desktop, path, text):
    """A real plaintext .docx ON DISK, product-shaped (session temp medium)."""
    doc = new_writer_doc(desktop, text)
    doc.storeToURL(uno.systemPathToFileUrl(path), (pv("FilterName", FILTER_DOCX),))
    doc.close(False)


def sha_of(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def engine_log(path):
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def dispatch(ctx, frame, command, arguments=()):
    helper = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.DispatchHelper", ctx)
    helper.executeDispatch(frame, command, "", 0, arguments)


def zip_has_marker(data, marker):
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            return any(marker.encode("utf-8") in zf.read(name)
                       for name in zf.namelist())
    except Exception:  # noqa: BLE001  (not a zip -> no marker)
        return False


def register_with(frame, provider, audits, guard_dir=None):
    """force_encrypt.register_on_frame with a capturing audit reporter."""
    def report(action, file_hash, key_version, ok):
        audits.append((action, file_hash, key_version, ok))
    interceptor = force_encrypt.register_on_frame(frame, provider, report)
    if guard_dir:
        interceptor.set_guard(guard_dir)
    return interceptor


def close_quietly(interceptor, doc):
    for closer in (interceptor.release, lambda: doc.close(False)):
        try:
            closer()
        except Exception:  # noqa: BLE001  (bridge may be gone; disk tells truth)
            pass


def verify_cfb_product(ctx, label, path, marker, password):
    """Hard verification: OLE magic, 5 engine streams, engine decrypt+marker."""
    if not check("%s: product written" % label, os.path.exists(path), path):
        return
    with open(path, "rb") as fh:
        raw = fh.read()
    if not check("%s: OLE/CFB magic (not plaintext ZIP)" % label,
                 raw[:8] == OLE_MAGIC,
                 "%d bytes, magic=%s" % (len(raw), raw[:8].hex())):
        return
    streams = open_cfb_streams(ctx, path)
    if not check("%s: CFB exposes the 5 engine streams" % label,
                 set(streams) == set(EXPECTED_STREAMS), str(sorted(streams))):
        return
    obj = ctx.ServiceManager.createInstanceWithContext(SERVICE, ctx)
    enc = obj.queryInterface(
        uno.getTypeByName("com.sun.star.packages.XPackageEncryption"))
    if not check("%s: engine instantiates" % label, enc is not None):
        return
    nvs = tuple(nv(name, uno.ByteSequence(data)) for name, data in streams.items())
    check("%s: readEncryptionInfo accepts container" % label,
          bool(enc.readEncryptionInfo(nvs)))
    check("%s: generateEncryptionKey(smoke password) accepted" % label,
          bool(enc.generateEncryptionKey(password)))
    pkg = ctx.ServiceManager.createInstanceWithArgumentsAndContext(
        "com.sun.star.io.SequenceInputStream",
        (uno.ByteSequence(streams["EncryptedPackage"]),), ctx)
    result = enc.decrypt(pkg, ())
    if not check("%s: decrypt() returns true" % label, bool(result[0])):
        return
    data = drain(result[1])
    check("%s: payload is the OOXML ZIP (PK magic)" % label,
          data.startswith(OOXML_MAGIC), "%d bytes" % len(data))
    check("%s: marker survives the engine round trip" % label,
          zip_has_marker(data, marker))


# ---------------------------------------------------------------------------
# P1: URP bridge frame identity idempotency (link-worker dedup premise)
# ---------------------------------------------------------------------------

def phase1(ctx, args):
    out("\n=== P1 frame identity: repeated enumeration over ONE bridge ===")
    desktop = desktop_of(ctx)
    d1 = new_writer_doc(desktop, "CipherBox smoke P1 first frame 1101")
    d2 = new_writer_doc(desktop, "CipherBox smoke P1 second frame 2202")
    list_a = enumerate_frames(desktop)
    list_b = enumerate_frames(desktop)
    check("P1 enumeration stable count",
          len(list_a) == len(list_b) and len(list_a) >= 2,
          "%d vs %d frames: %s" % (
              len(list_a), len(list_b),
              [getattr(f, "Title", "?") for f in list_a]))
    ids_a = [id(f) for f in list_a]
    ids_b = [id(f) for f in list_b]
    fresh = not (set(ids_a) & set(ids_b))
    note("P1 proxy freshness across repeated enumeration (LO build fact)",
         "FRESH ids per call -- dedup must NOT use proxy identity (this is "
         "why the link worker probes the interceptor chain)"
         if fresh else "proxies stable on this build")

    # The dedup mechanism the link worker relies on: a second registration on
    # the same frame receives the previous chain head as its slave, and that
    # slave reports OUR implementation name over XServiceInfo (the one string
    # member that survives the bridge -- plain python methods do not).
    audits = []
    ic1 = register_with(list_a[0], lambda: None, audits)
    ic2 = force_encrypt.register_on_frame(list_a[0], lambda: None,
                                          lambda *a: None)
    slave = ic2.getSlaveDispatchProvider()
    name = getattr(slave, "getImplementationName", None)
    check("P1 chain dedup probe: IC2's slave reports IC1's impl name",
          callable(name) and name() == ic1.getImplementationName(),
          "slave-impl=%r" % (name() if callable(name) else slave))
    check("P1 registration produced no audit (register-only)", audits == [],
          str(audits))
    ic2.release()
    close_quietly(ic1, d1)
    try:
        d2.close(False)
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------------------
# P2: forced SaveAs -> CFB (engine registration proof on THIS machine)
# ---------------------------------------------------------------------------

def phase2(ctx, args):
    out("\n=== P2 forced SaveAs -> CFB + engine round trip ===")
    session = os.path.join(args.out, "p2", "session")
    target_dir = os.path.join(args.out, "p2", "out")
    os.makedirs(session, exist_ok=True)
    os.makedirs(target_dir, exist_ok=True)
    plain = os.path.join(session, "plain.docx")
    store_plain_docx(desktop_of(ctx), plain, "CipherBox smoke P2 marker 2602")
    plain_sha = sha_of(plain)
    log_before = len(engine_log(args.engine_log))

    desktop = desktop_of(ctx)
    doc = desktop.loadComponentFromURL(
        uno.systemPathToFileUrl(plain), "_blank", 0, ())
    check("P2 plaintext loads", doc is not None)
    frame = doc.CurrentController.Frame
    audits = []
    interceptor = register_with(frame, lambda: PASSWORD, audits, guard_dir=session)
    target = os.path.join(target_dir, "smoke-forced.docx")
    dispatch(ctx, frame, ".uno:SaveAs", (
        pv("URL", uno.systemPathToFileUrl(target)),
        pv("FilterName", FILTER_DOCX)))
    encrypt_audits = [a for a in audits if a[0] == "encrypt"]
    check("P2 encrypt audit fired exactly once", len(encrypt_audits) == 1,
          str(audits))
    if encrypt_audits:
        check("P2 encrypt audit ok=True", encrypt_audits[0][3] is True)
        check("P2 encrypt audit carries a real content sha256",
              len(encrypt_audits[0][1]) == 64, "hash=%r" % encrypt_audits[0][1])
    try:
        check("P2 doc medium switched to the target",
              doc.getLocation() == uno.systemPathToFileUrl(target),
              "location=%r" % doc.getLocation())
    except Exception as exc:  # noqa: BLE001
        note("P2 in-memory assertion skipped", repr(exc))
    close_quietly(interceptor, doc)
    check("P2 engine encrypt() ran during forced SaveAs",
          "encrypt()" in engine_log(args.engine_log)[log_before:])
    check("P2 source plaintext untouched (byte-identical)",
          os.path.exists(plain) and sha_of(plain) == plain_sha)
    verify_cfb_product(ctx, "P2", target, "CipherBox smoke P2 marker 2602",
                       PASSWORD)


# ---------------------------------------------------------------------------
# P3: Ctrl+S on the temp plaintext must stay plaintext (corruption fix)
# ---------------------------------------------------------------------------

def disable_alien_warning(ctx):
    """Headless .uno:Save on a docx medium otherwise runs the alien-format
    interaction path (product deploy disables it too — controlled sessions
    must not prompt; todo 21 hardening)."""
    provider = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.configuration.ConfigurationProvider", ctx)
    access = provider.createInstanceWithArguments(
        "com.sun.star.configuration.ConfigurationUpdateAccess",
        (pv("nodepath", "/org.openoffice.Office.Common/Save/Document"),))
    access.setPropertyValue("WarnAlienFormat", False)
    access.commitChanges()


def phase3(ctx, args):
    out("\n=== P3 in-place .uno:Save -> delegate unchanged (plaintext persists) ===")
    session = os.path.join(args.out, "p3", "session")
    os.makedirs(session, exist_ok=True)
    disable_alien_warning(ctx)
    plain = os.path.join(session, "plain.docx")
    store_plain_docx(desktop_of(ctx), plain, "CipherBox smoke P3 first 3303")
    plain_sha = sha_of(plain)  # baseline BEFORE the edit (docx parts deflate)
    log_before = len(engine_log(args.engine_log))

    desktop = desktop_of(ctx)
    doc = desktop.loadComponentFromURL(
        uno.systemPathToFileUrl(plain), "_blank", 0, ())
    frame = doc.CurrentController.Frame
    audits = []
    interceptor = register_with(frame, lambda: PASSWORD, audits, guard_dir=session)
    doc.Text.setString("CipherBox smoke P3 EDITED 4404")  # simulate a user edit
    try:
        dispatch(ctx, frame, ".uno:Save")  # no URL argument: in-place save
    except Exception as exc:  # noqa: BLE001 — bridge may die mid-delegation
        note("P3 dispatch raised (delegate path)", repr(exc))
    # Disk assertions FIRST (no bridge): they survive a bridge death.
    with open(plain, "rb") as fh:
        raw = fh.read()
    check("P3 file on disk is STILL plaintext ZIP (no EncryptionData injection)",
          raw[:4] == OOXML_MAGIC, "magic=%s, %d bytes" % (raw[:8].hex(), len(raw)))
    check("P3 save rewrote the file (sha changed from the stored baseline)",
          sha_of(plain) != plain_sha,
          "before=%s after=%s" % (plain_sha[:16], sha_of(plain)[:16]))
    check("P3 edit persisted to disk (marker inside the inflated OOXML)",
          zip_has_marker(raw, "P3 EDITED 4404"),
          "%d bytes, zip=%r" % (len(raw), raw[:2]))
    check("P3 no encrypt audit fired",
          not any(a[0] == "encrypt" for a in audits), str(audits))
    check("P3 engine did NOT run (no encrypt() in engine log)",
          "encrypt()" not in engine_log(args.engine_log)[log_before:])
    # Bridge probes LAST: a dead bridge hard-crashes pyuno clients.
    try:
        check("P3 doc unmodified after save", not doc.isModified())
        check("P3 medium unchanged (still the temp plaintext)",
              doc.getLocation() == uno.systemPathToFileUrl(plain),
              "location=%r" % doc.getLocation())
        note("P3 instance still alive after dispatch", "yes")
    except Exception as exc:  # noqa: BLE001
        note("P3 bridge probes failed (bridge dead)", repr(exc))
    try:
        close_quietly(interceptor, doc)
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------------------
# P4: dialog-flow SaveAs (no URL) fail-closes without a key
# ---------------------------------------------------------------------------

def phase4(ctx, args):
    out("\n=== P4 dialog flow (no URL arg) -> fail-closed with key=None ===")
    guard_dir = os.path.join(args.out, "p4", "out")
    os.makedirs(guard_dir, exist_ok=True)
    desktop = desktop_of(ctx)
    doc = new_writer_doc(desktop, "CipherBox smoke P4 marker 5505")
    frame = doc.CurrentController.Frame
    audits = []
    interceptor = register_with(frame, lambda: None, audits, guard_dir=guard_dir)
    dispatch(ctx, frame, ".uno:SaveAs")  # dialog flow: no URL argument
    close_quietly(interceptor, doc)
    encrypt_audits = [a for a in audits if a[0] == "encrypt"]
    check("P4 fail-closed encrypt audit fired exactly once",
          len(encrypt_audits) == 1, str(audits))
    if encrypt_audits:
        check("P4 audit records ok=False (refusal, not silence)",
              encrypt_audits[0][3] is False)
        check("P4 refusal carries no content hash", encrypt_audits[0][1] == "")
    leftovers = os.listdir(guard_dir)
    check("P4 nothing written under the guard dir (no dialog escape)",
          leftovers == [], str(leftovers))


# ---------------------------------------------------------------------------
# P5: temp-escape guard -- SaveAs target inside the session temp dir
# ---------------------------------------------------------------------------

def phase5(ctx, args):
    out("\n=== P5 SaveAs target under the guard dir is refused ===")
    session = os.path.join(args.out, "p5", "session")
    os.makedirs(session, exist_ok=True)
    plain = os.path.join(session, "plain.docx")
    store_plain_docx(desktop_of(ctx), plain, "CipherBox smoke P5 marker 6606")
    desktop = desktop_of(ctx)
    doc = desktop.loadComponentFromURL(
        uno.systemPathToFileUrl(plain), "_blank", 0, ())
    frame = doc.CurrentController.Frame
    audits = []
    interceptor = register_with(frame, lambda: PASSWORD, audits, guard_dir=session)
    escape = os.path.join(session, "escape.docx")
    dispatch(ctx, frame, ".uno:SaveAs", (
        pv("URL", uno.systemPathToFileUrl(escape)),
        pv("FilterName", FILTER_DOCX)))
    close_quietly(interceptor, doc)
    encrypt_audits = [a for a in audits if a[0] == "encrypt"]
    check("P5 guard-refusal audit fired exactly once",
          len(encrypt_audits) == 1, str(audits))
    if encrypt_audits:
        check("P5 refusal ok=False", encrypt_audits[0][3] is False)
    check("P5 escape target NOT written", not os.path.exists(escape))
    check("P5 session dir gained no new files",
          os.listdir(session) == ["plain.docx"], str(os.listdir(session)))
    with open(plain, "rb") as fh:
        check("P5 source plaintext still plaintext ZIP", fh.read(4) == OOXML_MAGIC)


# ---------------------------------------------------------------------------
# P6: the real LinkWorker -- hard ordering, watcher, clean close
# ---------------------------------------------------------------------------

def phase6(ctx, args):
    out("\n=== P6 real LinkWorker: registered BEFORE loaded, watcher, close ===")
    from agent.uno_link_worker import LinkWorker

    session = os.path.join(args.out, "p6", "session")
    queue_dir = os.path.join(args.out, "p6", "audit-queue")
    os.makedirs(session, exist_ok=True)
    plain = os.path.join(session, "plain.docx")
    store_plain_docx(desktop_of(ctx), plain, "CipherBox smoke P6 marker 7707")

    desktop = desktop_of(ctx)
    sac = new_writer_doc(desktop, "CipherBox smoke P6 sacrificial frame")

    audits = []
    events = []

    def requester(pipe_name, request, timeout_s=None):
        if request.get("cmd") == "key":
            return {"ok": True, "key": PASSWORD}
        audits.append(dict(request))
        return {"ok": True}

    def emit(payload):
        events.append(payload)

    spec = {"soffice_pipe": args.pipe, "doc_path": plain,
            "agent_pipe": "\\\\.\\pipe\\cipherbox-smoke6-link",
            "queue_dir": queue_dir, "poll_seconds": 1.0}
    worker = LinkWorker(spec, uno_module=uno,
                        force_encrypt_module=force_encrypt,
                        requester=requester, emit=emit)
    thread = threading.Thread(target=worker.run, daemon=True)
    thread.start()

    deadline = time.time() + 60
    while time.time() < deadline and not any(
            e.get("event") == "loaded" or e.get("ok") is False for e in events):
        time.sleep(0.5)
    registered_idx = next((i for i, e in enumerate(events)
                           if e.get("event") == "registered"), None)
    loaded_idx = next((i for i, e in enumerate(events)
                       if e.get("event") == "loaded"), None)
    check("P6 worker reached registered+loaded",
          registered_idx is not None and loaded_idx is not None, str(events))
    check("P6 hard ordering: registered BEFORE loaded (todo 14)",
          registered_idx is not None and loaded_idx is not None
          and registered_idx < loaded_idx, str(events))
    frames_at_registered = next((e.get("frames") for e in events
                                 if e.get("event") == "registered"), 0)
    check("P6 registered on >=1 pre-existing frame", frames_at_registered >= 1,
          "frames=%r" % frames_at_registered)
    check("P6 the SACRIFICIAL frame was swept (existing frames intercepted)",
          len(worker._registered_frames) >= 1,
          "registered=%d" % len(worker._registered_frames))

    second = new_writer_doc(desktop, "CipherBox smoke P6 mid-session frame")
    deadline = time.time() + 15
    while time.time() < deadline and len(worker._registered_frames) < 2:
        time.sleep(0.5)
    check("P6 watcher registered the mid-session frame",
          len(worker._registered_frames) >= 2,
          "registered=%d" % len(worker._registered_frames))
    check("P6 temp plaintext still plaintext ZIP while session open",
          open(plain, "rb").read(4) == OOXML_MAGIC)

    def find_doc_with(text):
        enum = desktop.getComponents().createEnumeration()
        while enum.hasMoreElements():
            comp = enum.nextElement()
            try:
                if text in comp.Text.getString():
                    return comp
            except Exception:  # noqa: BLE001  (non-Writer components)
                pass
        return None

    target_doc = find_doc_with("7707")
    check("P6 target doc found for close", target_doc is not None)
    if target_doc is not None:
        target_doc.close(False)
    thread.join(timeout=30)
    closed = next((e for e in events if e.get("event") == "closed"), None)
    check("P6 worker emitted closed (clean, not crashed)",
          closed is not None and closed.get("crashed") is False, str(events))
    check("P6 worker thread exited", not thread.is_alive())
    check("P6 no audit events during open/edit/close (nothing saved)",
          audits == [], str(audits))
    with open(plain, "rb") as fh:
        check("P6 temp plaintext STILL plaintext after session end",
              fh.read(4) == OOXML_MAGIC)
    for leftover in (sac, second):
        try:
            leftover.close(False)
        except Exception:  # noqa: BLE001
            pass


PHASES = {1: phase1, 2: phase2, 3: phase3, 4: phase4, 5: phase5, 6: phase6}


def main():
    # LO doc titles follow the UI locale (CJK on this machine); the default
    # cp1252 redirected-stdout codec cannot encode them.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except AttributeError:
            pass
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", type=int, required=True,
                        choices=sorted(PHASES))
    parser.add_argument("--url", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--engine-log", required=True)
    parser.add_argument("--pipe", default="cipherbox-smoke6")
    args = parser.parse_args()

    out("smoke_link_live phase %d; products in %s" % (args.phase, args.out))
    ctx = connect(args.url)
    PHASES[args.phase](ctx, args)

    out("")
    if FAILURES:
        out("RESULT: FAIL (%d) -> %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    out("RESULT: PASS (phase %d)" % args.phase)
    return 0


if __name__ == "__main__":
    sys.exit(main())
