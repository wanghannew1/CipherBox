"""Spike: XDispatchProviderInterceptor feasibility on LO 26.8 (Wave 0 todo 4).

Phase-driven (plan lines 99-104). Each phase runs against a FRESH dedicated
headless instance (pipe cipherbox-spike4, own temp profile, CipherBoxDataSpace
engine registered via components.rdb + unorc replicating start_soffice.ps1).
Ciphertext is verified by OLE magic + engine-API decrypt round trip, never by
"dispatch returned". Hang-risky dispatches (picker-prone) run LAST inside a
phase so a runner watchdog kill still leaves earlier findings on disk.

P1 register interceptor on a doc frame; queryDispatch/dispatch fire.
P2 .uno:SaveAs: (b) interceptor self storeToURL(FilterName, Password,
   EncryptionData) first (hang-safe), then (a) descriptor pre-set + delegate
   to the slave provider (picker risk last).
P3 second doc frame: dispatch NOT intercepted until registered there too
   (per-frame registration evidence).
P4 new-frame discovery: Desktop.Components diff vs Desktop.Frames.queryFrames
   vs GlobalEventBroadcaster events; bonus XModel2.createViewController
   (second view of the same doc -- which channel sees the new frame?).
P5 reverse channel: agent-side callback object invoked from dispatch() (key
   fetch, measured latency) + bridge RTT baseline.
P6 .uno:SaveACopy interceptable + descriptor rewrite works.
P7 Save-after-SaveAs: does a later .uno:Save keep EncryptionData (product
   stays CFB) or is the .cbx overwritten in plaintext? (critical for todo 17)
P8 export/print/send family: .uno:ExportTo/.uno:ExportToPDF/
   .uno:ExportDirectToPDF executed with attempted EncryptionData injection;
   .uno:Print/.uno:PrintDefault/.uno:SendMail/.uno:SendDocAsPDF probed at
   queryDispatch level only (printer/mail side effects are out of bounds).
P9 .uno:SaveAll routing: does the frame interceptor chain see it; do the
   per-document stores it triggers pass any frame chain?

Run ONLY via run_spike_interceptor.ps1 (bundled LO python, per-phase
watchdog, dedicated instance lifecycle). NEVER against cipherbox-service.
"""

import argparse
import io
import os
import sys
import time
import zipfile

import uno
import unohelper
from com.sun.star.document import XEventListener
from com.sun.star.frame import XDispatch, XDispatchProviderInterceptor

from spike_reencrypt import (
    EXPECTED_STREAMS,
    OLE_MAGIC,
    SERVICE,
    drain,
    nv,
    open_cfb_streams,
    pv,
)

FILTER_DOCX = "MS Word 2007 XML"
PASSWORD = "correct horse battery staple"
CRYPTO_TYPE = "CipherBoxDataSpace"
FACTORY_WRITER = "private:factory/swriter"

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


def connect(url, timeout=30):
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
    raise SystemExit("could not connect to spike4 instance: %s" % last)


def engine_log():
    path = os.path.join(os.environ.get("TEMP", "."), "cipherbox-encryption.log")
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def make_url(ctx, complete):
    transformer = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.util.URLTransformer", ctx)
    u = uno.createUnoStruct("com.sun.star.util.URL")
    u.Complete = complete
    ok, parsed = transformer.parseStrict(u)
    return parsed if ok else u


def new_writer_doc(desktop):
    return desktop.loadComponentFromURL(FACTORY_WRITER, "_blank", 0, ())


def set_text(doc, text):
    doc.Text.setString(text)


def encryption_args(target_url, password=PASSWORD, filter_name=FILTER_DOCX):
    """The proven descriptor that routes a save to the custom engine."""
    return (
        pv("URL", target_url),
        pv("FilterName", filter_name),
        pv("Password", password),
        pv("EncryptionData", uno.Any(
            "[]com.sun.star.beans.NamedValue",
            (nv("CryptoType", CRYPTO_TYPE), nv("Password", password)))),
    )


def zip_has_marker(data, marker):
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            return any(marker.encode("utf-8") in zf.read(name)
                       for name in zf.namelist())
    except zipfile.BadZipFile:
        return False


def verify_cfb_product(ctx, label, path, marker):
    """Hard verification: OLE magic, 5 engine streams, engine decrypt + marker."""
    if not check("%s: product written" % label, os.path.exists(path), path):
        return
    with open(path, "rb") as fh:
        raw = fh.read()
    check("%s: OLE/CFB magic" % label, raw[:8] == OLE_MAGIC,
          "%d bytes, magic=%s" % (len(raw), raw[:8].hex()))
    if raw[:8] != OLE_MAGIC:
        note("%s: NOT CFB -- first bytes %r" % (label, raw[:16]))
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
    nvs = tuple(nv(name, uno.ByteSequence(data))
                for name, data in streams.items())
    check("%s: readEncryptionInfo accepts container" % label,
          bool(enc.readEncryptionInfo(nvs)))
    check("%s: generateEncryptionKey(test password)" % label,
          bool(enc.generateEncryptionKey(PASSWORD)))
    pkg = ctx.ServiceManager.createInstanceWithArgumentsAndContext(
        "com.sun.star.io.SequenceInputStream",
        (uno.ByteSequence(streams["EncryptedPackage"]),), ctx)
    result = enc.decrypt(pkg, ())
    if not check("%s: decrypt() returns true" % label, bool(result[0])):
        return
    data = drain(result[1])
    check("%s: payload is OOXML ZIP" % label, data.startswith(b"PK\x03\x04"),
          "%d bytes" % len(data))
    check("%s: marker survives engine round trip" % label,
          zip_has_marker(data, marker))


class AgentCallback(unohelper.Base):
    """Agent-side object handed to the interceptor at registration time.

    The pattern todo 17 needs: an XJob-style callback reference passed across
    the bridge once, invoked later from the interceptor's dispatch path.
    """

    def __init__(self):
        self.calls = []

    def getMasterKey(self, purpose):
        self.calls.append(("getMasterKey", purpose, time.time()))
        return PASSWORD

    def reportEvent(self, action, detail):
        self.calls.append(("reportEvent", action, detail, time.time()))
        return True


class Interceptor(unohelper.Base, XDispatchProviderInterceptor, XDispatch):
    """com.sun.star.frame.XDispatchProviderInterceptor + XDispatch."""

    def __init__(self, capture=(), on_dispatch=None):
        self._slave = None
        self._master = None
        self.capture = set(capture)
        self.on_dispatch = on_dispatch
        self.frame = None
        self.queries = []
        self.dispatches = []

    # -- XDispatchProvider (via XDispatchProviderInterceptor) ----------------
    def queryDispatch(self, url, targetFrameName, searchFlags):
        self.queries.append(url.Complete)
        if url.Complete in self.capture:
            return self
        if self._slave is not None:
            return self._slave.queryDispatch(url, targetFrameName, searchFlags)
        return None

    def queryDispatches(self, requests):
        return tuple(
            self.queryDispatch(r.FeatureURL, r.TargetFrameName, r.SearchFlags)
            for r in requests)

    # -- XDispatchProviderInterceptor chain hooks ----------------------------
    def getSlaveDispatchProvider(self):
        return self._slave

    def setSlaveDispatchProvider(self, provider):
        self._slave = provider

    def getMasterDispatchProvider(self):
        return self._master

    def setMasterDispatchProvider(self, supplier):
        self._master = supplier

    # -- XDispatch ------------------------------------------------------------
    def dispatch(self, url, args):
        self.dispatches.append(url.Complete)
        if self.on_dispatch is not None:
            self.on_dispatch(self, url, args)

    def addStatusListener(self, listener, url):
        pass

    def removeStatusListener(self, listener, url):
        pass

    # -- helpers --------------------------------------------------------------
    def delegate(self, url, args):
        if self._slave is None:
            raise RuntimeError("interceptor chain has no slave provider")
        target = self._slave.queryDispatch(url, "", 0)
        if target is None:
            raise RuntimeError("slave refused dispatch: %s" % url.Complete)
        target.dispatch(url, args)


def dispatch_via_helper(ctx, frame, complete, args=()):
    helper = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.DispatchHelper", ctx)
    helper.executeDispatch(frame, complete, "", 0, args)


def register(frame, interceptor):
    interceptor.frame = frame
    frame.registerDispatchProviderInterceptor(interceptor)


def release(frame, interceptor):
    try:
        frame.releaseDispatchProviderInterceptor(interceptor)
    except Exception:  # noqa: BLE001
        pass


def close_doc(doc):
    try:
        doc.close(False)
    except Exception:  # noqa: BLE001
        pass


# --------------------------------------------------------------------------
# P1: registration + queryDispatch/dispatch fire
# --------------------------------------------------------------------------

def phase1(ctx, out_dir):
    out("\n=== P1 register interceptor; queryDispatch fires ===")
    desktop = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.Desktop", ctx)
    doc = new_writer_doc(desktop)
    set_text(doc, "CipherBox spike P1 marker")
    frame = doc.CurrentController.Frame
    ic = Interceptor(capture={".uno:SaveAs"})  # swallow mode: no on_dispatch
    register(frame, ic)
    check("P1 registration wired the slave provider", ic.getSlaveDispatchProvider() is not None)

    dispatch_via_helper(ctx, frame, ".uno:SaveAs")
    check("P1 queryDispatch fired for .uno:SaveAs", ".uno:SaveAs" in ic.queries)
    check("P1 dispatch() reached the interceptor", ".uno:SaveAs" in ic.dispatches)
    check("P1 swallowed save left doc modified (slave never ran)",
          bool(doc.isModified()))

    dispatch_via_helper(ctx, frame, ".uno:Undo")
    check("P1 non-captured dispatch still traverses the chain",
          ".uno:Undo" in ic.queries)
    check("P1 non-captured dispatch NOT claimed by interceptor",
          ".uno:Undo" not in ic.dispatches)
    release(frame, ic)
    close_doc(doc)
    out("PROBE P1 XDispatchProviderInterceptor registration/queryDispatch: see PASS/FAIL above")


# --------------------------------------------------------------------------
# P2: .uno:SaveAs -- (b) self storeToURL, then (a) delegate with descriptor
# --------------------------------------------------------------------------

def phase2(ctx, out_dir):
    out("\n=== P2 .uno:SaveAs descriptor rewrite ===")
    desktop = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.Desktop", ctx)

    # (b) hang-safe first: interceptor performs storeToURL itself.
    marker_b = "CipherBox spike P2b marker 7357"
    target_b = os.path.join(out_dir, "p2b-selfstore.cbx")
    target_b_url = uno.systemPathToFileUrl(target_b)
    doc = new_writer_doc(desktop)
    set_text(doc, marker_b)
    frame = doc.CurrentController.Frame

    def on_dispatch_b(self_, url, args):
        model = self_.frame.getController().getModel()
        model.storeToURL(target_b_url, encryption_args(target_b_url))

    ic = Interceptor(capture={".uno:SaveAs"}, on_dispatch=on_dispatch_b)
    register(frame, ic)
    log_before = len(engine_log())
    dispatch_via_helper(ctx, frame, ".uno:SaveAs")  # no args: interceptor builds all
    check("P2b dispatch reached interceptor", ".uno:SaveAs" in ic.dispatches)
    check("P2b engine encrypt() ran during interceptor storeToURL",
          "encrypt()" in engine_log()[log_before:])
    verify_cfb_product(ctx, "P2b", target_b, marker_b)
    check("P2b doc medium NOT switched by storeToURL (location still empty)",
          doc.getLocation() == "", "location=%r" % doc.getLocation())
    release(frame, ic)
    close_doc(doc)

    # (a) hang-risk LAST: pre-set descriptor + delegate to the slave provider.
    marker_a = "CipherBox spike P2a marker 8801"
    target_a = os.path.join(out_dir, "p2a-delegate.cbx")
    target_a_url = uno.systemPathToFileUrl(target_a)
    doc2 = new_writer_doc(desktop)
    set_text(doc2, marker_a)
    frame2 = doc2.CurrentController.Frame

    def on_dispatch_a(self_, url, args):
        self_.delegate(url, encryption_args(target_a_url))

    ic2 = Interceptor(capture={".uno:SaveAs"}, on_dispatch=on_dispatch_a)
    register(frame2, ic2)
    log_before = len(engine_log())
    out("P2a delegating .uno:SaveAs with pre-set URL/FilterName/Password/"
        "EncryptionData (picker-free attempt; watchdog guards a hang)...")
    dispatch_via_helper(ctx, frame2, ".uno:SaveAs")
    check("P2a delegate SaveAs returned (no picker hang)",
          ".uno:SaveAs" in ic2.dispatches)
    check("P2a engine encrypt() ran during delegated SaveAs",
          "encrypt()" in engine_log()[log_before:])
    verify_cfb_product(ctx, "P2a", target_a, marker_a)
    check("P2a doc medium switched to the .cbx target (SaveAs semantics)",
          doc2.getLocation() == target_a_url, "location=%r" % doc2.getLocation())
    check("P2a doc unmodified after delegated SaveAs", not doc2.isModified())
    release(frame2, ic2)
    close_doc(doc2)
    out("PROBE P2 SaveAs rewrite: see PASS/FAIL above")


# --------------------------------------------------------------------------
# P3: second frame/doc is NOT intercepted until registered (per-frame)
# --------------------------------------------------------------------------

def phase3(ctx, out_dir):
    out("\n=== P3 second frame: per-frame registration evidence ===")
    desktop = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.Desktop", ctx)
    doc1 = new_writer_doc(desktop)
    set_text(doc1, "CipherBox spike P3 doc1")
    frame1 = doc1.CurrentController.Frame
    ic1 = Interceptor(capture={".uno:SaveAs"})
    register(frame1, ic1)

    doc2 = new_writer_doc(desktop)
    set_text(doc2, "CipherBox spike P3 doc2")
    frame2 = doc2.CurrentController.Frame

    plain = os.path.join(out_dir, "p3-frame2-plain.docx")
    plain_url = uno.systemPathToFileUrl(plain)
    dispatch_via_helper(ctx, frame2, ".uno:SaveAs",
                        (pv("URL", plain_url), pv("FilterName", FILTER_DOCX)))
    note("P3 frame1 chain background query traffic (menu/status polling is "
         "constant even headless; %d queries)" % len(ic1.queries),
         "first=%r" % (ic1.queries[:4],))
    check("P3 frame2's SaveAs DISPATCH never reached frame1's interceptor",
          ".uno:SaveAs" not in ic1.dispatches,
          "ic1.dispatches=%r" % (ic1.dispatches,))
    if check("P3 unintercepted frame2 SaveAs wrote a product",
             os.path.exists(plain), plain):
        with open(plain, "rb") as fh:
            raw = fh.read()
        check("P3 unintercepted product is PLAINTEXT docx (PK)",
              raw[:4] == b"PK\x03\x04", "magic=%s" % raw[:8].hex())

    swallowed = os.path.join(out_dir, "p3-frame2-swallowed.docx")
    ic2 = Interceptor(capture={".uno:SaveAs"})
    register(frame2, ic2)
    dispatch_via_helper(ctx, frame2, ".uno:SaveAs",
                        (pv("URL", uno.systemPathToFileUrl(swallowed)),
                         pv("FilterName", FILTER_DOCX)))
    check("P3 after registering on frame2 its SaveAs IS intercepted",
          ".uno:SaveAs" in ic2.dispatches)
    check("P3 swallowed by frame2 interceptor: no product written",
          not os.path.exists(swallowed))
    release(frame1, ic1)
    release(frame2, ic2)
    close_doc(doc1)
    close_doc(doc2)
    out("PROBE P3 per-frame registration: see PASS/FAIL above")


# --------------------------------------------------------------------------
# P4: new-frame discovery channels
# --------------------------------------------------------------------------

class GebListener(unohelper.Base, XEventListener):
    def __init__(self):
        self.events = []

    def notifyEvent(self, event):
        self.events.append((time.time(), getattr(event, "EventName", "?"),
                            getattr(getattr(event, "Source", None), "URL", "?")))

    def disposing(self, source):
        pass


def enum_components(desktop):
    comps = []
    enum = desktop.getComponents().createEnumeration()
    while enum.hasMoreElements():
        comp = enum.nextElement()
        try:
            comps.append(comp.getURL() or "<untitled:%s>" % comp.getTitle())
        except Exception:  # noqa: BLE001
            comps.append("<unknown>")
    return comps


def query_all_frames(desktop):
    flag = uno.getConstantByName("com.sun.star.frame.FrameSearchFlag.ALL")
    return list(desktop.getFrames().queryFrames(flag))


def phase4(ctx, out_dir):
    out("\n=== P4 new-frame discovery: Components diff vs queryFrames vs GEB ===")
    desktop = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.Desktop", ctx)
    geb = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.GlobalEventBroadcaster", ctx)
    listener = GebListener()
    geb.addEventListener(listener)

    comps0 = enum_components(desktop)
    frames0 = query_all_frames(desktop)
    note("P4 baseline", "components=%d frames=%d" % (len(comps0), len(frames0)))

    doc = new_writer_doc(desktop)
    set_text(doc, "CipherBox spike P4 marker")
    time.sleep(1.5)  # let async broadcaster events land
    comps1 = enum_components(desktop)
    frames1 = query_all_frames(desktop)
    check("P4 Desktop.Components diff sees the new document",
          len(comps1) - len(comps0) == 1, "+%d %r" % (len(comps1) - len(comps0), comps1))
    check("P4 Desktop.Frames queryFrames diff sees the new frame",
          len(frames1) - len(frames0) == 1, "+%d" % (len(frames1) - len(frames0)))
    ev_doc = [e for e in listener.events]
    note("P4 GEB events on document load", str([e[1] for e in ev_doc]))
    check("P4 GlobalEventBroadcaster fired document event(s)", len(ev_doc) > 0,
          str([e[1] for e in ev_doc]))

    # Bonus: second VIEW of the same document (Window > New Window equivalent).
    n_events_before = len(listener.events)
    try:
        frame2 = ctx.ServiceManager.createInstanceWithContext(
            "com.sun.star.frame.Frame", ctx)
        desktop.getFrames().append(frame2)
        controller = doc.createViewController("Default", (), frame2)
        time.sleep(1.5)
        if not check("P4 XModel2.createViewController produced a second view",
                     controller is not None):
            raise RuntimeError("no controller")
        comps2 = enum_components(desktop)
        frames2 = query_all_frames(desktop)
        check("P4 second view: queryFrames diff sees the new frame",
              len(frames2) - len(frames1) == 1, "+%d" % (len(frames2) - len(frames1)))
        check("P4 second view: Components diff does NOT see it (same doc)",
              len(comps2) - len(comps1) == 0, "+%d" % (len(comps2) - len(comps1)))
        ev_view = listener.events[n_events_before:]
        note("P4 GEB events on second view", str([e[1] for e in ev_view]))
    except Exception as exc:  # noqa: BLE001
        note("P4 createViewController headless", "RAISED %r -- second view of the "
             "same doc is not creatable headless (container window required); "
             "GEB OnViewCreated fired for the initial view, queryFrames polling "
             "sees all frames regardless" % (exc,))
    close_doc(doc)
    out("PROBE P4 new-frame discovery: see PASS/FAIL above")


# --------------------------------------------------------------------------
# P5: reverse UNO channel (agent-side callback) + latency
# --------------------------------------------------------------------------

def phase5(ctx, out_dir):
    out("\n=== P5 reverse channel: callback invoked from dispatch path ===")
    desktop = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.Desktop", ctx)
    doc = new_writer_doc(desktop)
    marker = "CipherBox spike P5 marker 2210"
    set_text(doc, marker)
    frame = doc.CurrentController.Frame

    # Bridge RTT baseline (LO-side getter called from agent, 50x).
    t0 = time.perf_counter()
    for _ in range(50):
        frame.getName()
    rtt_ms = (time.perf_counter() - t0) / 50 * 1000
    note("P5 bridge RTT baseline (agent->LO simple getter)", "%.2f ms" % rtt_ms)

    callback = AgentCallback()
    target = os.path.join(out_dir, "p5-callback.cbx")
    target_url = uno.systemPathToFileUrl(target)
    latencies = []

    def on_dispatch(self_, url, args):
        t_start = time.perf_counter()
        key = callback.getMasterKey("forced-saveas")
        latencies.append((time.perf_counter() - t_start) * 1000)
        model = self_.frame.getController().getModel()
        model.storeToURL(target_url, encryption_args(target_url, password=key))
        callback.reportEvent("encrypt", target_url)

    ic = Interceptor(capture={".uno:SaveAs"}, on_dispatch=on_dispatch)
    register(frame, ic)
    dispatch_via_helper(ctx, frame, ".uno:SaveAs")
    key_calls = [c for c in callback.calls if c[0] == "getMasterKey"]
    report_calls = [c for c in callback.calls if c[0] == "reportEvent"]
    check("P5 agent-side callback invoked from the dispatch path",
          len(key_calls) == 1, str(callback.calls))
    check("P5 callback-supplied key drove the encryption (round trip)",
          os.path.exists(target))
    if latencies:
        note("P5 getMasterKey latency (in-proc here; LO->agent adds ~1 RTT)",
             "%.3f ms; bridge RTT %.2f ms" % (latencies[0], rtt_ms))
    check("P5 audit reportEvent delivered", len(report_calls) == 1)
    verify_cfb_product(ctx, "P5", target, marker)
    release(frame, ic)
    close_doc(doc)
    out("PROBE P5 reverse channel: mechanism = agent-side unohelper.Base object "
        "passed at registration; invocations cross the pipe bridge via PyUNO "
        "XInvocation; measured RTT %.2f ms" % rtt_ms)


# --------------------------------------------------------------------------
# P6: .uno:SaveACopy
# --------------------------------------------------------------------------

def phase6(ctx, out_dir):
    out("\n=== P6 .uno:SaveACopy intercept + rewrite ===")
    desktop = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.Desktop", ctx)
    doc = new_writer_doc(desktop)
    marker = "CipherBox spike P6 marker 3141"
    set_text(doc, marker)
    frame = doc.CurrentController.Frame
    target = os.path.join(out_dir, "p6-saveacopy.cbx")
    target_url = uno.systemPathToFileUrl(target)

    # Attempt 1: delegate with the pre-set descriptor (SaveAs pattern).
    def on_delegate(self_, url, args):
        self_.delegate(url, encryption_args(target_url))

    ic = Interceptor(capture={".uno:SaveACopy"}, on_dispatch=on_delegate)
    register(frame, ic)
    log_before = len(engine_log())
    dispatch_via_helper(ctx, frame, ".uno:SaveACopy")
    check("P6 .uno:SaveACopy intercepted", ".uno:SaveACopy" in ic.dispatches)
    delegated_product = os.path.exists(target)
    delegated_engine = "encrypt()" in engine_log()[log_before:]
    note("P6 delegated SaveACopy outcome",
         "product=%s engine-ran=%s -- delegation with pre-set descriptor is a "
         "silent no-op headless (slot is picker-bound; contrast with SaveAs)"
         % (delegated_product, delegated_engine))
    check("P6 delegated SaveACopy wrote nothing (picker-bound slot finding)",
          not delegated_product and not delegated_engine)

    # Attempt 2: interceptor performs the copy itself (P2b pattern; SaveACopy
    # semantics kept: storeToURL never touches the doc medium).
    def on_selfstore(self_, url, args):
        model = self_.frame.getController().getModel()
        model.storeToURL(target_url, encryption_args(target_url))

    ic.on_dispatch = on_selfstore
    log_before = len(engine_log())
    dispatch_via_helper(ctx, frame, ".uno:SaveACopy")
    check("P6 self-store engine encrypt() ran", "encrypt()" in engine_log()[log_before:])
    verify_cfb_product(ctx, "P6-selfstore", target, marker)
    check("P6 doc medium NOT switched (SaveACopy semantics kept)",
          doc.getLocation() == "", "location=%r" % doc.getLocation())
    release(frame, ic)
    close_doc(doc)
    out("PROBE P6 SaveACopy: see PASS/FAIL above")


# --------------------------------------------------------------------------
# P7: Save-after-SaveAs -- does .uno:Save keep EncryptionData?
# --------------------------------------------------------------------------

def phase7(ctx, out_dir):
    out("\n=== P7 Save-after-SaveAs: EncryptionData retention (critical) ===")
    desktop = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.Desktop", ctx)
    doc = new_writer_doc(desktop)
    marker_a = "CipherBox spike P7 first marker 5150"
    set_text(doc, marker_a)
    frame = doc.CurrentController.Frame
    target = os.path.join(out_dir, "p7-doc.cbx")
    target_url = uno.systemPathToFileUrl(target)

    def on_dispatch(self_, url, args):
        if url.Complete == ".uno:SaveAs":
            self_.delegate(url, encryption_args(target_url))
        else:  # .uno:Save -- delegate UNCHANGED on purpose: the honest probe
            self_.delegate(url, args)

    ic = Interceptor(capture={".uno:SaveAs", ".uno:Save"}, on_dispatch=on_dispatch)
    register(frame, ic)
    dispatch_via_helper(ctx, frame, ".uno:SaveAs")
    check("P7 SaveAs intercepted+delegated", ".uno:SaveAs" in ic.dispatches)
    verify_cfb_product(ctx, "P7-SaveAs", target, marker_a)

    marker_b = "P7 SECOND marker 6262"
    doc.Text.setString(marker_a + " " + marker_b)
    with open(target, "rb") as fh:
        before = fh.read()
    dispatch_via_helper(ctx, frame, ".uno:Save")
    check("P7 .uno:Save intercepted", ".uno:Save" in ic.dispatches)
    with open(target, "rb") as fh:
        after = fh.read()
    check("P7 product rewritten by .uno:Save", before != after,
          "before=%dB after=%dB" % (len(before), len(after)))
    if after[:8] == OLE_MAGIC:
        note("P7 product after Save", "STILL CFB -- medium kept EncryptionData")
        verify_cfb_product(ctx, "P7-Save", target, marker_b)
    elif after[:4] == b"PK\x03\x04":
        check("P7 CRITICAL: .uno:Save overwrote .cbx with PLAINTEXT ZIP "
              "(EncryptionData NOT retained -- todo 17 must re-inject on Save)",
              False, "magic=%s" % after[:8].hex())
    else:
        check("P7 product after Save is neither CFB nor ZIP (unexpected)",
              False, "magic=%s" % after[:8].hex())
    release(frame, ic)
    close_doc(doc)
    out("PROBE P7 Save-after-SaveAs: see PASS/FAIL above")


# --------------------------------------------------------------------------
# P8: export / print / send family
# --------------------------------------------------------------------------

def phase8(ctx, out_dir):
    out("\n=== P8 export/print/send family ===")
    desktop = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.Desktop", ctx)
    doc = new_writer_doc(desktop)
    set_text(doc, "CipherBox spike P8 marker")
    frame = doc.CurrentController.Frame
    family = {".uno:ExportTo", ".uno:ExportToPDF", ".uno:ExportDirectToPDF",
              ".uno:Print", ".uno:PrintDefault", ".uno:SendMail",
              ".uno:SendDocAsPDF"}
    ic = Interceptor(capture=family)
    register(frame, ic)

    # Query-level only (no execution -> no printer/mail/picker side effects).
    for complete in sorted(family):
        before = len(ic.queries)
        provider = frame.queryDispatch(make_url(ctx, complete), "", 0)
        fired = len(ic.queries) > before and ic.queries[-1] == complete
        claimed = provider is not None
        note("P8 queryDispatch %-24s" % complete,
             "chain-fired=%s slave-has-handler=%s" % (fired, claimed))
        check("P8 %s traverses the interceptor chain" % complete, fired)

    # Executed: ExportTo (ODT) with attempted EncryptionData injection.
    def rewrite(target_url, filter_name):
        def handler(self_, url, args):
            self_.delegate(url, encryption_args(target_url,
                                                filter_name=filter_name))
        return handler

    odt = os.path.join(out_dir, "p8-exportto.odt")
    ic.on_dispatch = rewrite(uno.systemPathToFileUrl(odt), "writer8")
    log_before = len(engine_log())
    dispatch_via_helper(ctx, frame, ".uno:ExportTo")
    check("P8 .uno:ExportTo intercepted", ".uno:ExportTo" in ic.dispatches)
    exported = os.path.exists(odt)
    note("P8 ExportTo delegated outcome",
         "product=%s -- delegation with pre-set descriptor silently no-ops "
         "headless (same picker-bound class as SaveACopy); interception itself "
         "is proven, so the audit hook is viable" % exported)
    check("P8 ExportTo delegation produced no product headless (finding)",
          not exported)
    check("P8 ExportTo: engine encrypt() NOT invoked",
          "encrypt()" not in engine_log()[log_before:])

    # Executed: ExportDirectToPDF with attempted EncryptionData injection.
    pdf = os.path.join(out_dir, "p8-direct.pdf")
    ic.on_dispatch = rewrite(uno.systemPathToFileUrl(pdf), "writer_pdf_Export")
    log_before = len(engine_log())
    dispatch_via_helper(ctx, frame, ".uno:ExportDirectToPDF")
    check("P8 .uno:ExportDirectToPDF intercepted",
          ".uno:ExportDirectToPDF" in ic.dispatches)
    if check("P8 ExportDirectToPDF product written", os.path.exists(pdf), pdf):
        with open(pdf, "rb") as fh:
            raw = fh.read()
        check("P8 ExportDirectToPDF product is PLAINTEXT PDF",
              raw[:5] == b"%PDF-", "magic=%r" % raw[:8])
    check("P8 ExportDirectToPDF: engine encrypt() NOT invoked",
          "encrypt()" not in engine_log()[log_before:])

    # Executed LAST (picker risk): ExportToPDF with URL pre-set.
    pdf2 = os.path.join(out_dir, "p8-exporttopdf.pdf")
    ic.on_dispatch = rewrite(uno.systemPathToFileUrl(pdf2), "writer_pdf_Export")
    out("P8 executing .uno:ExportToPDF with URL pre-set (watchdog guards a hang)...")
    try:
        dispatch_via_helper(ctx, frame, ".uno:ExportToPDF")
        note("P8 ExportToPDF returned (no picker hang)",
             "dispatched=%s" % (".uno:ExportToPDF" in ic.dispatches))
        if os.path.exists(pdf2):
            with open(pdf2, "rb") as fh:
                raw = fh.read()
            note("P8 ExportToPDF product", "%d bytes magic=%r" % (len(raw), raw[:8]))
        else:
            note("P8 ExportToPDF product", "NONE -- returned without writing to "
                 "the pre-set URL (dialog-oriented slot headless; use "
                 "ExportDirectToPDF for the executable variant)")
    except Exception as exc:  # noqa: BLE001
        note("P8 ExportToPDF raised (recorded, not a chain failure)", repr(exc))
    release(frame, ic)
    close_doc(doc)
    out("PROBE P8 export/print/send family: see PASS/FAIL above")


# --------------------------------------------------------------------------
# P9: .uno:SaveAll routing
# --------------------------------------------------------------------------

def _settle_modified(docs, cap=5.0):
    """Poll until no doc is modified; return settle seconds or None."""
    t0 = time.time()
    while time.time() - t0 < cap:
        if not any(bool(d.isModified()) for d in docs):
            return time.time() - t0
        time.sleep(0.5)
    return None


def phase9(ctx, out_dir):
    out("\n=== P9 .uno:SaveAll routing ===")
    desktop = ctx.ServiceManager.createInstanceWithContext(
        "com.sun.star.frame.Desktop", ctx)
    paths, frames, docs = [], [], []
    for idx in (1, 2):
        doc = new_writer_doc(desktop)
        set_text(doc, "CipherBox spike P9 doc%d base" % idx)
        path = os.path.join(out_dir, "p9-doc%d.docx" % idx)
        doc.storeToURL(uno.systemPathToFileUrl(path), (pv("FilterName", FILTER_DOCX),))
        doc.Text.setString("CipherBox spike P9 doc%d EDITED 9999" % idx)
        paths.append(path)
        frames.append(doc.CurrentController.Frame)
        docs.append(doc)

    # A. Bare capability: does headless SaveAll save anything at all (no interceptor)?
    dispatch_via_helper(ctx, frames[0], ".uno:SaveAll")
    settled = _settle_modified(docs)
    saved_a = [not bool(d.isModified()) for d in docs]
    note("P9a headless SaveAll WITHOUT interceptor (frame-routed)",
         "saved=%s settle=%s" % (saved_a, "%.2fs" % settled if settled is not None else ">5s never"))
    if not any(saved_a):
        # desktop-routed variant: the Desktop is itself an XDispatchProvider.
        dispatch_via_helper(ctx, desktop, ".uno:SaveAll")
        settled = _settle_modified(docs)
        saved_desktop = [not bool(d.isModified()) for d in docs]
        note("P9a headless SaveAll WITHOUT interceptor (desktop-routed)",
             "saved=%s settle=%s" % (saved_desktop, "%.2fs" % settled if settled is not None else ">5s never"))

    # B. Routing facts: interceptors on BOTH frames, docs re-modified.
    for idx, d in enumerate(docs, 1):
        d.Text.setString("CipherBox spike P9 doc%d base" % idx)
        d.storeToURL(uno.systemPathToFileUrl(paths[idx - 1]), (pv("FilterName", FILTER_DOCX),))
        d.Text.setString("CipherBox spike P9 doc%d EDITED 9999" % idx)

    def passthrough(self_, url, args):
        self_.delegate(url, args)

    interceptors = []
    for frame in frames:
        ic = Interceptor(capture={".uno:SaveAll", ".uno:Save", ".uno:SaveAs"},
                         on_dispatch=passthrough)
        register(frame, ic)
        interceptors.append(ic)

    dispatch_via_helper(ctx, frames[0], ".uno:SaveAll")
    _settle_modified(docs)
    seen_q = [".uno:SaveAll" in ic.queries for ic in interceptors]
    seen_d = [".uno:SaveAll" in ic.dispatches for ic in interceptors]
    seen_save = [".uno:Save" in ic.dispatches for ic in interceptors]
    note("P9b SaveAll queryDispatch seen per frame", str(seen_q))
    note("P9b SaveAll dispatch seen per frame", str(seen_d))
    note("P9b per-doc .uno:Save dispatch seen per frame", str(seen_save))
    check("P9 SaveAll traverses ONLY the frame chain it was dispatched on "
          "(single-frame routing, not broadcast)", seen_q == [True, False] and seen_d == [True, False],
          "q=%s d=%s" % (seen_q, seen_d))
    check("P9 per-document stores do NOT traverse any frame dispatch chain",
          not any(seen_save), str(seen_save))
    saved_b = [not bool(d.isModified()) for d in docs]
    note("P9b delegated SaveAll saved docs", str(saved_b))
    for idx in (0, 1):
        if saved_b[idx]:
            with open(paths[idx], "rb") as fh:
                check("P9 doc%d product carries the edit (real save)" % (idx + 1),
                      b"EDITED 9999" in fh.read())
    for frame, ic in zip(frames, interceptors):
        release(frame, ic)
    for d in docs:
        close_doc(d)
    out("PROBE P9 SaveAll routing: see PASS/FAIL above")


PHASES = {1: phase1, 2: phase2, 3: phase3, 4: phase4, 5: phase5,
          6: phase6, 7: phase7, 8: phase8, 9: phase9}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", type=int, required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    os.makedirs(args.out, exist_ok=True)
    out("spike_interceptor phase %d; products in %s" % (args.phase, args.out))
    ctx = connect(args.url)
    PHASES[args.phase](ctx, args.out)
    out("")
    if FAILURES:
        out("RESULT: FAIL (%d) -> %s" % (len(FAILURES), ", ".join(FAILURES)))
        return 1
    out("RESULT: PASS phase %d" % args.phase)
    return 0


if __name__ == "__main__":
    sys.exit(main())
