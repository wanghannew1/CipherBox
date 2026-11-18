"""LibreOffice UNO interceptor: "strong encryption save" (plan todo 17/18).

A forced OOXML save carries the media-descriptor ``Password`` AND
``EncryptionData`` {CryptoType="CipherBoxDataSpace", Password} -- payload
proven by spike P2a / e2e_full.  Non-OOXML targets and the export/send family
are audited ``export_plaintext``; no key -> fail-closed refusal.

Live facts this design is built around (all 2026-11-18, LO 26 real machine):

* **The dispatch callback may not touch the office model.**  LO's main
  thread is blocked inside ``dispatch()`` waiting for the interceptor to
  return; a model API call from here (a content-hash ``storeToURL``) or a
  save that needs the main thread deadlocks the office instantly.  Every
  payload save, hash and audit therefore runs on a deferred worker thread
  that starts after the callback returned; the only inline office
  interaction left is a payload-less ``_delegate`` (proven 0.1 s).
* **Dispatching a payload save is unreliable.**  A payload-less delegate
  works, the identical delegate WITH Password/EncryptionData hangs or
  silently writes nothing (live).  The forced save therefore does NOT go
  through the dispatch chain at all: it is a plain ``model.storeToURL`` to
  ``<target>.part.<ext>`` followed by an atomic ``os.replace`` to
  ``<target>.cbx`` -- the exact agent.uno_driver-proven shape (LO rejects
  stores to unknown extensions like ``.cbx`` with Io Write/Code 16, so the
  part file carries the original extension; it is CIPHERTEXT, so its brief
  visibility is harmless).
* **The native SaveAs dialog discards an injected payload.**  The dialog
  flow (``.uno:SaveAs`` without URL argument) re-collects its media
  descriptor after the dialog closes, so a payload injected at dispatch time
  is lost and the file lands PLAINTEXT (the 1-3 s watcher window the user
  saw).  The dialog flow therefore runs its OWN file picker on the deferred
  thread and performs the same encrypted snapshot -- the file lands on disk
  already encrypted, no plaintext window.
* **Snapshot semantics.**  A forced save does not switch the session
  medium: the document keeps editing the session temp, whose write-back is
  the session close's re-encrypt; the picked target receives a point-in-time
  encrypted snapshot under the ``<name>.cbx`` convention.  In-place saves
  (``.uno:Save``/``.uno:SaveAll`` without URL) ALWAYS delegate clean --
  they write the temp plaintext itself and must never carry EncryptionData.
* **OOXML/``.cbx`` targets are always encrypted, never passed through.**
  The old P7 pass-through assumed a cipherbox-bound medium, but the
  interceptor only ever runs inside a controlled session whose medium is
  the PLAINTEXT temp; pass-through produced a plaintext file named ``.cbx``
  -- which the agent's watcher EXCLUDES by suffix, i.e. a permanent
  plaintext escape (live hole).

Agent entry point: ``register_on_frame(frame, password_provider)`` from any
pyuno process.  Requires PyUNO.
"""

from __future__ import annotations

import hashlib
import os
import re
import threading
import time
from urllib.parse import unquote
from typing import Any, Callable

import uno
import unohelper
from com.sun.star.beans import NamedValue, PropertyValue
from com.sun.star.frame import XDispatch, XDispatchProviderInterceptor
from com.sun.star.lang import XInitialization, XServiceInfo

SERVICE_NAME = "com.sun.star.comp.cipherbox.ForceEncryptInterceptor"
IMPLEMENTATION_NAME = "com.sun.star.comp.cipherbox.ForceEncryptInterceptorImpl"

CRYPTO_TYPE = "CipherBoxDataSpace"
ENCRYPT_ACTION = "encrypt"
PLAINTEXT_ACTION = "export_plaintext"

# Grace before the deferred thread touches the office: the dispatch callback
# must have returned (main thread free) first.
DEFER_GRACE_S = 0.3

# Dispatches whose target may be an OOXML save (candidates for forced encrypt).
FORCE_ENCRYPT_DISPATCHES = frozenset({
    ".uno:Save", ".uno:SaveAs", ".uno:SaveACopy", ".uno:SaveAll",
})

# SaveAs family: the target is a NEW location.  A dialog flow (no URL
# argument) never reaches the slave with an injected payload (see module
# docstring) -- it gets the deferred picker + encrypted snapshot instead.
SAVE_AS_FAMILY = frozenset({".uno:SaveAs", ".uno:SaveACopy"})

# Export/send family: never encryptable via EncryptionData (spike P8 -- none
# of these slots honours it), so audit as plaintext and pass through.
EXPORT_DISPATCHES = frozenset({
    ".uno:ExportTo", ".uno:ExportToPDF", ".uno:ExportDirectToPDF",
    ".uno:Print", ".uno:PrintDefault", ".uno:SendMail", ".uno:SendDocAsPDF",
})

# Forced-encrypt target formats (task scope: OOXML only).
OOXML_EXTENSIONS = frozenset({"docx", "xlsx", "pptx"})

# Native round-trip filter per document kind, used to serialize the current
# document into an in-memory stream for the audit content hash.
NATIVE_FILTERS = {
    "com.sun.star.text.TextDocument": "writer8",
    "com.sun.star.sheet.SpreadsheetDocument": "calc8",
    "com.sun.star.presentation.PresentationDocument": "impress8",
}

# OOXML save filter per extension (keys are dot-less: _target_extension()
# returns the bare extension).  Explicit FilterName is required for
# storeToURL to a part file whose own extension may differ.
FILTER_BY_EXT = {
    "docx": "MS Word 2007 XML",
    "xlsx": "Calc MS Excel 2007 XML",
    "pptx": "Impress MS PowerPoint 2007 XML",
}

# Picker labels per extension (also the current-filter names).
FILTER_LABELS = {
    "docx": "Word OOXML (*.docx)",
    "xlsx": "Excel OOXML (*.xlsx)",
    "pptx": "PowerPoint OOXML (*.pptx)",
}


# ---------------------------------------------------------------------------
# descriptor helpers -- the proven payload shapes
# ---------------------------------------------------------------------------

def _pv(name: str, value) -> PropertyValue:
    p = PropertyValue()
    p.Name = name
    p.Value = value
    return p


def _nv(name: str, value) -> NamedValue:
    n = NamedValue()
    n.Name = name
    n.Value = value
    return n


def _make_encryption_data(password: str) -> Any:
    """EncryptionData exactly as proven on LO 26.8 (spike P2a, e2e_full): an
    uno.Any typed []com.sun.star.beans.NamedValue with BOTH CryptoType
    (routes oox to the CipherBoxDataSpace engine) AND Password -- the defect
    never bound the password.
    """
    return uno.Any(
        "[]com.sun.star.beans.NamedValue",
        (_nv("CryptoType", CRYPTO_TYPE), _nv("Password", password)),
    )


def _target_extension(url: str) -> str:
    """Lower-case file extension of a (file) URL; '' when it has none."""
    path = url.split("?", 1)[0].split("#", 1)[0]
    name = path.rsplit("/", 1)[-1]
    if "." not in name:
        return ""
    return name.rsplit(".", 1)[1].lower()


def _default_spawn(fn: Callable[[], None]) -> None:
    threading.Thread(target=fn, daemon=True).start()


# ---------------------------------------------------------------------------
# interceptor component
# ---------------------------------------------------------------------------

class ForceEncryptInterceptor(unohelper.Base,
                              XDispatchProviderInterceptor,
                              XDispatch,
                              XServiceInfo,
                              XInitialization):
    """Per-frame interceptor (spike P3: interception is strictly per-frame).

    Claims the save/export families in queryDispatch (cheap -- that call also
    carries constant status-polling traffic, P3); decides in dispatch().
    """

    def __init__(self, ctx, *, spawn: Callable[[Callable[[], None]], None] | None = None,
                 pick_save_target: Callable[[], "str | None"] | None = None):
        self._ctx = ctx
        self._frame = None
        self._slave = None
        self._master = None
        self._registered = False
        self._password_provider = None
        self._audit_reporter = None
        self._guard_url = None
        # Seams for tests: spawn runs deferred jobs (production: a daemon
        # thread; tests: synchronous), pick_save_target replaces the modal
        # FilePicker (production path; tests: canned URL / None).
        self._spawn = spawn or _default_spawn
        self._pick_save_target = pick_save_target or self._pick_save_target_native

    # -- wiring ---------------------------------------------------------

    def attach(self, frame) -> None:
        """Bind to a frame: the wrapped provider + the interception point."""
        self._frame = frame

    def set_guard(self, directory: str) -> None:
        """Fail-closed guard directory (the session temp dir): save targets
        resolved to a URL under it are REFUSED (audited ok=False) instead of
        written there -- 堵 LO SaveAs/Export 把副本落进会话 scratch 目录后被
        收尾清理蒸发 (todo 17 ③ temp 规则).
        """
        if not directory:
            self._guard_url = None
            return
        try:
            url = uno.systemPathToFileUrl(os.path.abspath(directory))
        except Exception:
            self._guard_url = None
            return
        self._guard_url = url.replace("\\", "/").rstrip("/").lower() + "/"

    def set_password_provider(self, provider) -> None:
        self._password_provider = provider

    def set_audit_reporter(self, reporter) -> None:
        self._audit_reporter = reporter

    def register(self) -> None:
        """Push onto the frame's interceptor chain (loud on failure)."""
        if self._frame is not None and not self._registered:
            self._frame.registerDispatchProviderInterceptor(self)
            self._registered = True

    def release(self) -> None:
        if self._frame is not None and self._registered:
            self._registered = False
            self._frame.releaseDispatchProviderInterceptor(self)

    # -- XServiceInfo -----------------------------------------------------

    def getImplementationName(self) -> str:
        return IMPLEMENTATION_NAME

    def supportsService(self, name: str) -> bool:
        return name == SERVICE_NAME

    def getSupportedServiceNames(self) -> tuple:
        return (SERVICE_NAME,)

    # -- XInitialization (pythonloader deployment path) --------------------

    def initialize(self, arguments: tuple) -> None:
        """arguments[0] is the frame to wrap."""
        if len(arguments) >= 1:
            self._frame = arguments[0]

    # -- XDispatchProvider (chain view) ------------------------------------

    def queryDispatch(self, url, target_frame_name, search_flags):
        if url.Complete in FORCE_ENCRYPT_DISPATCHES or url.Complete in EXPORT_DISPATCHES:
            return self
        if self._slave is not None:
            return self._slave.queryDispatch(url, target_frame_name, search_flags)
        return None

    def queryDispatches(self, requests):
        return tuple(
            self.queryDispatch(r.FeatureURL, r.TargetFrameName, r.SearchFlags)
            for r in requests)

    # -- XDispatchProviderInterceptor chain hooks ---------------------------

    def getSlaveDispatchProvider(self):
        return self._slave

    def setSlaveDispatchProvider(self, provider):
        self._slave = provider

    def getMasterDispatchProvider(self):
        return self._master

    def setMasterDispatchProvider(self, supplier):
        self._master = supplier

    # -- XDispatch (entry point for claimed dispatches) ----------------------

    def dispatch(self, url, arguments) -> None:
        # INVARIANT: this callback must return quickly and must not touch the
        # office model (deadlock, see module docstring).  A payload-less
        # _delegate is the only office interaction allowed inline.
        if url.Complete in EXPORT_DISPATCHES:
            self._delegate(url, arguments)
            self._audit_deferred(PLAINTEXT_ACTION, True)
            return
        self._dispatch_save(url, arguments)

    def addStatusListener(self, listener, url) -> None:
        pass  # status-polling noise only (spike P3); no state to report

    def removeStatusListener(self, listener, url) -> None:
        pass

    # -- save routing ---------------------------------------------------------

    def _dispatch_save(self, url, arguments) -> None:
        url_arg = self._target_url_arg(arguments)
        if url_arg:
            extension = _target_extension(url_arg)
            if self._under_guard(url_arg):
                # temp escape refused: no copy of the document may land in
                # the session scratch dir where cleanup would evaporate it.
                self.report_audit(ENCRYPT_ACTION, "", None, False)
                return
            if extension in OOXML_EXTENSIONS or extension == "cbx":
                # encrypted snapshot, off the callback (deadlock + dispatch
                # payload unreliability, see module docstring); returns
                # BEFORE the file exists -- callers must not assume sync.
                self._spawn(lambda: self._snapshot_save_async(url_arg))
                return
            # .odt/.pdf/.txt/... target: plaintext family, native save.
            self._delegate(url, arguments)
            self._audit_deferred(PLAINTEXT_ACTION, True)
            return
        if url.Complete in SAVE_AS_FAMILY:
            self._spawn(lambda: self._dialog_save_async(url))
            return
        # .uno:Save / .uno:SaveAll with no URL argument: target IS the
        # current medium (the session temp plaintext) -> NEVER inject;
        # write-back of the temp is the session close's re-encrypt.
        self._delegate(url, arguments)

    # -- deferred save paths (office main thread is free here) ---------------

    def _dialog_save_async(self, url) -> None:
        """The dialog flow's real save, on the deferred thread: run the
        picker, then the encrypted snapshot.  Cancel == no save, no audit
        (parity with a native dialog cancel); failures are fail-closed and
        audited.  Plaintext-family picks (odt/pdf/...) save natively."""
        time.sleep(DEFER_GRACE_S)
        try:
            picked = self._pick_save_target()
        except Exception:
            self.report_audit(ENCRYPT_ACTION, "", None, False)
            return
        if not picked:
            return  # user cancelled
        extension = _target_extension(picked)
        if extension in OOXML_EXTENSIONS or extension == "cbx":
            if self._under_guard(picked):
                self.report_audit(ENCRYPT_ACTION, "", None, False)
                return
            try:
                self._snapshot_save(picked)
            except Exception as exc:
                self.report_audit(ENCRYPT_ACTION, "ERR: " + repr(exc)[:56],
                                  None, False)
            return
        try:
            self._delegate(url, (_pv("URL", picked),))
        except Exception:
            pass
        self._audit_deferred(PLAINTEXT_ACTION, True)

    def _snapshot_save_async(self, target_url) -> None:
        """Explicit-URL encrypted snapshot (deferred thread)."""
        time.sleep(DEFER_GRACE_S)
        try:
            self._snapshot_save(target_url)
        except Exception as exc:
            self.report_audit(ENCRYPT_ACTION, "ERR: " + repr(exc)[:56],
                              None, False)

    def _snapshot_save(self, target_url) -> None:
        """Encrypted snapshot of the CURRENT document to ``target_url``.

        OOXML targets gain the ``.cbx`` suffix (``report.docx`` ->
        ``report.docx.cbx``, the project convention that keeps double-click
        association working); explicit ``.cbx`` targets are kept as-is.  The
        write is ``storeToURL`` to ``<final>.part.<src-ext>`` + atomic
        ``os.replace`` (the uno_driver-proven shape).
        """
        password = self.get_master_key()
        if password is None:
            # fail-closed: no key -> refuse the save entirely.
            self.report_audit(ENCRYPT_ACTION, "", None, False)
            return
        model = self._doc_model()
        if model is None:
            self.report_audit(ENCRYPT_ACTION, "", None, False)
            return
        extension = _target_extension(target_url)
        if extension == "cbx":
            final_url = target_url
            filter_name = self._native_filter(model) or "MS Word 2007 XML"
            src_ext = self._source_extension(model) or "docx"
        else:
            final_url = target_url + ".cbx"
            filter_name = FILTER_BY_EXT[extension]
            src_ext = extension
        final_path = self._url_to_path(final_url)
        part_path = final_path + ".part." + src_ext
        model.storeToURL(uno.systemPathToFileUrl(part_path), (
            _pv("FilterName", filter_name),
            _pv("Password", password),
            _pv("EncryptionData", _make_encryption_data(password)),
        ))
        digest = self.current_doc_hash()
        try:
            os.replace(part_path, final_path)
        except OSError as exc:
            try:
                os.remove(part_path)
            except OSError:
                pass
            self.report_audit(ENCRYPT_ACTION, "ERR: " + repr(exc)[:56],
                              None, False)
            return
        self.report_audit(ENCRYPT_ACTION, digest, None, True)

    # -- picker ---------------------------------------------------------------

    def _pick_save_target_native(self) -> "str | None":
        """Modal FilePicker on the office main thread (deferred thread only).

        Returns the picked file URL, or None on cancel.  Defaults to the
        confidential volume root (the session temp dir is no save target).
        """
        template = uno.getConstantByName(
            "com.sun.star.ui.dialogs.TemplateDescription.FILESAVE_AUTOEXTENSION")
        picker = self._ctx.ServiceManager.createInstanceWithArgumentsAndContext(
            "com.sun.star.ui.dialogs.FilePicker", (template,), self._ctx)
        for label in FILTER_LABELS.values():
            picker.appendFilter(label, label.rsplit("(", 1)[1].rstrip(")"))
        picker.appendFilter("All files (*.*)", "*.*")
        default_ext = self._set_picker_context(picker)
        result = picker.execute()
        if result != uno.getConstantByName(
                "com.sun.star.ui.dialogs.ExecutableDialogResults.OK"):
            return None
        files = picker.getSelectedFiles()
        if not files:
            return None
        picked = str(files[0])
        if "." not in picked.rsplit("/", 1)[-1] and default_ext:
            picked += default_ext  # auto-extension when the user typed none
        return picked

    def _set_picker_context(self, picker) -> str:
        """Title, default dir (volume root), default name/filter; returns the
        source document's extension ('' when unknown)."""
        try:
            picker.setTitle("另存为（保存即加密）")
        except Exception:
            pass
        model = self._doc_model()
        if model is None:
            return ""
        try:
            url = model.getURL()
        except Exception:
            return ""
        match = re.match(r"^file:///([^/]+)/", url)
        if match:
            try:
                picker.setDisplayDirectory("file:///" + match.group(1))
            except Exception:
                pass
        name = unquote(url.rsplit("/", 1)[-1]) if "/" in url else ""
        extension = ""
        if "." in name:
            extension = name.rsplit(".", 1)[1].lower()
        label = FILTER_LABELS.get(extension)
        if label is not None:
            try:
                picker.setCurrentFilter(label)
            except Exception:
                pass
        if name:
            try:
                picker.setDefaultName(name)
            except Exception:
                pass
        return "." + extension if extension else ""

    # -- key + audit -------------------------------------------------------

    def get_master_key(self) -> str | None:
        """Current master-key password from the provider; None = fail closed."""
        provider = self._password_provider
        if provider is None:
            return None
        return provider if isinstance(provider, str) else provider()

    def report_audit(self, action: str, file_hash: str,
                     key_version: int | None, ok: bool) -> None:
        if self._audit_reporter is not None:
            self._audit_reporter(action, file_hash, key_version, ok)

    def _audit_deferred(self, action: str, ok: bool) -> None:
        """Audit AFTER the dispatch callback returned (hash needs the model;
        a model call inside the callback deadlocks the office)."""
        def run():
            time.sleep(DEFER_GRACE_S)
            try:
                digest = self.current_doc_hash()
            except Exception:
                digest = ""
            self.report_audit(action, digest, None, ok)
        self._spawn(run)

    # -- document content hash (plan todo 18) ---------------------------------

    def current_doc_hash(self) -> str:
        """sha256 of the CURRENT document content (todo 18): serialized in its
        native format into an in-memory stream via storeToURL("private:stream")
        -- no disk round trip, medium untouched (P2b).  NEVER call from inside
        the dispatch callback (deadlock).  Best-effort: failure yields "".
        """
        try:
            model = self._doc_model()
            if model is None:
                return ""
            sink = self._ctx.ServiceManager.createInstanceWithContext(
                "com.sun.star.io.SequenceOutputStream", self._ctx)
            model.storeToURL("private:stream", (
                _pv("OutputStream", sink),
                _pv("FilterName", self._native_filter(model)),
            ))
            return hashlib.sha256(
                bytes(bytearray(sink.getWrittenBytes()))).hexdigest()
        except Exception:
            return ""

    # -- small helpers ---------------------------------------------------------

    def _doc_model(self):
        if self._frame is None:
            return None
        controller = self._frame.getController()
        return controller.getModel() if controller is not None else None

    def _source_extension(self, model) -> str:
        try:
            return _target_extension(model.getURL())
        except Exception:
            return ""

    @staticmethod
    def _native_filter(model) -> str:
        for argument in model.getArgs():
            if getattr(argument, "Name", "") == "FilterName":
                value = getattr(argument, "Value", "") or ""
                if value:
                    return str(value)
        for service, filter_name in NATIVE_FILTERS.items():
            if model.supportsService(service):
                return filter_name
        return ""

    def _target_url_arg(self, arguments) -> str:
        """Explicit ``URL`` media-descriptor argument; '' when absent (dialog
        flow).  Deliberately NOT the model URL: that is the source medium, and
        deciding SaveAs on it would corrupt the temp-plaintext write-back."""
        for argument in arguments:
            if getattr(argument, "Name", "") == "URL":
                return str(getattr(argument, "Value", "") or "")
        return ""

    def _under_guard(self, url: str) -> bool:
        """True when a target file URL is inside the guarded (session temp)
        directory.  Prefix compare on normalized file URLs; no guard set or a
        non-file URL never matches."""
        if not self._guard_url or not url:
            return False
        normalized = url.replace("\\", "/").rstrip("/").lower()
        if not normalized.startswith("file:"):
            return False
        return normalized.startswith(self._guard_url) or normalized + "/" == self._guard_url

    def _delegate(self, url, arguments) -> None:
        """Forward to the slave chain (spike P2a delegate pattern)."""
        if self._slave is None:
            raise RuntimeError("interceptor chain has no slave provider")
        target = self._slave.queryDispatch(url, "", 0)
        if target is None:
            raise RuntimeError("slave refused dispatch: %s" % url.Complete)
        target.dispatch(url, arguments)

    @staticmethod
    def _url_to_path(url: str) -> str:
        """Local filesystem path of a ``file:///`` URL (local drives only;
        the interceptor's targets are volumes the user picked in the picker).
        """
        path = unquote(url)
        if path.startswith("file:///"):
            path = path[len("file:///"):]
        elif path.startswith("file:"):
            path = path[len("file:"):]
        return path.replace("/", os.sep)


# ---------------------------------------------------------------------------
# Agent entry point
# ---------------------------------------------------------------------------

def register_on_frame(frame, password_provider, audit_reporter=None):
    """Register a ForceEncryptInterceptor on ONE frame's dispatch chain.

    Callable from any pyuno process (the Agent's entry point): ``frame`` is
    the document's XFrame; ``password_provider`` supplies the master-key
    password at every forced save (zero-arg callable or constant str; None ->
    fail-closed refusal, audited ok=False); ``audit_reporter`` is an optional
    ``(action, file_hash, key_version, ok)`` callback.  The interceptor lives
    in the CALLING process; LO calls back across the pipe bridge (spike P5).
    Returns the instance; ``release()`` unregisters.
    """
    interceptor = ForceEncryptInterceptor(uno.getComponentContext())
    interceptor.attach(frame)
    interceptor.set_password_provider(password_provider)
    if audit_reporter is not None:
        interceptor.set_audit_reporter(audit_reporter)
    interceptor.register()
    return interceptor


# ---------------------------------------------------------------------------
# component factory (pythonloader deployment path)
# ---------------------------------------------------------------------------

class _ComponentFactory(unohelper.Base):
    """XSingleServiceFactory for the interceptor component."""

    def __init__(self, service_manager=None):
        self._smgr = service_manager

    def createInstance(self):
        return ForceEncryptInterceptor(uno.getComponentContext())

    def createInstanceWithArguments(self, arguments):
        return ForceEncryptInterceptor(uno.getComponentContext())


def getComponentFactory(implementationName, service_manager, reg_key):
    """Entry point used by the Python component loader."""
    if implementationName != IMPLEMENTATION_NAME:
        return None
    return _ComponentFactory(service_manager)


# For `program/pythonloader.py` __getattr__ hook.
def __getattr__(name):
    if name.startswith("_"):
        raise AttributeError(name)
    return _ComponentFactory()
