"""LibreOffice UNO interceptor: "strong encryption save" (plan todo 17/18 minimal).

A forced OOXML save carries the media-descriptor ``Password`` AND
``EncryptionData`` {CryptoType="CipherBoxDataSpace", Password} -- payload
proven by spike P2a / e2e_full.  Non-OOXML targets and the export/send family
are audited ``export_plaintext`` with the current document's content sha256
(todo 18); ``.cbx`` targets pass through (spike P7); no key -> fail-closed
refusal.  The interceptor claims save/export dispatches in ``queryDispatch``
and implements ``XDispatch`` itself (spike-proven shape --
``XDispatchProviderInterceptor`` has no ``interceptDispatch`` member).
Agent entry point: ``register_on_frame(frame, password_provider)`` from any
pyuno process (spike P5).  Requires PyUNO.
"""

from __future__ import annotations

import hashlib
from typing import Any

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

# Dispatches whose target may be an OOXML save (candidates for forced encrypt).
FORCE_ENCRYPT_DISPATCHES = frozenset({
    ".uno:Save", ".uno:SaveAs", ".uno:SaveACopy", ".uno:SaveAll",
})

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

    def __init__(self, ctx):
        self._ctx = ctx
        self._frame = None
        self._slave = None
        self._master = None
        self._registered = False
        self._password_provider = None
        self._audit_reporter = None

    # -- wiring ---------------------------------------------------------

    def attach(self, frame) -> None:
        """Bind to a frame: the wrapped provider + the interception point."""
        self._frame = frame

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
        if url.Complete in EXPORT_DISPATCHES:
            self.report_audit(PLAINTEXT_ACTION, self.current_doc_hash(), None, True)
            self._delegate(url, arguments)
            return
        self._dispatch_save(url, arguments)

    def addStatusListener(self, listener, url) -> None:
        pass  # status-polling noise only (spike P3); no state to report

    def removeStatusListener(self, listener, url) -> None:
        pass

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

    # -- internal dispatch paths ---------------------------------------------

    def _dispatch_save(self, url, arguments) -> None:
        extension = _target_extension(self._save_target_url(arguments))
        if extension == "cbx":
            # P7: a CipherBox-bound medium keeps Password+EncryptionData;
            # .uno:Save delegated unchanged stays CFB, never plaintext.
            self._delegate(url, arguments)
            return
        if extension not in OOXML_EXTENSIONS:
            # .odt/.pdf/.txt/... or no resolvable target: plaintext family.
            self.report_audit(PLAINTEXT_ACTION, self.current_doc_hash(), None, True)
            self._delegate(url, arguments)
            return
        password = self.get_master_key()
        if password is None:
            # fail-closed: no key -> refuse the OOXML save entirely.
            self.report_audit(ENCRYPT_ACTION, "", None, False)
            return
        plaintext_hash = self.current_doc_hash()
        self._delegate(url, arguments + (
            _pv("Password", password),
            _pv("EncryptionData", _make_encryption_data(password)),
        ))
        self.report_audit(ENCRYPT_ACTION, plaintext_hash, None, True)

    def _save_target_url(self, arguments) -> str:
        for argument in arguments:
            if getattr(argument, "Name", "") == "URL":
                return str(getattr(argument, "Value", "") or "")
        model = self._doc_model()
        return model.getURL() if model is not None else ""

    def _delegate(self, url, arguments) -> None:
        """Forward to the slave chain (spike P2a delegate pattern)."""
        if self._slave is None:
            raise RuntimeError("interceptor chain has no slave provider")
        target = self._slave.queryDispatch(url, "", 0)
        if target is None:
            raise RuntimeError("slave refused dispatch: %s" % url.Complete)
        target.dispatch(url, arguments)

    # -- document content hash (plan todo 18) ---------------------------------

    def current_doc_hash(self) -> str:
        """sha256 of the CURRENT document content (todo 18): serialized in its
        native format into an in-memory SequenceOutputStream via
        storeToURL("private:stream") -- no disk round trip, medium untouched
        (P2b).  Best-effort: failure yields "" (the audit still records).
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

    def _doc_model(self):
        if self._frame is None:
            return None
        controller = self._frame.getController()
        return controller.getModel() if controller is not None else None

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
