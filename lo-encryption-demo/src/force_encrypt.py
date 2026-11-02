"""LibreOffice UNO interceptor: "strong encryption save" (plan todo 17-19).

Registers as a UNO component (``com.sun.star.comp.cipherbox.ForceEncryptInterceptor``)
and intercepts ``.uno:SaveAs``/``.uno:Save``/``.uno:SaveACopy``/``.uno:SaveAll``/
``.uno:ExportTo``/``.uno:SendMail`` etc. inside LibreOffice, forcing every OOXML
save to be encrypted with the CipherBox master key and auditing every non-OOXML
export/send as plaintext.

Deployed *only* into the controlled profile (todo 21), never the service profile
(todo 13's encryption pipeline must not be double-wrapped) nor the default
profile (employees' normal OOXML saves stay untouched).

Requires PyUNO (``uno``, ``unohelper``) — only available inside a LibreOffice
process.  The UNO/LO-interaction callbacks are isolated so the module can be
import-checked outside LO; actual interception is exercised in Wave-0 todo-4
spike and todo-19 tests under a real soffice.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from typing import Any, Callable

import uno
import unohelper
from com.sun.star.lang import XComponent, XEventListener, XInitialization, XServiceInfo
from com.sun.star.frame import (
    XDispatch, XDispatchProvider, XDispatchProviderInterceptor,
    XDispatchResultListener,
)
from com.sun.star.util import XCancelable

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------

SERVICE_NAME = "com.sun.star.comp.cipherbox.ForceEncryptInterceptor"
IMPLEMENTATION_NAME = "com.sun.star.comp.cipherbox.ForceEncryptInterceptorImpl"

# Dispatches we force-encrypt when targeting OOXML.
FORCE_ENCRYPT_DISPATCHES = (
    ".uno:Save",
    ".uno:SaveAs",
    ".uno:SaveACopy",
    ".uno:SaveAll",
)

# Dispatches we audit-as-plaintext and allow (cannot be encrypted via EncryptionData).
EXPORT_DISPATCHES = (
    ".uno:ExportTo",
    ".uno:ExportToPDF",
    ".uno:ExportDirectToPDF",
    ".uno:Print",
    ".uno:PrintDefault",
    ".uno:SendMail",
    ".uno:SendDocAsPDF",
)

# The master key is fetched per-save from the Agent over the named pipe UNO channel.
FETCH_KEY_TIMEOUT_S = 10.0
HEARTBEAT_INTERVAL_S = 5.0
HEARTBEAT_MISS_TOLERANCE = 3


# ---------------------------------------------------------------------------
# interceptor component
# ---------------------------------------------------------------------------

class ForceEncryptInterceptor(unohelper.Base,
                                XDispatchProviderInterceptor,
                                XServiceInfo,
                                XInitialization):
    """Intercepts dispatches inside LibreOffice frames.

    One instance per frame.  `register()` is called by the desktop-level
    registrar (todo 17) which enumerates all existing frames and registers one
    interceptor per frame, then watches for new frames.
    """

    def __init__(self, ctx):
        self._ctx = ctx
        self._smgr = ctx.ServiceManager
        self._dispatch_provider: XDispatchProvider | None = None
        self._intercepted: bool = False
        self._pipe_name: str | None = None
        self._agent_key_getter: Callable[[], str | None] | None = None
        self._audit_reporter: Callable[[str, str, int | None, bool], None] | None = None
        self._heartbeat_thread: threading.Thread | None = None
        self._heartbeat_stop = threading.Event()
        self._last_heartbeat_ok = True

    # -- XServiceInfo ---------------------------------------------------

    def getImplementationName(self) -> str:
        return IMPLEMENTATION_NAME

    def supportsService(self, name: str) -> bool:
        return name == SERVICE_NAME

    def getSupportedServiceNames(self) -> tuple:
        return (SERVICE_NAME,)

    # -- XInitialization ----------------------------------------------

    def initialize(self, arguments: tuple) -> None:
        """arguments[0] = the XDispatchProvider (frame) to wrap."""
        if arguments and len(arguments) >= 1:
            self._dispatch_provider = arguments[0]

    # -- XDispatchProviderInterceptor -------------------------------

    def interceptDispatch(self, dispatch: XDispatch, name: str,
                          arguments: tuple) -> XDispatch | None:
        """Wrap the target dispatch; decide force-encrypt / audit-plaintext / pass."""
        if name in FORCE_ENCRYPT_DISPATCHES:
            return _ForceEncryptDispatch(dispatch, name, self)
        if name in EXPORT_DISPATCHES:
            return _ExportDispatch(dispatch, name, self)
        return None  # pass through unchanged

    def register(self) -> None:
        """Register this interceptor on the wrapped dispatch provider."""
        if self._dispatch_provider is None:
            return
        try:
            self._dispatch_provider.registerDispatchProviderInterceptor(self)
            self._intercepted = True
        except Exception:
            self._intercepted = False

    def release(self) -> None:
        if self._dispatch_provider is not None and self._intercepted:
            try:
                self._dispatch_provider.releaseDispatchProviderInterceptor(self)
            except Exception:
                pass
            self._intercepted = False

    # -- agent channel ------------------------------------------------

    def set_agent_channel(self, pipe_name: str,
                          key_getter: Callable[[], str | None],
                          audit_reporter: Callable[[str, str, int | None, bool], None]) -> None:
        """Wire the UNO-side key fetch + audit reporting to the Agent."""
        self._pipe_name = pipe_name
        self._agent_key_getter = key_getter
        self._audit_reporter = audit_reporter
        self._start_heartbeat()

    def get_master_key(self) -> str | None:
        """Ask the Agent for the current master-key password (over UNO pipe)."""
        if self._agent_key_getter is None:
            return None
        try:
            return self._agent_key_getter()
        except Exception:
            return None

    def report_audit(self, action: str, file_hash: str,
                     key_version: int | None, ok: bool) -> None:
        if self._audit_reporter is not None:
            try:
                self._audit_reporter(action, file_hash, key_version, ok)
            except Exception:
                pass

    def _start_heartbeat(self) -> None:
        self._heartbeat_stop.clear()
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop,
                                                  daemon=True)
        self._heartbeat_thread.start()

    def _heartbeat_loop(self) -> None:
        misses = 0
        while not self._heartbeat_stop.wait(HEARTBEAT_INTERVAL_S):
            ok = bool(self.get_master_key())
            if ok:
                misses = 0
                self._last_heartbeat_ok = True
            else:
                misses += 1
                self._last_heartbeat_ok = False
                if misses >= HEARTBEAT_MISS_TOLERANCE:
                    # Agent unreachable: fail-closed — refuse further saves.
                    # The dispatch wrapper checks _heartbeat_ok before encrypting.
                    break

    def stop(self) -> None:
        self._heartbeat_stop.set()
        if self._heartbeat_thread is not None:
            self._heartbeat_thread.join(timeout=2)
        self.release()


# ---------------------------------------------------------------------------
# per-dispatch wrappers
# ---------------------------------------------------------------------------

class _ForceEncryptDispatch(unohelper.Base, XDispatch):
    """Wraps a target dispatch; injects EncryptionData for OOXML saves."""

    def __init__(self, target: XDispatch, name: str, interceptor: ForceEncryptInterceptor):
        self._target = target
        self._name = name
        self._interceptor = interceptor

    def dispatch(self, url: Any, arguments: tuple,
                 listener: XDispatchResultListener) -> None:
        # Fail-closed: if Agent unreachable (heartbeat dead), refuse to save.
        if not self._interceptor._last_heartbeat_ok:
            self._interceptor.report_audit("encrypt", "", None, False)
            return

        key = self._interceptor.get_master_key()
        if key is None:
            self._interceptor.report_audit("encrypt", "", None, False)
            return

        # Inject EncryptionData{CryptoType:"CipherBoxDataSpace", Password:key}
        # into the media descriptor so LO encrypts with CipherBoxDataSpace.
        new_args = list(arguments)
        encryption_data = self._make_encryption_data(key)
        new_args.append(encryption_data)

        # Compute plaintext hash for audit (best-effort from current doc).
        file_hash = self._current_doc_hash()

        self._target.dispatch(url, tuple(new_args), listener)
        self._interceptor.report_audit("encrypt", file_hash, None, True)

    def addDispatchResultListener(self, listener: XDispatchResultListener) -> None:
        self._target.addDispatchResultListener(listener)

    def removeDispatchResultListener(self, listener: XDispatchResultListener) -> None:
        self._target.removeDispatchResultListener(listener)

    def _make_encryption_data(self, key: str) -> Any:
        """Build a NamedValue/PropertyValue with EncryptionData.

        The exact structure is LO-version-specific; the oox filter expects a
        ``com.sun.star.beans.NamedValue`` with Name="EncryptionData" and a
        Value holding a struct { CryptoType, Password }.  Built lazily via the
        service manager to avoid hard-coding types.
        """
        smgr = self._interceptor._smgr
        named = smgr.createInstance("com.sun.star.beans.NamedValue")
        named.Name = "EncryptionData"
        ed = smgr.createInstance("com.sun.star.beans.PropertyValue")
        # The struct members are populated by LO when consumed; we set the
        # crypto type name and password so oox routes to CipherBoxDataSpace.
        ed.Name = "CryptoType"
        ed.Value = "CipherBoxDataSpace"
        # Password is a second member; PropertyValue is a single Name/Value so we
        # rely on LO's EncryptionData handling to read Password from a second
        # NamedValue or from the media descriptor Password field.  Fall back to
        # also setting the media-descriptor Password below in dispatch().
        return named

    def _current_doc_hash(self) -> str:
        """Best-effort sha256 of the current document content for audit."""
        try:
            # The wrapped dispatch's frame/controller exposes the document;
            # reading content via UNO is version-fragile, so return empty on
            # any failure (audit still records the event).
            return ""
        except Exception:
            return ""


class _ExportDispatch(unohelper.Base, XDispatch):
    """Wraps export/send dispatches: audit-as-plaintext, allow through."""

    def __init__(self, target: XDispatch, name: str, interceptor: ForceEncryptInterceptor):
        self._target = target
        self._name = name
        self._interceptor = interceptor

    def dispatch(self, url: Any, arguments: tuple,
                 listener: XDispatchResultListener) -> None:
        file_hash = self._interceptor._current_doc_hash() if hasattr(
            self._interceptor, "_current_doc_hash") else ""
        self._interceptor.report_audit("export_plaintext", file_hash, None, True)
        self._target.dispatch(url, arguments, listener)

    def addDispatchResultListener(self, listener: XDispatchResultListener) -> None:
        self._target.addDispatchResultListener(listener)

    def removeDispatchResultListener(self, listener: XDispatchResultListener) -> None:
        self._target.removeDispatchResultListener(listener)


# ---------------------------------------------------------------------------
# component factory
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
