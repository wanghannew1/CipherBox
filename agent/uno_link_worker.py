"""One link worker: interceptor registration + document load + close watch.

Runs under LibreOffice's bundled python (pyuno is version-locked there —
system python can never import uno, and LO's python lacks the resident
agent's dependencies), one process per controlled session.  Hard ordering
(todo 14 "先注册、后加载"): the temp plaintext is loaded via
``loadComponentFromURL`` only AFTER ``force_encrypt.register_on_frame``
succeeded on every existing frame; any earlier failure exits with
``{"ok": false}`` and the document is never opened (fail-closed — the agent
then aborts the whole session).

stdin:  one JSON object: the session-link spec (no secrets — the master key
        is fetched per forced save from the agent's link pipe, fail-closed
        when unavailable; audit events are reported the same way, with a
        volume-side JSONL fallback queue when the agent cannot be reached).
stdout: one JSON line per event (see agent/session_link.py for the protocol).

The new-frame watcher re-registers on frames that appear mid-session
(spike-approved mechanism: poll ``Desktop.Frames`` diff — there is no
FRAME_CREATED enumeration in the UNO API).
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path

_REPO_ROOT = str(Path(__file__).resolve().parents[1])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
_LO_SRC = os.path.join(_REPO_ROOT, "lo-encryption-demo", "src")
if _LO_SRC not in sys.path:
    sys.path.insert(0, _LO_SRC)

from agent.ipc import connect_and_request  # noqa: E402  (stdlib + ctypes only)

DESKTOP_SERVICE = "com.sun.star.frame.Desktop"
RESOLVER_SERVICE = "com.sun.star.bridge.UnoUrlResolver"
NO_UPDATE = 0  # com.sun.star.document.UpdateDocMode.NO_UPDATE
CONNECT_TIMEOUT_S = 60.0
# GUI soffice shows the Start Center first; immediately after launch the
# frame set can legitimately be EMPTY.  An instant hard failure here would
# kill this worker while interceptors are already wired into LO's dispatch
# chains — the GUI process then aborts on the next dispatch to the dead
# bridge (live 2026-11-17: 3x soffice.bin 0xc0000409/KERNELBASE aborts).
# Poll for a bounded window instead; <= 0 keeps the old instant-fail.
FRAMES_WAIT_TIMEOUT_S = 10.0
KEY_REQUEST_TIMEOUT_S = 5.0
AUDIT_REQUEST_TIMEOUT_S = 5.0
QUEUE_FILE_NAME = "link-audit.jsonl"
CLOSE_POLL_S = 0.5

REQUIRED_SPEC_KEYS = ("soffice_pipe", "doc_path", "agent_pipe", "queue_dir")


def _emit(payload: dict) -> None:
    print(json.dumps(payload, sort_keys=True), flush=True)


def _default_uno():
    import uno  # noqa: PLC0415 — exists only under LibreOffice's python
    return uno


def _default_force_encrypt():
    import force_encrypt  # noqa: PLC0415 — the interceptor (from _LO_SRC)
    return force_encrypt


class LinkWorker:
    """One session's interception lifecycle.  All LO/UNO touchpoints are
    injected (``uno``/``force_encrypt`` modules, ``requester``) so the
    orchestration is unit-testable without soffice."""

    def __init__(self, spec: dict, *, uno_module=None, force_encrypt_module=None,
                 requester=None, sleep=time.sleep,
                 connect_timeout_s: float = CONNECT_TIMEOUT_S,
                 frames_wait_timeout_s: float = FRAMES_WAIT_TIMEOUT_S,
                 emit=None) -> None:
        self.spec = spec
        self._uno_module = uno_module
        self._fe = force_encrypt_module
        self._requester = requester or connect_and_request
        self._sleep = sleep
        self.connect_timeout_s = connect_timeout_s
        self.frames_wait_timeout_s = frames_wait_timeout_s
        self._emit = emit or _emit
        self._stop = threading.Event()
        self._crashed = threading.Event()
        self._close_signals: list[threading.Event] = []
        self._close_detail = ""
        self._watcher: threading.Thread | None = None
        self._desktop = None
        self._registered_frames: list = []
        self._interceptors: list = []

    # -- module seams ---------------------------------------------------------

    def _uno(self):
        if self._uno_module is None:
            self._uno_module = _default_uno()
        return self._uno_module

    def _force_encrypt(self):
        if self._fe is None:
            self._fe = _default_force_encrypt()
        return self._fe

    # -- entry ------------------------------------------------------------------

    def run(self) -> int:
        uno = self._uno()
        fe = self._force_encrypt()
        try:
            ctx = self._connect(uno)
            self._desktop = ctx.ServiceManager.createInstanceWithContext(
                DESKTOP_SERVICE, ctx)
            frames = self._register_all(uno, fe)
            self._emit({"event": "registered", "frames": frames})
            doc = self._load(uno)
            self._emit({"event": "loaded"})
        except Exception as exc:  # worker boundary: any pre-load failure is fatal
            self._emit({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
            return 1
        self._watcher = threading.Thread(
            target=self._watch_frames, args=(uno, fe), name="link-frames", daemon=True)
        self._watcher.start()
        crashed = self._await_close(uno, doc)
        self._stop.set()
        self._terminate_office()
        if self._watcher is not None:
            self._watcher.join(timeout=5.0)
        closed = {"event": "closed", "crashed": crashed}
        if self._close_detail:
            closed["detail"] = self._close_detail
        self._emit(closed)
        return 0

    # -- phases -----------------------------------------------------------------

    def _connect(self, uno):
        """Bounded retry on the per-session soffice pipe (e2e_full pattern)."""
        local = uno.getComponentContext()
        resolver = local.ServiceManager.createInstanceWithContext(
            RESOLVER_SERVICE, local)
        url = "uno:pipe,name=%s;urp;StarOffice.ComponentContext" % self.spec["soffice_pipe"]
        deadline = time.monotonic() + self.connect_timeout_s
        last = None
        while time.monotonic() < deadline:
            if self._stop.is_set():
                raise RuntimeError("link worker stopped before connecting")
            try:
                return resolver.resolve(url)
            except Exception as exc:  # noqa: BLE001 — soffice not accepting yet
                last = exc
                self._sleep(1.0)
        raise RuntimeError(f"controlled soffice pipe unreachable: {last}")

    def _register_all(self, uno, fe) -> int:
        """Register the interceptor on every existing frame.

        A zero-frame sweep right after launch is a normal GUI race (the
        Start Center frame may not exist yet), not a hard failure — see
        FRAMES_WAIT_TIMEOUT_S.  ``frames_wait_timeout_s <= 0`` restores the
        old instant-fail semantics (used by unit tests).
        """
        deadline = time.monotonic() + self.frames_wait_timeout_s
        while True:
            newly = self._register_new_frames(uno, fe)
            if newly > 0:
                return newly
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    "no frames to intercept (soffice start center missing?)")
            if self._stop.is_set():
                raise RuntimeError("link worker stopped before any frame appeared")
            self._sleep(0.5)

    def _register_new_frames(self, uno, fe) -> int:
        """One sweep: register on frames not yet intercepted; return count."""
        newly = 0
        for frame in self._enumerate_frames():
            interceptor = fe.register_on_frame(
                frame, self._password_provider, self._audit_report)
            try:
                interceptor.set_guard(os.path.dirname(self.spec["doc_path"]))
            except AttributeError:
                pass  # older interceptor builds without the temp guard
            if self._slave_is_sibling(interceptor):
                # Live smoke P1 (2026-11-16, build 861effc5): queryFrames
                # yields FRESH client proxies on every poll, so ``frame is
                # known`` never matches and proxy-identity dedup would stack
                # an interceptor every 2 s.  The duplicate just registered
                # sits ABOVE our previous interceptor (its slave IS the old
                # chain head); a slave reporting our own implementation name
                # proves the frame is already intercepted -- drop it.
                try:
                    interceptor.release()
                except Exception:  # noqa: BLE001 — release is best-effort
                    pass
                continue
            self._registered_frames.append(frame)
            self._interceptors.append(interceptor)
            newly += 1
        return newly

    @staticmethod
    def _slave_is_sibling(interceptor) -> bool:
        """True when the chain head below us is another of OUR interceptors
        (the frame is already intercepted by this worker).  Probed through
        XServiceInfo.getImplementationName -- the string member that survives
        the bridge (live smoke P1: pyuno proxies expose ONLY UNO-declared
        members; a plain python method such as a token getter is invisible to
        the remote side)."""
        try:
            slave = interceptor.getSlaveDispatchProvider()
            name = getattr(slave, "getImplementationName", None)
            return bool(callable(name)) and (
                name() == interceptor.getImplementationName())
        except Exception:  # noqa: BLE001 — LO's own providers differ
            return False

    def _enumerate_frames(self) -> list:
        """Frames via ``getFrames().queryFrames(ALL)`` (spike P4, live-proven).
        XFrames is an XIndexAccess/queryFrames interface -- it has NO
        createEnumeration; the enumeration call raises AttributeError on a
        real desktop (fake-uno unit tests cannot see this)."""
        if self._desktop is None:
            return []
        flag = self._uno().getConstantByName(
            "com.sun.star.frame.FrameSearchFlag.ALL")
        return list(self._desktop.getFrames().queryFrames(flag))

    # identity note: frame dedup does NOT rely on proxy identity — the live
    # smoke (P1, 2026-11-16 build 861effc5) proved queryFrames hands out fresh
    # client proxies on every poll even over ONE bridge, so ``is`` never
    # matches.  Dedup goes through the interceptor chain instead: a fresh
    # registration whose slave reports our own implementation name
    # (XServiceInfo — the member class that survives the bridge) is released
    # immediately (see _register_new_frames).

    def _watch_frames(self, uno, fe) -> None:
        """Poll-diff Desktop.Frames; register interceptors on new frames."""
        interval = float(self.spec.get("poll_seconds") or 2.0)
        while not self._stop.wait(interval):
            try:
                self._register_new_frames(uno, fe)
            except Exception:  # noqa: BLE001 — bridge dying; close path takes over
                self._crashed.set()
                self._set_close()
                return

    def _load(self, uno):
        """loadComponentFromURL on the temp plaintext (NO_UPDATE)."""
        descriptor = uno.createUnoStruct("com.sun.star.beans.PropertyValue")
        descriptor.Name = "UpdateDocMode"
        descriptor.Value = NO_UPDATE
        doc = self._desktop.loadComponentFromURL(
            uno.systemPathToFileUrl(self.spec["doc_path"]), "_blank", 0, (descriptor,))
        if doc is None:
            raise RuntimeError(
                f"loadComponentFromURL returned None for {self.spec['doc_path']}")
        return doc

    # -- close detection ----------------------------------------------------------

    def _terminate_office(self) -> None:
        """Best-effort ``desktop.terminate()`` at session end.

        After the document closes the controlled GUI would otherwise keep
        living with its Start Center frame.  A surviving office poisons the
        NEXT session twice over: (a) the next ``soffice.exe`` launch with the
        same ``UserInstallation`` profile forwards its ``--accept`` to the
        survivor instead of starting a fresh instance; (b) on that survivor
        the fresh worker bridge is never the process's FIRST bridge, and LO
        serves client-object callbacks (interceptor registration) on the
        first bridge only — plain client->server calls keep working, but
        ``registerDispatchProviderInterceptor`` raises ``RuntimeException:
        Binary URP bridge already disposed`` (live 2026-11-18: fresh office,
        1st bridge registers on 2 frames, 2nd bridge fails this way every
        time).  The opener's job kill is the backstop; terminate() here makes
        the normal path exit cleanly and releases the profile lock.
        """
        if self._desktop is None:
            return
        try:
            self._desktop.terminate()
        except Exception:  # noqa: BLE001 — bridge already dead: job kill follows
            pass

    def _await_close(self, uno, doc) -> bool:
        """Block until the document closes; True = abnormal (crash/bridge).

        Primary: an XCloseListener on the model (event-driven).  Fallback:
        poll the model — a disposed doc or a dead bridge raises, which is
        close too, but only the listener path distinguishes a clean close.
        """
        clean = threading.Event()
        listener = _make_close_listener(clean, self._crashed)
        try:
            doc.addCloseListener(listener)
            self._close_signals.append(clean)
        except Exception:  # noqa: BLE001 — listener unsupported: poll only
            pass
        while not any(signal.is_set() for signal in self._close_signals):
            if not self._poll_alive(doc):
                # Live smoke P6 (2026-11-16): a clean close(False) can OUTRACE
                # its own notifyClosing on the bridge -- the poll hits the
                # disposed doc first.  A dead doc alone is NOT a crash:
                # classify as crashed only when the whole bridge is dead too
                # (the desktop stays touchable after a user's doc close).
                if self._bridge_alive():
                    return False
                self._crashed.set()
                return True
            self._sleep(CLOSE_POLL_S)
        return self._crashed.is_set()

    def _bridge_alive(self) -> bool:
        """Touch the desktop proxy: raises only when the bridge is dead."""
        try:
            self._desktop.getFrames()
            return True
        except Exception as exc:  # noqa: BLE001 — bridge disposed/dead
            self._close_detail = "bridge-dead: " + repr(exc)
            return False

    def _poll_alive(self, doc) -> bool:
        try:
            doc.getURL()  # any bridge touch raises once disposed/dead
            return True
        except Exception as exc:  # noqa: BLE001 — DisposedException / bridge death
            self._close_detail = repr(exc)
            self._set_close()
            return False

    def _set_close(self) -> None:
        for signal in self._close_signals:
            signal.set()

    # -- agent channel (key + audit) -------------------------------------------------

    def _password_provider(self) -> str | None:
        """Current master key from the agent, per forced save (todo 17 ①:
        the interceptor never persists a key; unavailable -> fail-closed)."""
        try:
            response = self._requester(
                self.spec["agent_pipe"], {"cmd": "key"}, timeout_s=KEY_REQUEST_TIMEOUT_S)
        except Exception:  # noqa: BLE001 — agent gone/busy -> refuse the save
            return None
        if response.get("ok") is True:
            key = response.get("key")
            if isinstance(key, str) and key:
                return key
        return None

    def _audit_report(self, action: str, file_hash: str,
                      key_version: int | None, ok: bool) -> None:
        """Interceptor audit -> agent link pipe; volume JSONL on failure."""
        event = {"action": action, "file_hash": file_hash,
                 "key_version": key_version, "ok": bool(ok)}
        try:
            self._requester(
                self.spec["agent_pipe"], dict(event, cmd="audit"),
                timeout_s=AUDIT_REQUEST_TIMEOUT_S)
            return
        except Exception:  # noqa: BLE001 — agent unreachable: queue on the volume
            pass
        self._queue_audit(event)

    def _queue_audit(self, event: dict) -> None:
        try:
            os.makedirs(self.spec["queue_dir"], exist_ok=True)
            path = os.path.join(self.spec["queue_dir"], QUEUE_FILE_NAME)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, sort_keys=True) + "\n")
        except OSError:
            pass  # volume gone: the audit is lost, the session still ends


class _CloseListener:
    """Close-listener implementation shared by the pyuno and fake paths.

    The pyuno bridge only adapts objects derived from ``unohelper.Base`` plus
    the COM interface class — a bare duck-typed object is rejected — so
    :func:`_make_close_listener` wraps THIS behaviour in the properly derived
    class when real UNO types are importable, and falls back to the bare
    class under the fake uno of unit tests (where there is no type machinery
    to satisfy).
    """

    def __init__(self, clean: threading.Event, crashed: threading.Event) -> None:
        self._clean = clean
        self._crashed = crashed
        self._notified = threading.Event()

    def queryClosing(self, event, deliver_ownership: bool) -> None:
        pass  # never veto

    def notifyClosing(self, event) -> None:
        self._notified.set()
        self._clean.set()

    def disposing(self, event) -> None:
        # A NORMAL close(False) also disposes the doc right after
        # notifyClosing -- disposal alone is NOT a crash verdict (live smoke
        # P6).  Abnormal only when disposal arrives with NO notifyClosing
        # (model torn down under us).
        if not self._notified.is_set():
            self._crashed.set()
        self._clean.set()


def _make_close_listener(clean: threading.Event, crashed: threading.Event):
    """Close listener with the pyuno adapter when uno types are available."""
    try:
        import unohelper  # noqa: PLC0415
        from com.sun.star.util import XCloseListener  # noqa: PLC0415
    except Exception:  # noqa: BLE001 — fake uno (tests): no type machinery
        return _CloseListener(clean, crashed)

    class _BridgedCloseListener(unohelper.Base, XCloseListener):
        # NOTE: __init__ MUST be redefined here.  unohelper.Base provides a
        # no-argument __init__; without this override the constructor call
        # with (clean, crashed) raises TypeError (live smoke P6, 2026-11-16 --
        # fake-uno unit tests exercise only the bare _CloseListener path and
        # cannot see it).
        def __init__(self, clean, crashed):
            self._clean = clean
            self._crashed = crashed
            self._notified = threading.Event()

        queryClosing = _CloseListener.queryClosing
        notifyClosing = _CloseListener.notifyClosing
        disposing = _CloseListener.disposing

    return _BridgedCloseListener(clean, crashed)


def main(argv: list[str] | None = None,
         *, stdin=None, worker_class=LinkWorker) -> int:
    source = stdin if stdin is not None else sys.stdin
    raw = source.read() if hasattr(source, "read") else source
    try:
        spec = json.loads(raw)
    except json.JSONDecodeError as exc:
        _emit({"ok": False, "error": f"invalid stdin JSON: {exc}"})
        return 2
    if (not isinstance(spec, dict)
            or not all(isinstance(spec.get(key), str) and spec.get(key)
                       for key in REQUIRED_SPEC_KEYS)):
        _emit({"ok": False,
               "error": f"stdin must carry non-empty strings: {', '.join(REQUIRED_SPEC_KEYS)}"})
        return 2
    return worker_class(spec).run()


if __name__ == "__main__":
    raise SystemExit(main())
