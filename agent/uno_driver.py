"""Real UNO encryption driver (plan todo 13 service pipeline, e2e_full-proven pattern).

Drives the resident LibreOffice service instance over the named pipe
``uno:pipe,name=cipherbox-service;urp;StarOffice.ComponentContext``:

1. a FRESH ``resolver.resolve()`` per call — the URP bridge dies across
   operations ("Binary URP bridge disposed"), so no connection state is
   ever reused between calls;
2. ``loadComponentFromURL(plain, "_blank", 0, (UpdateDocMode=NO_UPDATE,))``
   — NO_UPDATE disables external-link/DDE/OLE auto-update on load;
3. ``storeToURL(temp, (FilterName, Password, EncryptionData{CryptoType,
   Password}))`` with ``CryptoType="CipherBoxDataSpace"``.  LibreOffice
   rejects custom extensions on store (e2e_full.py proven), so the temp
   file keeps the ORIGINAL extension in the destination directory
   (``<cbx>.part<orig_ext>``, e.g. ``a.docx.cbx.part.docx``) and
   ``os.replace`` renames it atomically to ``<name>.cbx``;
4. ``doc.close(False)`` always, then the atomic replace; a failed run
   removes the partial temp and raises :class:`UnoDriverError`.

There is no empty-password path: an empty password raises before any UNO
interaction.  The ``uno`` module is imported lazily (pyuno only loads under
a compatible interpreter — LibreOffice's bundled python); unit tests inject
a fake module instead.
"""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
from pathlib import Path

PIPE_URL = "uno:pipe,name=cipherbox-service;urp;StarOffice.ComponentContext"
CRYPTO_TYPE = "CipherBoxDataSpace"
DESKTOP_SERVICE = "com.sun.star.frame.Desktop"
RESOLVER_SERVICE = "com.sun.star.bridge.UnoUrlResolver"
NO_UPDATE = 0  # com.sun.star.document.UpdateDocMode.NO_UPDATE

REPO_ROOT = str(Path(__file__).resolve().parents[1])
DEFAULT_LO_PYTHON = r"C:\Program Files\LibreOffice\program\python.exe"
SUBPROCESS_TIMEOUT_S = 120

# Only the three OOXML formats enter the encryption pipeline (watcher
# OFFICE_EXTENSIONS); anything else fails closed rather than guessing a filter.
FILTER_BY_EXT = {
    ".docx": "MS Word 2007 XML",
    ".xlsx": "Calc MS Excel 2007 XML",
    ".pptx": "Impress MS PowerPoint 2007 XML",
}

_LO_PROGRAM_DIRS = (r"C:\Program Files\LibreOffice\program",)


def _resolve_lo_python() -> str:
    """LibreOffice's bundled python: CIPHERBOX_LO_PYTHON first, then default."""
    candidate = os.environ.get("CIPHERBOX_LO_PYTHON", DEFAULT_LO_PYTHON)
    if not os.path.isfile(candidate):
        raise UnoDriverError(
            "subprocess",
            f"LibreOffice python not found at {candidate!r}; set CIPHERBOX_LO_PYTHON "
            "to LO's bundled python.exe (pyuno is version-locked to that interpreter)")
    return candidate


def _parse_last_json_line(stdout: str) -> dict | None:
    """The worker's one JSON response line (last non-empty stdout line)."""
    for line in reversed((stdout or "").splitlines()):
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def _scrubbed_tail(stdout: str, stderr: str, secret: str) -> str:
    """Concise failure tail; the secret is scrubbed before it leaves memory."""
    lines = [line.strip() for line in
             ((stdout or "") + "\n" + (stderr or "")).splitlines() if line.strip()]
    tail = " | ".join(lines[-4:])[-500:]
    return tail.replace(secret, "***") if secret else tail


class UnoDriverError(Exception):
    """Typed failure of one UNO encryption step (stage names the phase)."""

    def __init__(self, stage: str, detail: str) -> None:
        super().__init__(f"UNO {stage} failed: {detail}")
        self.stage = stage


def _default_uno():
    """Import pyuno, retrying once with LibreOffice's program dir on sys.path."""
    try:
        import uno  # noqa: PLC0415 — lazy: pyuno exists only under LO-compatible python
        return uno
    except ImportError:
        pass
    for prog_dir in _LO_PROGRAM_DIRS:
        if os.path.isdir(prog_dir) and prog_dir not in sys.path:
            sys.path.append(prog_dir)
    import uno  # noqa: PLC0415
    return uno


class UnoDriver:
    """Encrypt one plaintext OOXML file into ``.cbx`` via the LO service pipe.

    In-process when pyuno is importable; otherwise each call is delegated to
    :mod:`agent.uno_subprocess` running under LibreOffice's bundled python
    (system python's pyuno is version-locked to LO's python and can never
    load here).  A fake-injected ``uno_module`` never touches the subprocess.
    """

    def __init__(self, *, pipe_url: str = PIPE_URL, uno_module=None) -> None:
        self.pipe_url = pipe_url
        self._uno_module = uno_module

    def _uno(self):
        if self._uno_module is None:
            self._uno_module = _default_uno()
        return self._uno_module

    # -- public API ---------------------------------------------------------

    def encrypt_to_cbx(self, plain_path: str, cbx_path: str, password: str) -> None:
        """Load ``plain_path`` in the service LO, store it encrypted, rename to ``cbx_path``."""
        if not password:
            raise UnoDriverError("password", "refusing to encrypt with an empty password")
        plain = os.path.abspath(plain_path)
        cbx = os.path.abspath(cbx_path)
        ext = os.path.splitext(plain)[1].lower()
        filter_name = FILTER_BY_EXT.get(ext)
        if filter_name is None:
            raise UnoDriverError("filter", f"no OOXML filter for extension {ext!r} ({plain})")
        temp = cbx + ".part" + ext
        if self._uno_module is not None:
            self._store_via_uno(plain, cbx, temp, filter_name, password)
            return
        try:
            u = _default_uno()
        except ImportError:
            self._store_via_subprocess(plain, cbx, password)
            return
        self._uno_module = u
        self._store_via_uno(plain, cbx, temp, filter_name, password)

    # -- internals ----------------------------------------------------------

    def _store_via_uno(self, plain: str, cbx: str, temp: str, filter_name: str,
                       password: str) -> None:
        u = self._uno()
        try:
            ctx = self._connect(u)
            desktop = ctx.ServiceManager.createInstanceWithContext(DESKTOP_SERVICE, ctx)
            doc = desktop.loadComponentFromURL(
                u.systemPathToFileUrl(plain), "_blank", 0,
                (self._prop(u, "com.sun.star.beans.PropertyValue", "UpdateDocMode", NO_UPDATE),),
            )
            if doc is None:
                raise UnoDriverError("load", f"loadComponentFromURL returned None for {plain}")
            try:
                doc.storeToURL(u.systemPathToFileUrl(temp), self._store_props(u, filter_name, password))
            finally:
                # Best-effort dispose: a failed close must not mask the store
                # result, and on the success path the artifact is complete.
                with contextlib.suppress(Exception):
                    doc.close(False)
            os.replace(temp, cbx)
        except UnoDriverError:
            self._discard(temp)
            raise
        except Exception as exc:  # URP/bridge/IO failure -> typed driver error
            self._discard(temp)
            raise UnoDriverError("uno", str(exc)) from exc

    def _store_via_subprocess(self, plain: str, cbx: str, password: str) -> None:
        """Delegate one encryption to agent.uno_subprocess under LO's python.

        The password crosses via stdin only (never argv); a claimed success is
        verified at the trust boundary by the artifact's existence.
        """
        lo_python = _resolve_lo_python()
        payload = json.dumps({"plain": plain, "cbx": cbx, "password": password})
        try:
            completed = subprocess.run(
                [lo_python, "-m", "agent.uno_subprocess", "encrypt"],
                input=payload, capture_output=True, text=True,
                timeout=SUBPROCESS_TIMEOUT_S, cwd=str(REPO_ROOT),
            )
        except subprocess.TimeoutExpired as exc:
            raise UnoDriverError(
                "subprocess",
                f"LO python encryption timed out after {SUBPROCESS_TIMEOUT_S}s") from exc
        except OSError as exc:
            raise UnoDriverError("subprocess", f"cannot run {lo_python}: {exc}") from exc
        if completed.returncode == 0:
            response = _parse_last_json_line(completed.stdout)
            if response is not None and response.get("ok") is True:
                if not os.path.isfile(cbx):
                    raise UnoDriverError(
                        "subprocess", f"worker reported ok but {cbx} is missing")
                return
        raise UnoDriverError(
            "subprocess",
            f"worker failed (rc={completed.returncode}): "
            f"{_scrubbed_tail(completed.stdout, completed.stderr, password)}")

    def _connect(self, u):
        """Fresh resolver.resolve() — never reuse a bridge across calls."""
        local = u.getComponentContext()
        try:
            resolver = local.ServiceManager.createInstanceWithContext(RESOLVER_SERVICE, local)
            return resolver.resolve(self.pipe_url)
        except UnoDriverError:
            raise
        except Exception as exc:
            raise UnoDriverError("connect", f"cannot resolve {self.pipe_url}: {exc}") from exc

    def _store_props(self, u, filter_name: str, password: str) -> tuple:
        encryption_data = u.Any("[]com.sun.star.beans.NamedValue", (
            self._prop(u, "com.sun.star.beans.NamedValue", "CryptoType", CRYPTO_TYPE),
            self._prop(u, "com.sun.star.beans.NamedValue", "Password", password),
        ))
        return (
            self._prop(u, "com.sun.star.beans.PropertyValue", "FilterName", filter_name),
            self._prop(u, "com.sun.star.beans.PropertyValue", "Password", password),
            self._prop(u, "com.sun.star.beans.PropertyValue", "EncryptionData", encryption_data),
        )

    @staticmethod
    def _prop(u, struct_name: str, name: str, value):
        prop = u.createUnoStruct(struct_name)
        prop.Name = name
        prop.Value = value
        return prop

    @staticmethod
    def _discard(temp: str) -> None:
        """Remove a partial temp artifact after a failed run (error cleanup)."""
        with contextlib.suppress(OSError):
            os.remove(temp)
