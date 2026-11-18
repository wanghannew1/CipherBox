"""force_encrypt routing-matrix tests with a fake uno (no LibreOffice).

The interceptor body (todo 17 ③ family routing + session-temp guard) decides
at dispatch time; these tests lock the matrix in with recording fakes:

* dispatch() runs INSIDE the office's callback and must never touch the
  model: payload saves / hashes / audits are deferred to the injected spawn
  (tests run it synchronously);
* explicit OOXML/``.cbx`` targets produce an ENCRYPTED SNAPSHOT
  (``storeToURL`` to ``<final>.part.<ext>`` + atomic ``os.replace`` to
  ``<final>.cbx``) — never a dispatch-chain delegation (live 2026-11-18: a
  payload delegate deadlocks or silently writes nothing);
* dialog flows (no URL argument) defer to the picker seam and snapshot the
  picked target under the ``.cbx`` convention; cancel saves nothing;
* in-place saves (``.uno:Save``/``.uno:SaveAll``, no URL) ALWAYS delegate
  clean — they write the session temp plaintext itself (the corruption
  guard); the session close owns the re-encrypt;
* missing key fail-closes the OOXML save (audited ok=False, no write);
* queryDispatch claims only the save/export families and forwards the rest.

The fake uno module graph is seeded in sys.modules before the (module-level)
import of force_encrypt; nothing here needs LibreOffice.
"""

from __future__ import annotations

import importlib
import os
import sys
import types
from pathlib import Path
from typing import Any

import pytest


# ---------------------------------------------------------------------------
# fake uno module graph
# ---------------------------------------------------------------------------

class FakePropertyValue:
    def __init__(self) -> None:
        self.Name = ""
        self.Value: Any = None


class FakeNamedValue(FakePropertyValue):
    pass


class FakeAny:
    def __init__(self, type_name: str, value: Any) -> None:
        self.type_name = type_name
        self.value = value


class FakeBase:
    """unohelper.Base stand-in."""


def _install_fake_uno(monkeypatch: pytest.MonkeyPatch) -> None:
    uno = types.ModuleType("uno")
    uno.PropertyValue = FakePropertyValue
    uno.NamedValue = FakeNamedValue
    uno.Any = FakeAny
    uno.getComponentContext = lambda: object()
    uno.systemPathToFileUrl = lambda path: (
        "file:///" + str(path).replace("\\", "/").lstrip("/"))
    uno.getConstantByName = lambda name: (_ for _ in ()).throw(
        RuntimeError("no constants under the fake uno"))

    unohelper = types.ModuleType("unohelper")
    unohelper.Base = FakeBase

    for name, attrs in {
        "com.sun.star.beans": {"NamedValue": FakeNamedValue, "PropertyValue": FakePropertyValue},
        "com.sun.star.frame": {"XDispatch": type("XDispatch", (), {}),
                               "XDispatchProviderInterceptor": type("XPI", (), {})},
        "com.sun.star.lang": {"XInitialization": type("XInitialization", (), {}),
                              "XServiceInfo": type("XServiceInfo", (), {})},
    }.items():
        module = types.ModuleType(name)
        for attr, value in attrs.items():
            setattr(module, attr, value)
        monkeypatch.setitem(sys.modules, name, module)
    for parent in ("com", "com.sun", "com.sun.star"):
        monkeypatch.setitem(sys.modules, parent, types.ModuleType(parent))
    monkeypatch.setitem(sys.modules, "uno", uno)
    monkeypatch.setitem(sys.modules, "unohelper", unohelper)


@pytest.fixture()
def force_encrypt(monkeypatch: pytest.MonkeyPatch):
    """force_encrypt imported with the fake uno graph active in sys.modules."""
    _install_fake_uno(monkeypatch)
    module = importlib.import_module("force_encrypt")
    try:
        yield module
    finally:
        sys.modules.pop("force_encrypt", None)


# ---------------------------------------------------------------------------
# recording fakes
# ---------------------------------------------------------------------------

class FakeURL:
    def __init__(self, complete: str) -> None:
        self.Complete = complete


class FakeArg:
    def __init__(self, name: str, value: Any) -> None:
        self.Name = name
        self.Value = value


class FakeDispatch:
    def __init__(self) -> None:
        self.dispatched: list[tuple[str, tuple]] = []

    def dispatch(self, url, arguments) -> None:
        self.dispatched.append((url.Complete, tuple(arguments)))


class FakeSlave:
    def __init__(self, dispatch: FakeDispatch) -> None:
        self._dispatch = dispatch

    def queryDispatch(self, url, target, flags):
        return self._dispatch


class FakeModel:
    """Doc model with a real URL and a recording storeToURL that writes
    ciphertext bytes to the part file (so os.replace works in tests)."""

    def __init__(self, url: str = "file:///s:/src/a.docx") -> None:
        self.url = url
        self.stored: list[tuple[str, tuple]] = []

    def getURL(self) -> str:
        return self.url

    def getArgs(self) -> tuple:
        return ()

    def supportsService(self, name: str) -> bool:
        return False

    def storeToURL(self, url: str, properties) -> None:
        props = tuple(properties)
        self.stored.append((str(url), props))
        # materialize the part file so the snapshot's os.replace succeeds
        path = str(url)
        if path.startswith("file:///"):
            path = path[len("file:///"):]
        path = path.replace("/", os.sep)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(b"CIPHERTEXT-BYTES")


class FakeController:
    def __init__(self, model: FakeModel) -> None:
        self._model = model

    def getModel(self) -> FakeModel:
        return self._model


class FakeFrame:
    def __init__(self, model: FakeModel | None = None) -> None:
        self._model = model or FakeModel()

    def getController(self) -> FakeController:
        return FakeController(self._model)

    def registerDispatchProviderInterceptor(self, interceptor) -> None:
        pass

    def releaseDispatchProviderInterceptor(self, interceptor) -> None:
        pass


def _sync_spawn(fn) -> None:
    """Tests run deferred jobs (picker flow, deferred audits, snapshots) inline."""
    fn()


def make_interceptor(fe, *, guard=None, password="k3", audits=None,
                     pick=None, spawn=_sync_spawn, frame=None):
    interceptor = fe.ForceEncryptInterceptor(
        object(), spawn=spawn, pick_save_target=pick)
    interceptor.attach(frame or FakeFrame())
    interceptor.setSlaveDispatchProvider(FakeSlave(FakeDispatch()))
    interceptor.set_password_provider(password)
    recorder = audits if audits is not None else []
    interceptor.set_audit_reporter(lambda a, h, kv, ok: recorder.append((a, h, kv, ok)))
    if guard is not None:
        interceptor.set_guard(guard)
    return interceptor


def arg_names(arguments) -> list[str]:
    return [getattr(a, "Name", "") for a in arguments]


def prop_map(props) -> dict:
    return {getattr(p, "Name", ""): getattr(p, "Value", None) for p in props}


def url_of(tmp_path: Path, *parts: str) -> str:
    return "file:///" + (tmp_path.joinpath(*parts)).as_posix()


# ---------------------------------------------------------------------------
# routing matrix
# ---------------------------------------------------------------------------

SESSION_DIR = r"S:\.cipherbox-tmp\uuid-1"


class TestExplicitUrlTargets:
    def test_ooxml_target_snapshots_encrypted(self, force_encrypt, tmp_path: Path):
        audits: list = []
        interceptor = make_interceptor(
            force_encrypt, guard=str(tmp_path / "session"), audits=audits)
        interceptor.dispatch(FakeURL(".uno:SaveAs"), (
            FakeArg("URL", url_of(tmp_path, "out", "report.docx")),
            FakeArg("FilterName", "MS Word 2007 XML"),
        ))
        final = tmp_path / "out" / "report.docx.cbx"
        assert final.read_bytes() == b"CIPHERTEXT-BYTES"  # landed encrypted
        assert not list((tmp_path / "out").glob("*.part.*"))  # part renamed
        stored_url, props = interceptor._frame._model.stored[-1]
        assert stored_url.endswith("report.docx.cbx.part.docx")
        assert list(prop_map(props)) == ["FilterName", "Password", "EncryptionData"]
        assert prop_map(props)["FilterName"] == "MS Word 2007 XML"
        assert [a[0] for a in audits] == ["encrypt"]
        assert audits[0][3] is True
        # the slave chain was NOT used for the payload save
        assert interceptor._slave._dispatch.dispatched == []

    def test_encryption_data_carries_cryptotype_and_password(self, force_encrypt,
                                                             tmp_path: Path):
        interceptor = make_interceptor(force_encrypt, password="the-key")
        interceptor.dispatch(FakeURL(".uno:SaveAs"), (
            FakeArg("URL", url_of(tmp_path, "out", "book.xlsx")),))
        _, props = interceptor._frame._model.stored[-1]
        encryption_data = prop_map(props)["EncryptionData"]
        assert isinstance(encryption_data, FakeAny)
        assert encryption_data.type_name == "[]com.sun.star.beans.NamedValue"
        values = {nv.Name: nv.Value for nv in encryption_data.value}
        assert values == {"CryptoType": "CipherBoxDataSpace", "Password": "the-key"}

    def test_cbx_target_is_snapshot_as_is(self, force_encrypt, tmp_path: Path):
        """A ``.cbx`` target is kept (no double suffix) and still encrypted:
        a pass-through would write plaintext into a .cbx-named file the
        watcher EXCLUDES by suffix — permanent escape (live 2026-11-18)."""
        audits: list = []
        interceptor = make_interceptor(force_encrypt, audits=audits)
        interceptor.dispatch(FakeURL(".uno:Save"), (
            FakeArg("URL", url_of(tmp_path, "out", "keep.cbx")),))
        final = tmp_path / "out" / "keep.cbx"
        assert final.read_bytes() == b"CIPHERTEXT-BYTES"
        stored_url, props = interceptor._frame._model.stored[-1]
        assert stored_url.endswith("keep.cbx.part.docx")  # src ext in the part
        assert "EncryptionData" in prop_map(props)
        assert any(a[0] == "encrypt" and a[3] is True for a in audits)

    def test_non_ooxml_target_audited_export_plaintext(self, force_encrypt,
                                                       tmp_path: Path):
        audits: list = []
        interceptor = make_interceptor(force_encrypt, audits=audits)
        interceptor.dispatch(FakeURL(".uno:SaveAs"), (
            FakeArg("URL", url_of(tmp_path, "out", "notes.odt")),))
        assert audits == [("export_plaintext", "", None, True)]
        _, arguments = interceptor._slave._dispatch.dispatched[0]
        assert arg_names(arguments) == ["URL"]  # delegated clean

    def test_target_under_session_guard_is_refused(self, force_encrypt,
                                                   tmp_path: Path):
        audits: list = []
        interceptor = make_interceptor(
            force_encrypt, guard=str(tmp_path / "session"), audits=audits)
        interceptor.dispatch(FakeURL(".uno:SaveAs"), (
            FakeArg("URL", url_of(tmp_path, "session", "escape.docx")),))
        assert audits == [("encrypt", "", None, False)]
        assert interceptor._slave._dispatch.dispatched == []  # never delegated
        assert interceptor._frame._model.stored == []  # never written

    def test_guard_is_case_insensitive_and_boundary_safe(self, force_encrypt,
                                                         tmp_path: Path):
        interceptor = make_interceptor(
            force_encrypt, guard=str(tmp_path / "session"))
        base = "file:///" + (tmp_path / "session").as_posix().lower()
        assert interceptor._under_guard(base + "/x.docx")
        assert interceptor._under_guard(base + "/sub/y.docx")
        # sibling directory sharing the prefix must NOT match
        assert not interceptor._under_guard(base + "10/z.docx")
        assert not interceptor._under_guard("")
        assert not interceptor._under_guard("https://evil.example/x.docx")

    def test_no_guard_set_never_matches(self, force_encrypt):
        interceptor = make_interceptor(force_encrypt)
        assert not interceptor._under_guard("file:///s:/x.docx")

    def test_inplace_save_without_url_never_injects(self, force_encrypt):
        """The corruption guard: .uno:Save targets the session temp plaintext
        itself — the write-back belongs to the session close's re-encrypt."""
        audits: list = []
        interceptor = make_interceptor(force_encrypt, audits=audits)
        interceptor.dispatch(FakeURL(".uno:Save"), ())
        assert interceptor._slave._dispatch.dispatched[0][1] == ()  # clean
        assert interceptor._frame._model.stored == []
        assert audits == []

    def test_inplace_saveall_without_url_never_injects(self, force_encrypt):
        interceptor = make_interceptor(force_encrypt)
        interceptor.dispatch(FakeURL(".uno:SaveAll"), ())
        assert interceptor._slave._dispatch.dispatched[0][1] == ()


class TestDialogFlows:
    """Dialog flows (no URL argument) can NOT inject at dispatch time: the
    native dialog discards the payload and the file landed PLAINTEXT (the
    user-visible 1-3 s watcher window).  The flow now runs its own picker on
    the deferred thread and snapshots the picked target encrypted."""

    def test_saveas_dialog_snapshots_picked_as_cbx(self, force_encrypt,
                                                   tmp_path: Path):
        audits: list = []
        interceptor = make_interceptor(
            force_encrypt, audits=audits,
            pick=lambda: url_of(tmp_path, "out", "report.docx"))
        interceptor.dispatch(FakeURL(".uno:SaveAs"), ())
        final = tmp_path / "out" / "report.docx.cbx"
        assert final.read_bytes() == b"CIPHERTEXT-BYTES"
        assert any(a[0] == "encrypt" and a[3] is True for a in audits)
        # no slave delegation at all (snapshot path)
        assert interceptor._slave._dispatch.dispatched == []

    def test_dialog_save_keeps_inplace_clean(self, force_encrypt, tmp_path: Path):
        """The snapshot never switches the medium: subsequent in-place saves
        keep writing the session temp plaintext, clean."""
        interceptor = make_interceptor(
            force_encrypt, pick=lambda: url_of(tmp_path, "out", "report.docx"))
        interceptor.dispatch(FakeURL(".uno:SaveAs"), ())
        interceptor.dispatch(FakeURL(".uno:Save"), ())
        slot, arguments = interceptor._slave._dispatch.dispatched[0]
        assert slot == ".uno:Save"
        assert arguments == ()

    def test_saveacopy_dialog_snapshots_too(self, force_encrypt, tmp_path: Path):
        interceptor = make_interceptor(
            force_encrypt, pick=lambda: url_of(tmp_path, "out", "copy.docx"))
        interceptor.dispatch(FakeURL(".uno:SaveACopy"), ())
        assert (tmp_path / "out" / "copy.docx.cbx").read_bytes() == b"CIPHERTEXT-BYTES"

    def test_dialog_cancel_saves_nothing(self, force_encrypt):
        audits: list = []
        interceptor = make_interceptor(force_encrypt, audits=audits,
                                       pick=lambda: None)
        interceptor.dispatch(FakeURL(".uno:SaveAs"), ())
        assert interceptor._slave._dispatch.dispatched == []
        assert interceptor._frame._model.stored == []
        assert audits == []  # parity with a native-dialog cancel

    def test_dialog_picker_failure_fails_closed(self, force_encrypt):
        audits: list = []

        def boom():
            raise RuntimeError("picker unavailable")

        interceptor = make_interceptor(force_encrypt, audits=audits, pick=boom)
        interceptor.dispatch(FakeURL(".uno:SaveAs"), ())
        assert interceptor._slave._dispatch.dispatched == []
        assert interceptor._frame._model.stored == []
        assert audits == [("encrypt", "", None, False)]

    def test_dialog_plain_target_delegates_clean(self, force_encrypt,
                                                 tmp_path: Path):
        audits: list = []
        interceptor = make_interceptor(
            force_encrypt, audits=audits,
            pick=lambda: url_of(tmp_path, "out", "notes.odt"))
        interceptor.dispatch(FakeURL(".uno:SaveAs"), ())
        _, arguments = interceptor._slave._dispatch.dispatched[0]
        # only the URL rides along (no payload, no filter): plaintext family
        assert arg_names(arguments) == ["URL"]
        url_arg = next(a for a in arguments if getattr(a, "Name", "") == "URL")
        assert url_arg.Value == url_of(tmp_path, "out", "notes.odt")
        assert audits == [("export_plaintext", "", None, True)]


class TestKeyFailClosed:
    def test_missing_key_refuses_ooxml_save(self, force_encrypt, tmp_path: Path):
        audits: list = []
        interceptor = make_interceptor(force_encrypt, password=None, audits=audits)
        interceptor.dispatch(FakeURL(".uno:SaveAs"), (
            FakeArg("URL", url_of(tmp_path, "out", "report.docx")),))
        assert audits == [("encrypt", "", None, False)]
        assert interceptor._slave._dispatch.dispatched == []
        assert interceptor._frame._model.stored == []

    def test_missing_key_still_passes_non_ooxml(self, force_encrypt,
                                                tmp_path: Path):
        audits: list = []
        interceptor = make_interceptor(force_encrypt, password=None, audits=audits)
        interceptor.dispatch(FakeURL(".uno:SaveAs"), (
            FakeArg("URL", url_of(tmp_path, "out", "notes.pdf")),))
        assert audits == [("export_plaintext", "", None, True)]
        assert len(interceptor._slave._dispatch.dispatched) == 1

    def test_provider_callable_is_consulted_each_snapshot(self, force_encrypt,
                                                          tmp_path: Path):
        keys = iter(["k-a", None])
        audits: list = []
        interceptor = force_encrypt.ForceEncryptInterceptor(
            object(), spawn=_sync_spawn,
            pick_save_target=lambda: None)
        interceptor.attach(FakeFrame())
        interceptor.setSlaveDispatchProvider(FakeSlave(FakeDispatch()))
        interceptor.set_password_provider(lambda: next(keys))
        interceptor.set_audit_reporter(lambda a, h, kv, ok: audits.append((a, h, kv, ok)))
        interceptor.dispatch(FakeURL(".uno:SaveAs"), (
            FakeArg("URL", url_of(tmp_path, "out", "one.docx")),))
        interceptor.dispatch(FakeURL(".uno:SaveAs"), (
            FakeArg("URL", url_of(tmp_path, "out", "two.docx")),))
        assert len(interceptor._frame._model.stored) == 1  # first save wrote
        ok_events = [a for a in audits if a[0] == "encrypt" and a[3] is True]
        refused = [a for a in audits if a[0] == "encrypt" and a[3] is False]
        assert len(ok_events) == 1 and len(refused) == 1  # second: no key


class TestDispatchClaiming:
    def test_query_dispatch_claims_save_and_export_families(self, force_encrypt):
        interceptor = make_interceptor(force_encrypt)
        for slot in (".uno:Save", ".uno:SaveAs", ".uno:SaveACopy", ".uno:SaveAll",
                     ".uno:ExportTo", ".uno:ExportToPDF", ".uno:ExportDirectToPDF",
                     ".uno:Print", ".uno:SendMail"):
            assert interceptor.queryDispatch(FakeURL(slot), "", 0) is interceptor, slot

    def test_query_dispatch_forwards_other_slots(self, force_encrypt):
        interceptor = make_interceptor(force_encrypt)
        result = interceptor.queryDispatch(FakeURL(".uno:Undo"), "", 0)
        # forwarded to the slave chain, never claimed by the interceptor itself
        assert result is not interceptor


class TestExportFamily:
    def test_exportto_audits_plaintext_and_delegates(self, force_encrypt):
        audits: list = []
        interceptor = make_interceptor(force_encrypt, audits=audits)
        interceptor.dispatch(FakeURL(".uno:ExportToPDF"), (
            FakeArg("URL", "file:///s:/out/share.pdf"),))
        assert audits == [("export_plaintext", "", None, True)]
        assert len(interceptor._slave._dispatch.dispatched) == 1
