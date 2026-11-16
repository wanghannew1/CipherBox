"""force_encrypt routing-matrix tests with a fake uno (no LibreOffice).

The interceptor body (todo 17 ③ family routing + session-temp guard) decides
at dispatch time; these tests lock the matrix in with recording fakes:

* SaveAs/SaveACopy with an explicit URL: .cbx passes clean (P7), OOXML is
  forced-encrypted (Password + EncryptionData injected), non-OOXML is audited
  export_plaintext, and a target under the session-temp guard is REFUSED
  (fail-closed, audited ok=False) — nothing may be written into the scratch
  dir the session close would evaporate;
* .uno:Save / .uno:SaveAll with no URL argument NEVER inject EncryptionData:
  their target IS the session temp plaintext, and injecting there would
  overwrite the temp with ciphertext and corrupt the session-close re-encrypt
  (the data-corruption hazard this branch exists to close);
* dialog flows (no URL argument, SaveAs/SaveACopy) inject the forced-encrypt
  payload as the fail-safe default — worst case an odd save, never plaintext;
* missing key fail-closes the OOXML save (audited ok=False, no delegation);
* queryDispatch claims only the save/export families and forwards the rest.

The fake uno module graph is seeded in sys.modules before the (module-level)
import of force_encrypt; nothing here needs LibreOffice.
"""

from __future__ import annotations

import importlib
import sys
import types
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


class FakeFrame:
    def registerDispatchProviderInterceptor(self, interceptor) -> None:
        pass

    def releaseDispatchProviderInterceptor(self, interceptor) -> None:
        pass


def make_interceptor(fe, *, guard=None, password="k3", audits=None):
    interceptor = fe.ForceEncryptInterceptor(object())
    interceptor.attach(FakeFrame())
    interceptor.setSlaveDispatchProvider(FakeSlave(FakeDispatch()))
    interceptor.set_password_provider(password)
    recorder = audits if audits is not None else []
    interceptor.set_audit_reporter(lambda a, h, kv, ok: recorder.append((a, h, kv, ok)))
    if guard is not None:
        interceptor.set_guard(guard)
    return interceptor


def arg_names(arguments) -> list[str]:
    return [getattr(a, "Name", "") for a in arguments]


# ---------------------------------------------------------------------------
# routing matrix
# ---------------------------------------------------------------------------

SESSION_DIR = r"S:\.cipherbox-tmp\uuid-1"


class TestExplicitUrlTargets:
    def test_ooxml_target_is_force_encrypted(self, force_encrypt):
        audits: list = []
        interceptor = make_interceptor(force_encrypt, guard=SESSION_DIR, audits=audits)
        interceptor.dispatch(FakeURL(".uno:SaveAs"), (
            FakeArg("URL", "file:///s:/users/emp/Desktop/report.docx"),
            FakeArg("FilterName", "MS Word 2007 XML"),
        ))
        encrypt = [a for a in audits if a[0] == "encrypt"]
        assert len(encrypt) == 1 and encrypt[0][3] is True
        delegated = interceptor._slave._dispatch.dispatched
        assert len(delegated) == 1
        _, arguments = delegated[0]
        injected = arg_names(arguments)
        assert "Password" in injected and "EncryptionData" in injected

    def test_encryption_data_carries_cryptotype_and_password(self, force_encrypt):
        interceptor = make_interceptor(force_encrypt, password="the-key")
        interceptor.dispatch(FakeURL(".uno:SaveAs"), (
            FakeArg("URL", "file:///s:/out/book.xlsx"),))
        _, arguments = interceptor._slave._dispatch.dispatched[0]
        encryption_data = next(a for a in arguments if getattr(a, "Name", "") == "EncryptionData")
        value = encryption_data.Value
        assert isinstance(value, FakeAny) and value.type_name == "[]com.sun.star.beans.NamedValue"
        names = [nv.Name for nv in value.value]
        values = {nv.Name: nv.Value for nv in value.value}
        assert names == ["CryptoType", "Password"]
        assert values["CryptoType"] == "CipherBoxDataSpace"
        assert values["Password"] == "the-key"

    def test_cbx_target_delegates_unchanged(self, force_encrypt):
        audits: list = []
        interceptor = make_interceptor(force_encrypt, audits=audits)
        original = (FakeArg("URL", "file:///s:/out/keep.cbx"),)
        interceptor.dispatch(FakeURL(".uno:Save"), original)
        _, arguments = interceptor._slave._dispatch.dispatched[0]
        assert arguments == tuple(original)  # no Password injected (P7)
        assert audits == []

    def test_non_ooxml_target_audited_export_plaintext(self, force_encrypt):
        audits: list = []
        interceptor = make_interceptor(force_encrypt, audits=audits)
        interceptor.dispatch(FakeURL(".uno:SaveAs"), (
            FakeArg("URL", "file:///s:/out/notes.odt"),))
        assert audits == [("export_plaintext", "", None, True)]
        _, arguments = interceptor._slave._dispatch.dispatched[0]
        assert arg_names(arguments) == ["URL"]  # delegated clean

    def test_target_under_session_guard_is_refused(self, force_encrypt):
        audits: list = []
        interceptor = make_interceptor(
            force_encrypt, guard=SESSION_DIR, audits=audits)
        interceptor.dispatch(FakeURL(".uno:SaveAs"), (
            FakeArg("URL", "file:///S:/.cipherbox-tmp/uuid-1/escape.docx"),))
        assert audits == [("encrypt", "", None, False)]
        assert interceptor._slave._dispatch.dispatched == []  # never delegated

    def test_guard_is_case_insensitive_and_boundary_safe(self, force_encrypt):
        interceptor = make_interceptor(force_encrypt, guard=r"S:\.CipherBox-Tmp\UUID-1")
        assert interceptor._under_guard("file:///S:/.cipherbox-tmp/uuid-1/x.docx")
        assert interceptor._under_guard("file:///s:/.cipherbox-tmp/uuid-1/sub/y.docx")
        # sibling directory sharing the prefix must NOT match
        assert not interceptor._under_guard("file:///s:/.cipherbox-tmp/uuid-10/z.docx")
        assert not interceptor._under_guard("")
        assert not interceptor._under_guard("https://evil.example/x.docx")

    def test_no_guard_set_never_matches(self, force_encrypt):
        interceptor = make_interceptor(force_encrypt)
        assert not interceptor._under_guard("file:///s:/x.docx")


class TestDialogFlows:
    def test_saveas_without_url_forces_encrypt(self, force_encrypt):
        audits: list = []
        interceptor = make_interceptor(force_encrypt, audits=audits)
        interceptor.dispatch(FakeURL(".uno:SaveAs"), ())
        injected = arg_names(interceptor._slave._dispatch.dispatched[0][1])
        assert "Password" in injected and "EncryptionData" in injected
        assert any(a[0] == "encrypt" and a[3] is True for a in audits)

    def test_save_without_url_never_injects(self, force_encrypt):
        """The corruption guard: .uno:Save targets the session temp plaintext
        itself — injecting here would overwrite the temp with ciphertext."""
        audits: list = []
        interceptor = make_interceptor(force_encrypt, audits=audits)
        interceptor.dispatch(FakeURL(".uno:Save"), ())
        assert interceptor._slave._dispatch.dispatched[0][1] == ()  # clean delegate
        assert audits == []

    def test_saveall_without_url_never_injects(self, force_encrypt):
        interceptor = make_interceptor(force_encrypt)
        interceptor.dispatch(FakeURL(".uno:SaveAll"), ())
        assert interceptor._slave._dispatch.dispatched[0][1] == ()

    def test_saveacopy_without_url_forces_encrypt(self, force_encrypt):
        interceptor = make_interceptor(force_encrypt)
        interceptor.dispatch(FakeURL(".uno:SaveACopy"), ())
        injected = arg_names(interceptor._slave._dispatch.dispatched[0][1])
        assert "EncryptionData" in injected


class TestKeyFailClosed:
    def test_missing_key_refuses_ooxml_save(self, force_encrypt):
        audits: list = []
        interceptor = make_interceptor(force_encrypt, password=None, audits=audits)
        interceptor.dispatch(FakeURL(".uno:SaveAs"), (
            FakeArg("URL", "file:///s:/out/report.docx"),))
        assert audits == [("encrypt", "", None, False)]
        assert interceptor._slave._dispatch.dispatched == []

    def test_missing_key_still_passes_non_ooxml(self, force_encrypt):
        audits: list = []
        interceptor = make_interceptor(force_encrypt, password=None, audits=audits)
        interceptor.dispatch(FakeURL(".uno:SaveAs"), (
            FakeArg("URL", "file:///s:/out/notes.pdf"),))
        assert audits == [("export_plaintext", "", None, True)]
        assert len(interceptor._slave._dispatch.dispatched) == 1

    def test_provider_callable_is_consulted_each_dispatch(self, force_encrypt):
        keys = iter(["k-a", None])
        audits: list = []
        interceptor = force_encrypt.ForceEncryptInterceptor(object())
        interceptor.attach(FakeFrame())
        interceptor.setSlaveDispatchProvider(FakeSlave(FakeDispatch()))
        interceptor.set_password_provider(lambda: next(keys))
        interceptor.set_audit_reporter(lambda a, h, kv, ok: audits.append((a, h, kv, ok)))
        interceptor.dispatch(FakeURL(".uno:SaveAs"), (
            FakeArg("URL", "file:///s:/one.docx"),))
        interceptor.dispatch(FakeURL(".uno:SaveAs"), (
            FakeArg("URL", "file:///s:/two.docx"),))
        assert len(interceptor._slave._dispatch.dispatched) == 1
        assert "Password" in arg_names(interceptor._slave._dispatch.dispatched[0][1])
        refused = [a for a in audits if a[0] == "encrypt" and a[3] is False]
        assert len(refused) == 1  # second save: no key -> fail-closed


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


class TestWiring:
    def test_register_on_frame_attaches_and_registers(self, force_encrypt):
        interceptor = force_encrypt.register_on_frame(
            FakeFrame(), "k", audit_reporter=None)
        assert interceptor._registered is True
        assert interceptor._frame is not None

    def test_release_unregisters(self, force_encrypt):
        interceptor = force_encrypt.register_on_frame(FakeFrame(), "k")
        interceptor.release()
        assert interceptor._registered is False
