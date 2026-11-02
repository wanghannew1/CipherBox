"""Unit tests for agent/uno_driver.py with a fake UNO bridge (no soffice).

The fake module is injected through UnoDriver's ``uno_module`` seam and
records everything the driver builds, proving:

* EncryptionData carries BOTH CryptoType=CipherBoxDataSpace AND Password,
  plus the top-level Password (e2e_full.py-proven media descriptor shape);
* loadComponentFromURL carries UpdateDocMode=NO_UPDATE;
* a FRESH bridge (resolver.resolve) is used per call — never reused;
* the store target is a non-.cbx temp in the same directory (LO rejects
  custom store extensions) renamed atomically to ``<name>.cbx``;
* failures raise typed UnoDriverError and never take an empty-password path.

Subprocess-delegation tests live in test_uno_subprocess_delegation.py.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent.uno_driver import (
    CRYPTO_TYPE,
    DESKTOP_SERVICE,
    FILTER_BY_EXT,
    NO_UPDATE,
    PIPE_URL,
    RESOLVER_SERVICE,
    UnoDriver,
    UnoDriverError,
)

CFB_OUTPUT = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1-cipherbox-output"


class FakeStruct:
    def __init__(self, type_name: str) -> None:
        self.type_name = type_name
        self.Name: str | None = None
        self.Value: object = None


class FakeAny:
    def __init__(self, type_name: str, value: object) -> None:
        self.type_name = type_name
        self.value = value


class FakeDoc:
    def __init__(self, fake_uno: "FakeUno") -> None:
        self._uno = fake_uno
        self.store_calls: list[tuple[str, tuple]] = []
        self.close_calls: list[bool] = []

    def storeToURL(self, url: str, props) -> None:
        self.store_calls.append((url, tuple(props)))
        if self._uno.store_fail is not None:
            raise self._uno.store_fail
        with open(self._uno.url_to_system(url), "wb") as fh:
            fh.write(CFB_OUTPUT)

    def close(self, deliver: bool) -> None:
        self.close_calls.append(deliver)


class FakeDesktop:
    def __init__(self, fake_uno: "FakeUno") -> None:
        self._uno = fake_uno
        self.load_calls: list[tuple] = []
        self.docs: list[FakeDoc] = []

    def loadComponentFromURL(self, url: str, target: str, search: int, props):
        self.load_calls.append((url, target, search, tuple(props)))
        if self._uno.load_returns_none:
            return None
        doc = FakeDoc(self._uno)
        self.docs.append(doc)
        return doc


class _RemoteCtx:
    def __init__(self, desktop: FakeDesktop) -> None:
        self.ServiceManager = _RemoteServices(desktop)


class _RemoteServices:
    def __init__(self, desktop: FakeDesktop) -> None:
        self._desktop = desktop

    def createInstanceWithContext(self, name: str, ctx) -> FakeDesktop:
        assert name == DESKTOP_SERVICE
        return self._desktop


class _LocalServices:
    def __init__(self, fake_uno: "FakeUno") -> None:
        self._uno = fake_uno

    def createInstanceWithContext(self, name: str, ctx) -> "FakeResolver":
        assert name == RESOLVER_SERVICE
        return self._uno.resolver


class _LocalCtx:
    def __init__(self, fake_uno: "FakeUno") -> None:
        self.ServiceManager = _LocalServices(fake_uno)


class FakeResolver:
    def __init__(self, fake_uno: "FakeUno") -> None:
        self._uno = fake_uno

    def resolve(self, url: str) -> _RemoteCtx:
        self._uno.resolve_urls.append(url)
        if self._uno.resolver_fail is not None:
            raise self._uno.resolver_fail
        # A fresh remote context per resolve: the URP bridge never survives
        # an operation, so sharing one across calls would be the bug here.
        desktop = FakeDesktop(self._uno)
        self._uno.desktops.append(desktop)
        return _RemoteCtx(desktop)


class FakeUno:
    def __init__(self) -> None:
        self.resolve_urls: list[str] = []
        self.desktops: list[FakeDesktop] = []
        self.resolver_fail: Exception | None = None
        self.load_returns_none = False
        self.store_fail: Exception | None = None
        self.resolver = FakeResolver(self)

    def getComponentContext(self) -> _LocalCtx:
        return _LocalCtx(self)

    @staticmethod
    def systemPathToFileUrl(path: str) -> str:
        return "file:///" + str(path).replace("\\", "/")

    @staticmethod
    def url_to_system(url: str) -> str:
        return url[len("file:///"):].replace("/", "\\")

    @staticmethod
    def Any(type_name: str, value: object) -> FakeAny:
        return FakeAny(type_name, value)

    @staticmethod
    def createUnoStruct(name: str) -> FakeStruct:
        return FakeStruct(name)


def make_plain(tmp_path: Path, name: str = "a.docx") -> Path:
    plain = tmp_path / name
    plain.write_bytes(b"PK\x03\x04-fake-ooxml")
    return plain


# ---------------------------------------------------------------------------
# happy path
# ---------------------------------------------------------------------------

class TestEncryptToCbx:
    def test_load_descriptor_has_no_update(self, tmp_path: Path):
        fake = FakeUno()
        plain = make_plain(tmp_path)
        driver = UnoDriver(uno_module=fake)

        driver.encrypt_to_cbx(str(plain), str(plain) + ".cbx", "master-pw-1")

        (load_url, target, search, load_props), = fake.desktops[0].load_calls
        assert load_url == fake.systemPathToFileUrl(str(plain))
        assert target == "_blank" and search == 0
        update = [prop for prop in load_props if prop.Name == "UpdateDocMode"]
        assert len(update) == 1
        assert update[0].Value == NO_UPDATE

    def test_encryption_data_carries_crypto_type_and_password(self, tmp_path: Path):
        fake = FakeUno()
        plain = make_plain(tmp_path)
        driver = UnoDriver(uno_module=fake)

        driver.encrypt_to_cbx(str(plain), str(plain) + ".cbx", "master-pw-1")

        (store_url, store_props), = fake.desktops[0].docs[0].store_calls
        named = {prop.Name: prop.Value for prop in store_props}
        assert named["Password"] == "master-pw-1"  # top-level Password too
        assert named["FilterName"] == FILTER_BY_EXT[".docx"]
        encryption_data = named["EncryptionData"]
        assert isinstance(encryption_data, FakeAny)
        assert encryption_data.type_name == "[]com.sun.star.beans.NamedValue"
        members = {item.Name: item.Value for item in encryption_data.value}
        assert members == {"CryptoType": CRYPTO_TYPE, "Password": "master-pw-1"}

    def test_store_temp_then_atomic_rename(self, tmp_path: Path):
        fake = FakeUno()
        plain = make_plain(tmp_path)
        cbx = tmp_path / "a.docx.cbx"
        driver = UnoDriver(uno_module=fake)

        driver.encrypt_to_cbx(str(plain), str(cbx), "master-pw-1")

        (store_url, _props), = fake.desktops[0].docs[0].store_calls
        # The store target must NOT be the .cbx name (LO rejects custom ext);
        # it keeps the ORIGINAL extension in the same directory.
        assert store_url != fake.systemPathToFileUrl(str(cbx))
        assert store_url == fake.systemPathToFileUrl(str(cbx) + ".part.docx")
        assert cbx.read_bytes() == CFB_OUTPUT
        assert not (tmp_path / "a.docx.cbx.part.docx").exists()

    def test_document_closed_after_store(self, tmp_path: Path):
        fake = FakeUno()
        plain = make_plain(tmp_path)
        driver = UnoDriver(uno_module=fake)

        driver.encrypt_to_cbx(str(plain), str(plain) + ".cbx", "pw")

        assert fake.desktops[0].docs[0].close_calls == [False]

    def test_reconnect_per_call(self, tmp_path: Path):
        fake = FakeUno()
        plain = make_plain(tmp_path)
        driver = UnoDriver(uno_module=fake)

        driver.encrypt_to_cbx(str(plain), str(plain) + ".cbx", "pw")
        driver.encrypt_to_cbx(str(plain), str(plain) + ".cbx", "pw")

        assert fake.resolve_urls == [PIPE_URL, PIPE_URL]
        assert fake.desktops[0] is not fake.desktops[1]  # fresh ctx each call
        assert len(fake.desktops[0].load_calls) == 1
        assert len(fake.desktops[1].load_calls) == 1


# ---------------------------------------------------------------------------
# failure paths (typed errors, no empty-password route)
# ---------------------------------------------------------------------------

class TestFailing:
    def test_empty_password_raises_before_any_uno_call(self, tmp_path: Path):
        fake = FakeUno()
        plain = make_plain(tmp_path)
        driver = UnoDriver(uno_module=fake)

        with pytest.raises(UnoDriverError):
            driver.encrypt_to_cbx(str(plain), str(plain) + ".cbx", "")

        assert fake.resolve_urls == []  # never touched the bridge

    def test_connect_failure_is_typed(self, tmp_path: Path):
        fake = FakeUno()
        fake.resolver_fail = RuntimeError("Binary URP bridge disposed")
        plain = make_plain(tmp_path)
        driver = UnoDriver(uno_module=fake)

        with pytest.raises(UnoDriverError) as excinfo:
            driver.encrypt_to_cbx(str(plain), str(plain) + ".cbx", "pw")

        assert excinfo.value.stage == "connect"

    def test_load_none_is_typed(self, tmp_path: Path):
        fake = FakeUno()
        fake.load_returns_none = True
        plain = make_plain(tmp_path)
        driver = UnoDriver(uno_module=fake)

        with pytest.raises(UnoDriverError) as excinfo:
            driver.encrypt_to_cbx(str(plain), str(plain) + ".cbx", "pw")

        assert excinfo.value.stage == "load"

    def test_store_failure_removes_temp_and_raises_typed(self, tmp_path: Path):
        fake = FakeUno()
        fake.store_fail = RuntimeError("io error")
        plain = make_plain(tmp_path)
        cbx = tmp_path / "a.docx.cbx"
        driver = UnoDriver(uno_module=fake)

        with pytest.raises(UnoDriverError) as excinfo:
            driver.encrypt_to_cbx(str(plain), str(cbx), "pw")

        assert excinfo.value.stage == "uno"
        assert not cbx.exists()
        assert not (tmp_path / "a.docx.cbx.part.docx").exists()

    def test_unknown_extension_fails_closed(self, tmp_path: Path):
        fake = FakeUno()
        plain = make_plain(tmp_path, "a.txt")
        driver = UnoDriver(uno_module=fake)

        with pytest.raises(UnoDriverError) as excinfo:
            driver.encrypt_to_cbx(str(plain), str(plain) + ".cbx", "pw")

        assert excinfo.value.stage == "filter"
        assert fake.resolve_urls == []
