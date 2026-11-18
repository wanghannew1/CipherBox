"""Tests for agent/opener.py (todo 14): session store, controlled-open loop, mutex.

LibreOffice/UNO is fully mocked via callbacks; no soffice needed.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

import cipherbox_crypto as crypto
from agent.container import CbxContainer, STREAM_DATASPACEINFO, STREAM_ENCRYPTEDPACKAGE
from agent import hide_directory
from agent.opener import (
    ControlledOpener,
    JobObject,
    MUTEX_NAME,
    OpenResult,
    SessionRecord,
    SessionStore,
    SingleInstanceMutex,
    _dpapi_decrypt,
    _dpapi_encrypt,
    bind_office_children,
)

PASSWORD = "master-password-v1"
WRONG = "wrong-password"


# ---------------------------------------------------------------------------
# helpers: build a synthetic .cbx stream map
# ---------------------------------------------------------------------------

def make_stream_map(password: str, plaintext: bytes) -> dict:
    iv = os.urandom(crypto.IV_LEN)
    cipher = crypto.aes_cbc(crypto.derive_key(password), iv, plaintext, encrypt=True)
    payload = crypto._i64(len(plaintext)) + iv + cipher
    salt, digest = crypto.make_verifier(password)
    trailer = (
        crypto.VERIFIER_MAGIC
        + len(salt).to_bytes(4, "little")
        + salt
        + len(digest).to_bytes(4, "little")
        + digest
    )
    streams = {
        STREAM_ENCRYPTEDPACKAGE: payload,
        STREAM_DATASPACEINFO: b"\x00" * 48 + trailer,
    }
    return streams


def make_container(password: str, plaintext: bytes) -> CbxContainer:
    return CbxContainer(make_stream_map(password, plaintext), source="<test>")


# ---------------------------------------------------------------------------
# DPAPI session round-trip
# ---------------------------------------------------------------------------

@pytest.mark.skipif(os.name != "nt", reason="DPAPI is Windows-only")
class TestDpapiSession:
    def test_encrypt_decrypt_roundtrip(self):
        plain = b"session json metadata"
        enc = _dpapi_encrypt(plain)
        assert enc != plain
        assert _dpapi_decrypt(enc) == plain

    def test_tamper_fails(self):
        enc = bytearray(_dpapi_encrypt(b"tamper"))
        enc[-1] ^= 0xFF
        with pytest.raises(Exception):
            _dpapi_decrypt(bytes(enc))


# ---------------------------------------------------------------------------
# SessionStore
# ---------------------------------------------------------------------------

class TestSessionStore:
    def test_save_load_delete(self, tmp_path: Path):
        session_dir = str(tmp_path / "sessions")
        store = SessionStore(session_dir)
        rec = SessionRecord(
            session_id="sess-1",
            cbx_path=r"S:\report.docx.cbx",
            tmp_path=r"S:\.cipherbox-tmp\sess-1\report.docx",
            orig_sha256="a" * 64,
            key_version=2,
            ts=1234567890.0,
        )
        store.save(rec)
        assert os.path.exists(store._path("sess-1"))

        loaded = store.load("sess-1")
        assert loaded is not None
        assert loaded.session_id == "sess-1"
        assert loaded.cbx_path == r"S:\report.docx.cbx"
        assert loaded.orig_sha256 == "a" * 64
        assert loaded.key_version == 2

        store.delete("sess-1")
        assert store.load("sess-1") is None

    def test_load_missing_returns_none(self, tmp_path: Path):
        store = SessionStore(str(tmp_path / "sessions"))
        assert store.load("nope") is None

    def test_list_orphans(self, tmp_path: Path):
        session_dir = str(tmp_path / "sessions")
        store = SessionStore(session_dir)
        r1 = SessionRecord("s1", "a.cbx", "a.tmp", "h1", 1, 1.0)
        r2 = SessionRecord("s2", "b.cbx", "b.tmp", "h2", 2, 2.0)
        store.save(r1)
        store.save(r2)
        orphans = store.list_orphans()
        assert {o.session_id for o in orphans} == {"s1", "s2"}


# ---------------------------------------------------------------------------
# ControlledOpener open_controlled
# ---------------------------------------------------------------------------

class TestControlledOpener:
    def _make_opener(self, tmp_path, plaintext, passwords=None):
        container = make_container(PASSWORD, plaintext)
        tmp_root = str(tmp_path / "tmp")
        session_store = SessionStore(str(tmp_path / "sessions"))
        return ControlledOpener(
            container=container,
            passwords=passwords or [PASSWORD],
            key_version=2,
            session_store=session_store,
            tmp_root=tmp_root,
        )

    def test_open_controlled_full_loop(self, tmp_path: Path):
        plaintext = b"PK\x03\x04<document>hello</document>"
        opener = self._make_opener(tmp_path, plaintext)
        cbx_path = r"S:\report.docx.cbx"

        launched = []
        waited = []
        re_encrypted = []
        audited = []

        def launch(tmp, profile, pipe, env):
            launched.append((tmp, profile, pipe, env))
            return 1234  # fake PID

        def wait_close(pid, timeout):
            waited.append(pid)
            return True

        def reenc(tmp, cbx, pw):
            re_encrypted.append((tmp, cbx, pw))

        def audit(action, fhash, kv, ok, err):
            audited.append((action, fhash, kv, ok, err))

        result = opener.open_controlled(
            cbx_path,
            launch_soffice=launch,
            wait_document_close=wait_close,
            re_encrypt=reenc,
            audit=audit,
        )

        assert isinstance(result, OpenResult)
        assert result.changed is False  # content unchanged
        assert result.re_encrypted is False
        assert result.cbx_path == os.path.abspath(cbx_path)
        # session record cleaned up.
        assert opener.session_store.load(result.session_id) is None
        # temp dir removed.
        assert not os.path.exists(os.path.dirname(result.tmp_path))
        # launch called with controlled profile + session pipe.
        assert launched[0][1] == r"S:\.cipherbox-profile\controlled"
        assert launched[0][2] == f"cipherbox-controlled-{result.session_id}"
        assert launched[0][3]["TMP"] == os.path.dirname(result.tmp_path)
        # decrypt + re-encrypt (unchanged -> no re-encrypt) audited.
        assert any(a[0] == "decrypt" for a in audited)
        assert len(re_encrypted) == 0

    def test_open_controlled_changed_triggers_reencrypt(self, tmp_path: Path):
        original = b"PK\x03\x04<document>v1</document>"
        edited = b"PK\x03\x04<document>v2-edited</document>"
        opener = self._make_opener(tmp_path, original)
        cbx_path = r"S:\report.docx.cbx"

        re_encrypted = []
        def reenc(tmp, cbx, pw):
            re_encrypted.append((tmp, cbx, pw))
            # Simulate re-encrypt by overwriting tmp with edited content.
            with open(tmp, "wb") as fh:
                fh.write(edited)

        def launch(tmp, profile, pipe, env):
            # After launch, pretend LO edited the file: write edited content.
            with open(tmp, "wb") as fh:
                fh.write(edited)
            return 999

        def wait_close(pid, timeout):
            return True

        result = opener.open_controlled(
            cbx_path, launch_soffice=launch, wait_document_close=wait_close,
            re_encrypt=reenc,
        )
        assert result.changed is True
        assert result.re_encrypted is True

    def test_open_controlled_wrong_key_raises(self, tmp_path: Path):
        plaintext = b"PK\x03\x04<document>x</document>"
        opener = self._make_opener(tmp_path, plaintext, passwords=[WRONG])
        with pytest.raises(RuntimeError, match="无法解密"):
            opener.open_controlled(r"S:\report.docx.cbx")


# ---------------------------------------------------------------------------
# SingleInstanceMutex
# ---------------------------------------------------------------------------

class TestSingleInstanceMutex:
    def test_mutex_exclusive(self):
        m1 = SingleInstanceMutex(MUTEX_NAME)
        assert m1.acquired() is True
        m2 = SingleInstanceMutex(MUTEX_NAME)
        assert m2.acquired() is False  # already held
        m2.release()
        m1.release()

    def test_mutex_context_manager(self):
        with SingleInstanceMutex(MUTEX_NAME) as m:
            assert m.acquired() is True
        # After exit, another can acquire.
        with SingleInstanceMutex(MUTEX_NAME) as m2:
            assert m2.acquired() is True


# ---------------------------------------------------------------------------
# JobObject (smoke: create + close, no process assigned)
# ---------------------------------------------------------------------------

class TestJobObject:
    def test_job_object_create_close(self):
        job = JobObject()
        job.close()


# ---------------------------------------------------------------------------
# bind_office_children (live 2026-11-18: the stub spawns soffice.bin BEFORE
# assign_process(stub) lands -> bin never inherits the job -> the office
# survives session end -> the next session's launch forwards into the
# survivor and its second UNO bridge cannot register interceptors)
# ---------------------------------------------------------------------------

class FakeJob:
    def __init__(self, fail_on=None):
        self.assigned: list[int] = []
        self.fail_on = fail_on or set()

    def assign_process(self, pid):
        if pid in self.fail_on:
            raise OSError(f"assign refused for {pid}")
        self.assigned.append(pid)


class TestBindOfficeChildren:
    def test_binds_child_appearing_late(self):
        """The normal race: the bin is not born on the first poll."""
        job = FakeJob()
        polls = {"n": 0}

        def find(_pid):
            polls["n"] += 1
            return [] if polls["n"] < 3 else [4242]

        bound = bind_office_children(job, 1000, find=find,
                                     sleep=lambda _s: None, timeout_s=3.0)
        assert bound == 1
        assert job.assigned == [4242]

    def test_binds_every_office_child_once(self):
        job = FakeJob()

        def find(_pid):
            return [111, 222]

        bound = bind_office_children(job, 1000, find=find,
                                     sleep=lambda _s: None, timeout_s=3.0)
        assert bound == 2
        assert job.assigned == [111, 222]

    def test_assign_failure_is_logged_not_raised(self):
        job = FakeJob(fail_on={4242})
        logs: list[str] = []
        bound = bind_office_children(job, 1000, find=lambda _p: [4242],
                                     sleep=lambda _s: None, timeout_s=0.2,
                                     log=logs.append)
        assert bound == 0
        assert job.assigned == []
        assert any("cannot bind" in line for line in logs)

    def test_failed_child_is_attempted_once(self):
        """A refused pid must not be re-attempted/re-logged every poll."""
        job = FakeJob(fail_on={4242})
        logs: list[str] = []
        bind_office_children(job, 1000, find=lambda _p: [4242],
                             sleep=lambda _s: None, timeout_s=0.2,
                             log=logs.append)
        assert len([line for line in logs if "cannot bind" in line]) == 1

    def test_timeout_logs_warning_when_no_child(self):
        """No soffice child ever appears (stub died with its children or the
        launch was forwarded): report, don't fail — terminate-on-close is the
        remaining guard."""
        job = FakeJob()
        logs: list[str] = []
        bound = bind_office_children(job, 1000, find=lambda _p: [],
                                     sleep=lambda _s: None, timeout_s=0.3,
                                     log=logs.append)
        assert bound == 0
        assert any("no office child" in line for line in logs)


# ---------------------------------------------------------------------------
# _cleanup_session_dir (session scratch must not leave shell dirs behind —
# LO's lu*.tmp used to defeat the plain rmdir and recovery then quarantined
# the empty shell as an orphan on every next startup)
# ---------------------------------------------------------------------------

def _make_opener(log) -> ControlledOpener:
    return ControlledOpener(
        container=None, passwords=[], key_version=1,
        session_store=None, log=log)


class TestCleanupSessionDir:
    @staticmethod
    def _make_dir(tmp_path: Path) -> str:
        d = tmp_path / "session"
        (d / "lu9828ec09f.tmp" / "inner").mkdir(parents=True)
        (d / "a.docx").write_bytes(b"plaintext")
        (d / "lu9828ec09f.tmp" / "lock.bin").write_bytes(b"x")
        return str(d)

    def test_removes_dir_with_lo_residue(self, tmp_path: Path):
        logs: list[str] = []
        d = self._make_dir(tmp_path)
        _make_opener(logs.append)._cleanup_session_dir(d)
        assert not os.path.exists(d)
        assert logs == []

    def test_retries_transient_lock_then_succeeds(self, tmp_path: Path, monkeypatch):
        import shutil
        logs: list[str] = []
        d = self._make_dir(tmp_path)
        calls = {"n": 0}
        real_rmtree = shutil.rmtree

        def flaky(path, *args, **kwargs):
            calls["n"] += 1
            if calls["n"] < 3:
                raise OSError("lock held")
            return real_rmtree(path, *args, **kwargs)

        monkeypatch.setattr(shutil, "rmtree", flaky)
        _make_opener(logs.append)._cleanup_session_dir(d, delay_s=0)
        assert not os.path.exists(d)
        assert calls["n"] == 3
        assert logs == []

    def test_permanent_failure_reports_and_does_not_raise(self, tmp_path: Path,
                                                          monkeypatch):
        import shutil
        logs: list[str] = []
        d = self._make_dir(tmp_path)

        def refuse(path, *args, **kwargs):
            raise OSError("locked forever")

        monkeypatch.setattr(shutil, "rmtree", refuse)
        _make_opener(logs.append)._cleanup_session_dir(d, attempts=2, delay_s=0)
        assert os.path.exists(d)  # fail-closed: recovery sweeps it as an orphan
        assert any("not fully removed" in line for line in logs)

    def test_missing_dir_is_noop(self, tmp_path: Path):
        logs: list[str] = []
        _make_opener(logs.append)._cleanup_session_dir(str(tmp_path / "gone"))
        assert logs == []


# ---------------------------------------------------------------------------
# hide_directory (agent work areas stay out of Explorer's default view)
# ---------------------------------------------------------------------------

class TestHideDirectory:
    def test_sets_hidden_attribute(self, tmp_path: Path):
        import ctypes
        d = tmp_path / "h"
        d.mkdir()
        hide_directory(str(d))
        attrs = ctypes.WinDLL("kernel32.dll").GetFileAttributesW(str(d))
        assert attrs != -1 and attrs & 0x2

    def test_idempotent(self, tmp_path: Path):
        import ctypes
        d = tmp_path / "h2"
        d.mkdir()
        hide_directory(str(d))
        hide_directory(str(d))
        attrs = ctypes.WinDLL("kernel32.dll").GetFileAttributesW(str(d))
        assert attrs != -1 and attrs & 0x2

    def test_missing_path_is_noop(self, tmp_path: Path):
        hide_directory(str(tmp_path / "nope"))  # must not raise


# ---------------------------------------------------------------------------
# engine deployment into the controlled profile (live 2026-11-18: the
# controlled profile had NO CipherBoxDataSpace engine -> every payload save
# failed impl_store Io Write/16; the service profile got the engine from
# start_soffice.ps1, the controlled one from nobody)
# ---------------------------------------------------------------------------

class TestEnsureCipherboxEngine:
    def test_deploys_modules_rdb_and_unorc(self, tmp_path: Path):
        from agent.engine_deploy import ensure_cipherbox_engine
        profile = tmp_path / "controlled"
        ensure_cipherbox_engine(str(profile), log=lambda _m: None)
        base = profile / "user"
        assert (base / "Scripts" / "python" / "cipherbox.py").is_file()
        assert (base / "Scripts" / "python" / "cipherbox_crypto.py").is_file()
        rdb = (base / "extensions" / "shared" / "cipherbox" / "components.rdb").read_text()
        assert "com.cipherbox.CipherBoxDataSpace" in rdb
        assert "com.sun.star.comp.oox.crypto.CipherBoxDataSpace" in rdb
        assert (profile.as_uri() + "/user/Scripts/python/cipherbox") in rdb
        unorc_path = (base / "extensions" / "shared" / "registry" /
                      "com.sun.star.comp.deployment.component.PackageRegistryBackend" /
                      "unorc")
        content = unorc_path.read_text()
        assert "UNO_SERVICES=?$SHARED_EXTENSIONS_USER/cipherbox/components.rdb" in content

    def test_second_run_is_noop(self, tmp_path: Path):
        from agent.engine_deploy import ensure_cipherbox_engine
        profile = tmp_path / "controlled"
        ensure_cipherbox_engine(str(profile), log=lambda _m: None)
        rdb = (profile / "user" / "extensions" / "shared" / "cipherbox" /
               "components.rdb")
        before = rdb.read_bytes()
        logs: list[str] = []
        ensure_cipherbox_engine(str(profile), log=logs.append)
        assert logs == []  # hash-guarded: nothing rewritten
        assert rdb.read_bytes() == before

    def test_module_change_redeploys(self, tmp_path: Path):
        from agent.engine_deploy import ensure_cipherbox_engine
        profile = tmp_path / "controlled"
        ensure_cipherbox_engine(str(profile), log=lambda _m: None)
        deployed = profile / "user" / "Scripts" / "python" / "cipherbox.py"
        deployed.write_bytes(b"tampered")
        logs: list[str] = []
        ensure_cipherbox_engine(str(profile), log=logs.append)
        assert any("engine deploy" in line for line in logs)
        assert deployed.read_bytes() != b"tampered"

    def test_missing_source_raises(self, tmp_path: Path):
        from agent.engine_deploy import ensure_cipherbox_engine
        with pytest.raises(FileNotFoundError):
            ensure_cipherbox_engine(str(tmp_path / "p"),
                                    src_dir=str(tmp_path / "nowhere"),
                                    log=lambda _m: None)
