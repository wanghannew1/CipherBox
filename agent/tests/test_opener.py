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
