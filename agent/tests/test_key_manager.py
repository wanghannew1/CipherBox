"""Tests for agent/key_manager.py (todo 11): DPAPI cache, server fetch, key resolution.

DPAPI is Windows-only; these tests run on Windows.  Server HTTP is mocked
with requests-mock so no real server is needed.
"""

from __future__ import annotations

import io
import os
import zipfile
from unittest.mock import patch

import pytest
import requests_mock

import cipherbox_crypto as crypto
from agent.container import CbxContainer, STREAM_DATASPACEINFO, STREAM_ENCRYPTEDPACKAGE
from agent.key_manager import (
    CachedKey,
    KeyManager,
    KeyNotFoundError,
    KeySet,
    ServerAuthError,
    ServerUnreachableError,
    dpapi_decrypt,
    dpapi_encrypt,
)

PASSWORD_V1 = "alpha-version-one-key-1234"
PASSWORD_V2 = "beta-version-two-key-5678"
FILE_HASH = "0" * 64


# ---------------------------------------------------------------------------
# helpers: build a synthetic .cbx stream map (like agent/container tests)
# ---------------------------------------------------------------------------

def make_stream_map(password: str, plaintext: bytes, with_verifier: bool = True) -> dict:
    iv = os.urandom(crypto.IV_LEN)
    cipher = crypto.aes_cbc(crypto.derive_key(password), iv, plaintext, encrypt=True)
    payload = crypto._i64(len(plaintext)) + iv + cipher
    streams = {STREAM_ENCRYPTEDPACKAGE: payload}
    if with_verifier:
        salt, digest = crypto.make_verifier(password)
        trailer = (
            crypto.VERIFIER_MAGIC
            + len(salt).to_bytes(4, "little")
            + salt
            + len(digest).to_bytes(4, "little")
            + digest
        )
        streams[STREAM_DATASPACEINFO] = b"\x00" * 48 + trailer
    return streams


def make_zip_plaintext() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("content.xml", b"hello world")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# DPAPI round-trip (Windows-only, skips on non-Windows)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(os.name != "nt", reason="DPAPI is Windows-only")
class TestDpapiRoundTrip:
    def test_encrypt_decrypt_roundtrip(self):
        plain = b"sensitive master key material v1"
        enc = dpapi_encrypt(plain)
        assert enc != plain
        assert dpapi_decrypt(enc) == plain

    def test_tampering_fails(self):
        plain = b"tamper me"
        enc = bytearray(dpapi_encrypt(plain))
        enc[-1] ^= 0xFF
        with pytest.raises(Exception):
            dpapi_decrypt(bytes(enc))


# ---------------------------------------------------------------------------
# KeyManager: cache save/load
# ---------------------------------------------------------------------------

class TestCacheRoundTrip:
    def test_save_and_load_cache(self, tmp_path, monkeypatch):
        cache_file = str(tmp_path / "keycache.dat")
        monkeypatch.setattr("agent.key_manager.KEYCACHE_FILE", cache_file)
        # Also patch module-level constant used in __init__ default.
        km = KeyManager("https://x", "tok", cache_file=cache_file)
        ks = KeySet(
            versions=[CachedKey(1, PASSWORD_V1), CachedKey(2, PASSWORD_V2)],
            current=2,
        )
        km.save_cache(ks)
        assert os.path.exists(cache_file)

        loaded = km.load_cache()
        assert loaded is not None
        assert loaded.current == 2
        assert {v.version: v.key for v in loaded.versions} == {1: PASSWORD_V1, 2: PASSWORD_V2}

    def test_load_cache_missing_file_returns_none(self, tmp_path, monkeypatch):
        cache_file = str(tmp_path / "does-not-exist.dat")
        monkeypatch.setattr("agent.key_manager.KEYCACHE_FILE", cache_file)
        km = KeyManager("https://x", "tok", cache_file=cache_file)
        assert km.load_cache() is None


# ---------------------------------------------------------------------------
# KeyManager: ensure_keys (online/offline/auth)
# ---------------------------------------------------------------------------

class TestEnsureKeys:
    @staticmethod
    def _key_set_json():
        return {
            "versions": [
                {"version": 1, "key": PASSWORD_V1},
                {"version": 2, "key": PASSWORD_V2},
            ],
            "current": 2,
        }

    def test_online_fetch_and_cache(self, tmp_path, monkeypatch):
        cache_file = str(tmp_path / "kc.dat")
        km = KeyManager("https://server.example", "tok", cache_file=cache_file)
        with requests_mock.Mocker() as m:
            m.get("https://server.example/key", json=self._key_set_json(), status_code=200)
            ks = km.ensure_keys(online=True)
        assert ks.current == 2
        assert len(ks.versions) == 2
        # Cache file was written.
        assert os.path.exists(cache_file)
        loaded = km.load_cache()
        assert loaded is not None and loaded.current == 2

    def test_offline_uses_cache(self, tmp_path, monkeypatch):
        cache_file = str(tmp_path / "kc.dat")
        km = KeyManager("https://server.example", "tok", cache_file=cache_file)
        # Prime the cache directly.
        km.save_cache(KeySet(
            versions=[CachedKey(1, PASSWORD_V1)],
            current=1,
        ))
        # No network mock -> offline should use cache.
        ks = km.ensure_keys(online=False)
        assert ks.current == 1
        assert ks.versions[0].key == PASSWORD_V1

    def test_offline_no_cache_raises(self, tmp_path, monkeypatch):
        cache_file = str(tmp_path / "kc-missing.dat")
        km = KeyManager("https://server.example", "tok", cache_file=cache_file)
        with pytest.raises(ServerUnreachableError):
            km.ensure_keys(online=False)

    def test_401_raises_server_auth_error(self, tmp_path, monkeypatch):
        cache_file = str(tmp_path / "kc.dat")
        km = KeyManager("https://server.example", "badtok", cache_file=cache_file)
        with requests_mock.Mocker() as m:
            m.get("https://server.example/key", status_code=401, json={"detail": "invalid or missing credentials"})
            with pytest.raises(ServerAuthError):
                km.ensure_keys(online=True)

    def test_unreachable_raises(self, tmp_path, monkeypatch):
        cache_file = str(tmp_path / "kc.dat")
        km = KeyManager("https://127.0.0.1:9", "tok", cache_file=cache_file, timeout=1)
        with pytest.raises(ServerUnreachableError):
            km.ensure_keys(online=True)


# ---------------------------------------------------------------------------
# KeyManager: current_key / resolve_key_for_container
# ---------------------------------------------------------------------------

class TestKeyResolution:
    def test_current_key_returns_highest(self, tmp_path, monkeypatch):
        cache_file = str(tmp_path / "kc.dat")
        km = KeyManager("https://x", "tok", cache_file=cache_file)
        km._keys = KeySet(
            versions=[CachedKey(1, PASSWORD_V1), CachedKey(3, PASSWORD_V2), CachedKey(2, "mid")],
            current=3,
        )
        cur = km.current_key()
        assert cur.version == 3
        assert cur.key == PASSWORD_V2

    def test_resolve_finds_correct_version(self, tmp_path, monkeypatch):
        cache_file = str(tmp_path / "kc.dat")
        km = KeyManager("https://x", "tok", cache_file=cache_file)
        km._keys = KeySet(
            versions=[CachedKey(1, "wrong"), CachedKey(2, PASSWORD_V2)],
            current=2,
        )
        plaintext = make_zip_plaintext()
        container = CbxContainer(make_stream_map(PASSWORD_V2, plaintext), source="<test>")
        matched, recovered = km.resolve_key_for_container(container)
        assert matched.version == 2
        assert matched.key == PASSWORD_V2
        assert recovered == plaintext

    def test_resolve_unknown_version_raises(self, tmp_path, monkeypatch):
        cache_file = str(tmp_path / "kc.dat")
        km = KeyManager("https://x", "tok", cache_file=cache_file)
        km._keys = KeySet(
            versions=[CachedKey(1, "wrong-1"), CachedKey(2, "wrong-2")],
            current=2,
        )
        plaintext = make_zip_plaintext()
        container = CbxContainer(make_stream_map(PASSWORD_V2, plaintext), source="<test>")
        with pytest.raises(KeyNotFoundError):
            km.resolve_key_for_container(container)

    def test_resolve_no_versions_raises(self, tmp_path, monkeypatch):
        cache_file = str(tmp_path / "kc.dat")
        km = KeyManager("https://x", "tok", cache_file=cache_file)
        km._keys = KeySet(versions=[], current=None)
        container = CbxContainer({}, source="<empty>")
        with pytest.raises(KeyNotFoundError):
            km.resolve_key_for_container(container)
