"""Tests for agent/container.py -- .cbx parsing, verifier probe, decryption, fail-closed.

Layers (plan todo 10):
* pure unit: synthetic stream maps built with cipherbox_crypto (no LibreOffice needed)
* adversarial: corrupt/truncated/wrong-magic inputs -> clear ContainerError, wrong
  password -> WrongKeyError ("密钥错误"), never a silent empty return
* integration: a REAL .cbx produced by the live engine (todo-2 spike product, recorded
  in fixtures/ by make_fixtures.py) must decrypt byte-for-byte to the engine's own
  decrypt, and the verifier probe must accept the right / reject the wrong password.

Run with the PATH python (3.11+):  python -m pytest agent/tests -q
"""

from __future__ import annotations

import io
import os
import zipfile

import pytest

import cipherbox_crypto as crypto
from agent.container import (
    STREAM_DATASPACEINFO,
    STREAM_ENCRYPTEDPACKAGE,
    CbxContainer,
    ContainerError,
    WrongKeyError,
    decrypt_file,
    probe_file,
)

PASSWORD = "correct horse battery staple"
WRONG = "wrong password entirely"
OTHER = "another cached version 9f3e"

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
FIXTURE_CBX = os.path.join(FIXTURES, "reencrypted.docx.cbx")
FIXTURE_PLAIN = os.path.join(FIXTURES, "reencrypted.docx.plain")


# ---------------------------------------------------------------------------
# helpers: build synthetic containers (stream maps) with the shared crypto
# ---------------------------------------------------------------------------


def make_zip_payload(marker: bytes = b"CipherBox round trip marker 4711") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("content.xml", b"payload:" + marker)
        zf.writestr("META-INF/manifest.xml", b"manifest")
    return buf.getvalue()


def encrypt_payload(password: str, plaintext: bytes) -> bytes:
    """EncryptedPackage payload: _i64(len) + iv + AES-256-CBC(pkcs7)."""
    iv = os.urandom(crypto.IV_LEN)
    cipher = crypto.aes_cbc(crypto.derive_key(password), iv, plaintext, encrypt=True)
    return crypto._i64(len(plaintext)) + iv + cipher


def data_space_info_with_verifier(password: str) -> bytes:
    """48-byte base (content irrelevant to the tail parser) + CBPV trailer."""
    salt, digest = crypto.make_verifier(password)
    trailer = (
        crypto.VERIFIER_MAGIC
        + len(salt).to_bytes(4, "little")
        + salt
        + len(digest).to_bytes(4, "little")
        + digest
    )
    return b"\x00" * 48 + trailer


def make_container(
    password: str = PASSWORD,
    plaintext: bytes | None = None,
    with_verifier: bool = True,
) -> CbxContainer:
    plain = plaintext if plaintext is not None else make_zip_payload()
    streams = {STREAM_ENCRYPTEDPACKAGE: encrypt_payload(password, plain)}
    if with_verifier:
        streams[STREAM_DATASPACEINFO] = data_space_info_with_verifier(password)
    return CbxContainer(streams, source="<synthetic>")


# ---------------------------------------------------------------------------
# pure-unit: synthetic containers
# ---------------------------------------------------------------------------


class TestSyntheticContainer:
    def test_round_trip_byte_identical(self):
        plain = make_zip_payload()
        container = make_container(plaintext=plain)
        recovered, used = container.decrypt([PASSWORD])
        assert recovered == plain
        assert used == PASSWORD

    def test_verifier_probe_accepts_and_rejects(self):
        container = make_container()
        assert container.probe_password(PASSWORD) is True
        assert container.probe_password(WRONG) is False

    def test_decrypt_picks_the_right_candidate(self):
        plain = make_zip_payload()
        container = make_container(plaintext=plain)
        recovered, used = container.decrypt([WRONG, PASSWORD, OTHER])
        assert recovered == plain
        assert used == PASSWORD

    def test_wrong_password_raises_key_error(self):
        container = make_container()
        with pytest.raises(WrongKeyError) as excinfo:
            container.decrypt([WRONG, OTHER])
        assert "密钥错误" in str(excinfo.value)

    def test_verifier_is_checked_before_decrypt(self):
        # A matching verifier must be authoritative: corrupt the ciphertext while
        # keeping the verifier intact -> ContainerError (corrupt), NOT WrongKeyError.
        container = make_container()
        payload = bytearray(container._streams[STREAM_ENCRYPTEDPACKAGE])
        payload[-1] ^= 0xFF  # flip a bit in the last cipher block
        broken = CbxContainer(
            {**container._streams, STREAM_ENCRYPTEDPACKAGE: bytes(payload)},
            source="<tampered>",
        )
        with pytest.raises(ContainerError) as excinfo:
            broken.decrypt([PASSWORD])
        assert not isinstance(excinfo.value, WrongKeyError)

    def test_missing_encrypted_package_raises(self):
        container = CbxContainer({"SomeOtherStream": b"data"}, source="<empty>")
        with pytest.raises(ContainerError, match="EncryptedPackage"):
            container.decrypt([PASSWORD])

    def test_truncated_payload_raises(self):
        payload = encrypt_payload(PASSWORD, make_zip_payload())
        short = CbxContainer(
            {STREAM_ENCRYPTEDPACKAGE: payload[: 8 + 16 + 5]}, source="<truncated>"
        )
        with pytest.raises(ContainerError, match="截断|损坏"):
            short.decrypt([PASSWORD])
        # also: ciphertext length not a multiple of 16
        misaligned = CbxContainer(
            {STREAM_ENCRYPTEDPACKAGE: payload[: 8 + 16 + 24]}, source="<misaligned>"
        )
        with pytest.raises(ContainerError, match="16"):
            misaligned.decrypt([PASSWORD])

    def test_empty_candidate_list_raises_key_error(self):
        container = make_container()
        with pytest.raises(WrongKeyError, match="密钥错误"):
            container.decrypt([])


class TestLegacyNoVerifier:
    """Files written before the verifier existed: probe is 'unknown', decrypt tries
    every cached version and requires valid padding + OOXML PK magic."""

    def test_probe_returns_unknown(self):
        container = make_container(with_verifier=False)
        assert container.probe_password(PASSWORD) is None
        assert container.probe_password(WRONG) is None

    def test_decrypt_tries_all_versions_and_wins(self):
        plain = make_zip_payload()
        container = make_container(plaintext=plain, with_verifier=False)
        recovered, used = container.decrypt([WRONG, OTHER, PASSWORD])
        assert recovered == plain
        assert used == PASSWORD

    def test_decrypt_exhausts_versions_into_key_error(self):
        container = make_container(with_verifier=False)
        with pytest.raises(WrongKeyError, match="密钥错误"):
            container.decrypt([WRONG, OTHER])

    def test_non_ooxml_plaintext_is_rejected(self):
        # padding would validate for the right key, but the PK-magic rule must still
        # reject it (legacy success criterion = padding AND OOXML ZIP).
        container = make_container(
            plaintext=b"definitely not a zip file" + b"\x00" * 32,
            with_verifier=False,
        )
        with pytest.raises(WrongKeyError, match="密钥错误"):
            container.decrypt([PASSWORD])


# ---------------------------------------------------------------------------
# adversarial: corrupt files on disk
# ---------------------------------------------------------------------------


class TestCorruptFiles:
    def test_wrong_magic_raises_clear_error(self, tmp_path):
        bad = tmp_path / "fake.docx.cbx"
        bad.write_bytes(b"PK\x03\x04" + b"\x00" * 256)
        with pytest.raises(ContainerError, match="magic"):
            CbxContainer.from_file(bad)

    def test_truncated_cfb_raises_clear_error(self, tmp_path):
        bad = tmp_path / "truncated.cbx"
        bad.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 512)
        with pytest.raises(ContainerError):
            CbxContainer.from_file(bad)

    def test_missing_file_raises_clear_error(self, tmp_path):
        with pytest.raises(ContainerError):
            CbxContainer.from_file(tmp_path / "does-not-exist.cbx")

    def test_corrupted_real_cfb_raises_not_silent(self, tmp_path):
        if not os.path.isfile(FIXTURE_CBX):
            pytest.skip("real .cbx fixture not recorded")
        raw = open(FIXTURE_CBX, "rb").read()
        mangled = tmp_path / "mangled.cbx"
        mangled.write_bytes(raw[:4096])  # truncated CFB mid-stream
        with pytest.raises(ContainerError):
            CbxContainer.from_file(mangled)


# ---------------------------------------------------------------------------
# integration: real .cbx from the live engine (todo-2 spike product)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not (os.path.isfile(FIXTURE_CBX) and os.path.isfile(FIXTURE_PLAIN)),
    reason="fixtures not recorded -- run agent/tests/make_fixtures.py with bundled python",
)
class TestRealEngineProduct:
    def test_decrypt_matches_engine_ground_truth_byte_for_byte(self):
        expected = open(FIXTURE_PLAIN, "rb").read()
        recovered, used = decrypt_file(FIXTURE_CBX, [WRONG, PASSWORD])
        assert recovered == expected, "agent decrypt must equal the engine's own decrypt"
        assert used == PASSWORD
        assert recovered.startswith(b"PK\x03\x04")

    def test_verifier_probe_on_real_file(self):
        assert probe_file(FIXTURE_CBX, PASSWORD) is True
        assert probe_file(FIXTURE_CBX, WRONG) is False

    def test_wrong_password_on_real_file_raises_key_error(self):
        with pytest.raises(WrongKeyError, match="密钥错误"):
            decrypt_file(FIXTURE_CBX, [WRONG, OTHER])

    def test_round_trip_marker_survives(self):
        expected = open(FIXTURE_PLAIN, "rb").read()
        with zipfile.ZipFile(io.BytesIO(expected)) as zf:
            assert any(
                b"CipherBox round trip marker 4711" in zf.read(name)
                for name in zf.namelist()
            )

    def test_container_info(self):
        info = CbxContainer.from_file(FIXTURE_CBX).info()
        assert info.has_verifier is True
        assert STREAM_ENCRYPTEDPACKAGE in info.stream_names
        assert info.declared_length == len(open(FIXTURE_PLAIN, "rb").read())
