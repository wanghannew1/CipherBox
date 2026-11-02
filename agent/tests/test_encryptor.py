"""Tests for agent/encryptor.py (todo 13): ZIP pre-check, UNO encrypt, retries, audit.

All external dependencies (UNO/LibreOffice, server) are injected as callables
and mocked here.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from agent.encryptor import (
    CBX_SUFFIX,
    CBX_TMP_SUFFIX,
    EncryptResult,
    Encryptor,
    MAX_RETRIES,
    OOXML_MAGIC,
    encrypt_file_simple,
)

PLAIN_DOCX = b"PK\x03\x04" + b"<fake-docx></fake-docx>"
PLAIN_TXT = b"this is not a zip file"
PASSWORD = "master-password-v1"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _mk_plain(root: str, name: str, content: bytes) -> str:
    full = os.path.join(root, name)
    with open(full, "wb") as fh:
        fh.write(content)
    return full


def _make_encryptor(root: str, *, encrypt_side_effect=None, audit_calls=None):
    """Build an Encryptor with injected callbacks, recording audit calls."""
    calls = [] if audit_calls is None else audit_calls

    def encrypt_func(plain_path: str, password: str) -> bytes:
        if encrypt_side_effect is not None:
            encrypt_side_effect(plain_path, password)
        # Produce a fake .cbx: OLE2 magic + marker.
        return b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"FAKE-CBX:" + os.path.basename(plain_path).encode()

    def audit_reporter(action, file_hash, key_version, ok, error):
        calls.append((action, file_hash, key_version, ok, error))

    enc = Encryptor(
        encrypt_func=encrypt_func,
        audit_reporter=audit_reporter,
        get_password=lambda: PASSWORD,
        get_key_version=lambda: 3,
    )
    return enc, calls


# ---------------------------------------------------------------------------
# encrypt_file success path
# ---------------------------------------------------------------------------

class TestEncryptSuccess:
    def test_encrypt_docx_creates_cbx_and_deletes_plain(self, tmp_path: Path):
        root = str(tmp_path)
        plain = _mk_plain(root, "report.docx", PLAIN_DOCX)
        enc, calls = _make_encryptor(root)

        result = enc.encrypt_file(plain)

        assert isinstance(result, EncryptResult)
        assert result.action == "encrypt"
        assert result.ok is True
        assert result.key_version == 3
        assert result.error is None
        assert result.cbx_path == plain + CBX_SUFFIX
        assert os.path.exists(result.cbx_path)
        assert not os.path.exists(plain)  # plaintext deleted
        # .cbx.tmp must not linger.
        assert not os.path.exists(plain + CBX_TMP_SUFFIX)
        # Audit: one encrypt event with plaintext hash.
        assert len(calls) == 1
        assert calls[0][0] == "encrypt"
        assert calls[0][3] is True  # ok
        assert calls[0][4] is None or calls[0][4] == ""  # no error

    def test_encrypt_xlsx_and_pptx(self, tmp_path: Path):
        root = str(tmp_path)
        for name in ("budget.xlsx", "deck.pptx"):
            plain = _mk_plain(root, name, PLAIN_DOCX)
            enc, calls = _make_encryptor(root)
            result = enc.encrypt_file(plain)
            assert result.ok is True
            assert result.cbx_path == plain + CBX_SUFFIX
            assert os.path.exists(result.cbx_path)
            assert not os.path.exists(plain)


# ---------------------------------------------------------------------------
# ZIP pre-check (encrypt_skip)
# ---------------------------------------------------------------------------

class TestEncryptSkip:
    def test_non_zip_file_skipped_and_retained(self, tmp_path: Path):
        root = str(tmp_path)
        plain = _mk_plain(root, "notes.txt", PLAIN_TXT)
        enc, calls = _make_encryptor(root)

        result = enc.encrypt_file(plain)

        assert result.action == "encrypt_skip"
        assert result.ok is False
        assert result.cbx_path is None
        assert os.path.exists(plain)  # plaintext retained
        assert not os.path.exists(plain + CBX_SUFFIX)
        # encrypt_func must NOT have been called.
        assert len(calls) == 1
        assert calls[0][0] == "encrypt_skip"
        assert calls[0][3] is False  # ok=false

    def test_empty_file_skipped(self, tmp_path: Path):
        root = str(tmp_path)
        plain = _mk_plain(root, "empty.docx", b"")
        enc, calls = _make_encryptor(root)
        result = enc.encrypt_file(plain)
        assert result.action == "encrypt_skip"
        assert result.ok is False
        assert os.path.exists(plain)


# ---------------------------------------------------------------------------
# UNO encryption failure + retries
# ---------------------------------------------------------------------------

class TestEncryptFailure:
    def test_uno_failure_retries_then_fails_keeps_plain(self, tmp_path: Path):
        root = str(tmp_path)
        plain = _mk_plain(root, "report.docx", PLAIN_DOCX)
        call_count = {"n": 0}

        def boom(plain_path, password):
            call_count["n"] += 1
            raise RuntimeError("UNO disconnected")

        enc, calls = _make_encryptor(root, encrypt_side_effect=boom)
        result = enc.encrypt_file(plain)

        assert result.action == "encrypt"
        assert result.ok is False
        assert result.cbx_path is None
        assert result.error is not None and "UNO" in result.error
        assert call_count["n"] == MAX_RETRIES
        assert os.path.exists(plain)  # plaintext retained on failure
        # Audit: one encrypt event with ok=false.
        assert len(calls) == 1
        assert calls[0][0] == "encrypt"
        assert calls[0][3] is False

    def test_uno_succeeds_on_second_attempt(self, tmp_path: Path):
        root = str(tmp_path)
        plain = _mk_plain(root, "report.docx", PLAIN_DOCX)
        call_count = {"n": 0}

        def flaky(plain_path, password):
            call_count["n"] += 1
            if call_count["n"] < 2:
                raise RuntimeError("transient UNO error")
            return b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"FAKE-CBX"

        enc, calls = _make_encryptor(root, encrypt_side_effect=flaky)
        result = enc.encrypt_file(plain)
        assert result.ok is True
        assert call_count["n"] == 2
        assert os.path.exists(result.cbx_path)


# ---------------------------------------------------------------------------
# plaintext-delete failure (cbx already written)
# ---------------------------------------------------------------------------

class TestDeleteFailure:
    def test_delete_failure_still_reports_ok(self, tmp_path: Path):
        root = str(tmp_path)
        plain = _mk_plain(root, "report.docx", PLAIN_DOCX)
        enc, calls = _make_encryptor(root)

        with patch("os.remove", side_effect=OSError("locked")):
            result = enc.encrypt_file(plain)

        assert result.ok is True  # cbx was written
        assert result.error is not None and "locked" in result.error
        assert os.path.exists(plain)  # plaintext not deleted
        assert os.path.exists(plain + CBX_SUFFIX)  # cbx exists
        # Audit: ok=True with error detail.
        assert len(calls) == 1
        assert calls[0][0] == "encrypt"
        assert calls[0][3] is True
        assert "locked" in calls[0][4]


# ---------------------------------------------------------------------------
# functional entry point
# ---------------------------------------------------------------------------

class TestFunctionalEntry:
    def test_encrypt_file_simple(self, tmp_path: Path):
        root = str(tmp_path)
        plain = _mk_plain(root, "report.docx", PLAIN_DOCX)
        calls = []

        def enc_func(p, pw):
            return b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"FAKE"

        def audit(action, fhash, kv, ok, err):
            calls.append((action, fhash, kv, ok, err))

        result = encrypt_file_simple(
            plain,
            encrypt_func=enc_func,
            audit_reporter=audit,
            get_password=lambda: PASSWORD,
            get_key_version=lambda: 1,
        )
        assert result.ok is True
        assert result.cbx_path == plain + CBX_SUFFIX
        assert calls[0][0] == "encrypt"
        assert calls[0][2] == 1
