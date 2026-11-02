"""Agent-side plaintext-file encryption pipeline (plan todo 13).

Flow for each watcher-emitted candidate:

    1. ZIP-magic pre-check (PK\x03\x04).  Non-ZIP (e.g. a CFB ciphertext
       container, or a non-Office file with an Office extension) is skipped
       and audited action=encrypt_skip, ok=false.
    2. UNO re-encrypt: ``encrypt_func(plain_path, password)`` -> ``.cbx`` bytes
       (injected; real implementation drives LibreOffice via UNO, see plan
       Wave 0 todo-2 spike).
    3. Write ``<orig>.cbx.tmp`` then atomically rename to ``<orig>.cbx``
       (preserves original extension, e.g. ``a.docx.cbx``).
    4. Delete the plaintext.
    5. POST /events (action=encrypt, file_hash=sha256(plaintext),
       key_version=current version).

Retries on UNO failure (max 5, exponential backoff); never silently deletes
plaintext on failure.

Designed for injection: ``encrypt_func`` and ``audit_reporter`` are callables
so the module can be unit-tested without LibreOffice or a real server.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass
from typing import Callable

OOXML_MAGIC = b"PK\x03\x04"
CBX_SUFFIX = ".cbx"
CBX_TMP_SUFFIX = ".cbx.tmp"

MAX_RETRIES = 5


@dataclass
class EncryptResult:
    plain_path: str
    cbx_path: str | None
    action: str  # "encrypt" | "encrypt_skip"
    ok: bool
    key_version: int | None
    error: str | None = None


class Encryptor:
    """Encrypts plaintext Office files into ``.cbx`` containers."""

    def __init__(
        self,
        *,
        encrypt_func: Callable[[str, str], bytes],
        audit_reporter: Callable[[str, str, int | None, bool, str | None], None],
        get_password: Callable[[], str],
        get_key_version: Callable[[], int | None],
    ) -> None:
        """
        Args:
            encrypt_func(plain_path, password) -> raw .cbx bytes.
            audit_reporter(action, file_hash, key_version, ok, error).
            get_password() -> current master-key password.
            get_key_version() -> current key version number.
        """
        self.encrypt_func = encrypt_func
        self.audit_reporter = audit_reporter
        self.get_password = get_password
        self.get_key_version = get_key_version

    # -- public API -------------------------------------------------------

    def encrypt_file(self, plain_path: str) -> EncryptResult:
        """Encrypt one plaintext Office file.  Never deletes plaintext on failure."""
        plain_path = os.path.abspath(plain_path)
        cbx_path = plain_path + CBX_SUFFIX
        tmp_path = plain_path + CBX_TMP_SUFFIX

        # --- 1. Read plaintext + ZIP-magic pre-check --------------------
        try:
            with open(plain_path, "rb") as fh:
                plaintext = fh.read()
        except OSError as exc:
            return self._fail(plain_path, None, "encrypt_skip",
                              f"cannot read plaintext: {exc}")

        if plaintext[: len(OOXML_MAGIC)] != OOXML_MAGIC:
            file_hash = self._sha256_bytes(plaintext)
            self.audit_reporter(
                "encrypt_skip", file_hash, self.get_key_version(), False,
                "not a ZIP/OOXML file",
            )
            return EncryptResult(
                plain_path=plain_path, cbx_path=None, action="encrypt_skip",
                ok=False, key_version=self.get_key_version(),
                error="not a ZIP/OOXML file",
            )

        # Plaintext hash is needed for the audit event; compute BEFORE deletion.
        file_hash = self._sha256_bytes(plaintext)

        # --- 2. Encrypt via injected UNO func, with retries -------------
        password = self.get_password()
        key_version = self.get_key_version()
        cbx_bytes: bytes | None = None
        last_err: str | None = None

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                cbx_bytes = self.encrypt_func(plain_path, password)
                break
            except Exception as exc:  # UNO/LO failure -> retry
                last_err = str(exc)
                if attempt < MAX_RETRIES:
                    backoff = min(30.0, 0.5 * (2 ** (attempt - 1)))
                    time.sleep(backoff)

        if cbx_bytes is None:
            return self._fail(plain_path, key_version, "encrypt",
                              f"UNO encryption failed after {MAX_RETRIES} attempts: {last_err}")

        # --- 3. Atomic write: .cbx.tmp -> .cbx --------------------------
        try:
            with open(tmp_path, "wb") as fh:
                fh.write(cbx_bytes)
            os.replace(tmp_path, cbx_path)  # atomic rename
        except OSError as exc:
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except OSError:
                pass
            return self._fail(plain_path, key_version, "encrypt",
                              f"cannot write .cbx: {exc}")

        # --- 4. Delete plaintext ---------------------------------------
        delete_error: str | None = None
        try:
            os.remove(plain_path)
        except OSError as exc:
            delete_error = str(exc)
            # .cbx already written; encryption succeeded.  Report ok=True with
            # a delete-warning so callers can decide whether to retry deletion.

        # --- 5. Audit encrypt event ------------------------------------
        self.audit_reporter(
            "encrypt", file_hash, key_version, True, delete_error,
        )
        return EncryptResult(
            plain_path=plain_path, cbx_path=cbx_path, action="encrypt",
            ok=True,  # .cbx was written successfully; delete failure is a warning
            key_version=key_version,
            error=delete_error,
        )

    # -- helpers ----------------------------------------------------------

    def _sha256_bytes(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _fail(self, plain_path: str, key_version: int | None, action: str,
              error: str) -> EncryptResult:
        try:
            with open(plain_path, "rb") as fh:
                file_hash = self._sha256_bytes(fh.read())
        except OSError:
            file_hash = ""
        self.audit_reporter(action, file_hash, key_version, False, error)
        return EncryptResult(
            plain_path=plain_path, cbx_path=None, action=action, ok=False,
            key_version=key_version, error=error,
        )


def encrypt_file_simple(
    plain_path: str,
    *,
    encrypt_func: Callable[[str, str], bytes],
    audit_reporter: Callable[[str, str, int | None, bool, str | None], None],
    get_password: Callable[[], str],
    get_key_version: Callable[[], int | None],
) -> EncryptResult:
    """Convenience functional entry point (one-shot, no state)."""
    enc = Encryptor(
        encrypt_func=encrypt_func,
        audit_reporter=audit_reporter,
        get_password=get_password,
        get_key_version=get_key_version,
    )
    return enc.encrypt_file(plain_path)
