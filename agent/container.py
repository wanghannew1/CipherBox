"""Agent-side ``.cbx`` (CipherBox DataSpaces) container parser and decryptor.

A ``.cbx`` file is an MS-OFFCRYPTO DataSpaces CFB (OLE2) container produced by the
LibreOffice ``CipherBoxDataSpace`` engine with these streams::

    \\x06DataSpaces/DataSpaceMap
    \\x06DataSpaces/Version
    \\x06DataSpaces/DataSpaceInfo/CipherBoxDataSpace   (+ optional CBPV verifier trailer)
    \\x06DataSpaces/TransformInfo/CipherBoxTransform/\\x06Primary
    EncryptedPackage                                    (i64 len + 16-byte IV + AES-256-CBC)

This module parses the container read-only via ``olefile`` and decrypts the payload with
the *same* pure-cryptography implementation the engine uses (``cipherbox_crypto``), so no
LibreOffice / UNO dependency is needed on the Agent.

Password selection:

* verifier present (files written by todo-10-era engines): the verifier in the
  DataSpaceInfo trailer is authoritative -- the first candidate that matches it is used;
  if none matches, a :class:`WrongKeyError` is raised *before* any decryption attempt.
* verifier absent (legacy files): "unknown" -- every cached candidate is tried in order;
  success requires valid PKCS#7 padding *and* a plaintext starting with ``PK\\x03\\x04``
  (OOXML is always a ZIP).  Exhausting all candidates raises :class:`WrongKeyError`.

Corrupt input (wrong magic, truncated CFB, missing/truncated payload, non-aligned
ciphertext) raises :class:`ContainerError` -- never a silent empty return.

Honest residual (format-level, shared with the engine): the payload is AES-CBC *without*
a MAC, so a mid-stream ciphertext bit-flip that leaves the final block's padding intact
decrypts "successfully" into a locally-corrupted plaintext.  The in-LO engine behaves
identically (no integrity check exists in the format); detecting this requires a format
change (HMAC), which is out of scope for the extraction todo.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Mapping, Optional, Tuple, Union

try:
    import olefile
except ImportError as exc:  # pragma: no cover - environment guard
    raise ImportError(
        "agent/container.py requires olefile (pip install olefile) to parse .cbx CFB containers"
    ) from exc

try:
    import cipherbox_crypto as crypto
except ImportError:  # repo layout: lo-encryption-demo/src next to agent/
    sys.path.insert(
        0, str(Path(__file__).resolve().parents[1] / "lo-encryption-demo" / "src")
    )
    import cipherbox_crypto as crypto

PathLike = Union[str, os.PathLike]

STREAM_DATASPACEINFO = "\x06DataSpaces/DataSpaceInfo/CipherBoxDataSpace"
STREAM_ENCRYPTEDPACKAGE = "EncryptedPackage"

OOXML_MAGIC = b"PK\x03\x04"
_OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_LENGTH_PREFIX_LEN = 8  # signed little-endian i64 plaintext length
_MIN_PAYLOAD_LEN = _LENGTH_PREFIX_LEN + crypto.IV_LEN + 16  # header + at least one block


class ContainerError(Exception):
    """The .cbx container is corrupt, truncated, or not a CipherBox CFB file at all."""


class WrongKeyError(ContainerError):
    """密钥错误: no candidate password verifies against / decrypts this container."""


@dataclass(frozen=True)
class ContainerInfo:
    """Metadata about a parsed .cbx container (no plaintext)."""

    source: str
    has_verifier: bool
    declared_length: int
    payload_length: int
    stream_names: Tuple[str, ...]


def _read_cfb_streams(path: PathLike) -> Dict[str, bytes]:
    """Read every stream of a CFB container into memory (read-only, olefile)."""
    path_str = os.fspath(path)
    try:
        with open(path_str, "rb") as probe:
            magic = probe.read(len(_OLE2_MAGIC))
    except OSError as exc:
        raise ContainerError("无法读取 .cbx 文件 %s: %s" % (path_str, exc)) from exc
    if magic != _OLE2_MAGIC:
        raise ContainerError(
            "不是有效的 CipherBox 容器: %s 缺少 CFB/OLE2 magic "
            "(got %s, expected %s) -- 文件可能不是 .cbx 或已损坏"
            % (path_str, magic.hex() or "<empty>", _OLE2_MAGIC.hex())
        )
    try:
        ole = olefile.OleFileIO(path_str)
    except Exception as exc:  # olefile raises OSError/OlefileError depending on version
        raise ContainerError(
            "CFB 容器解析失败: %s (%s) -- 文件可能被截断或损坏" % (path_str, exc)
        ) from exc
    try:
        streams: Dict[str, bytes] = {}
        for entry in ole.listdir(streams=True, storages=False):
            name = "/".join(entry)
            try:
                streams[name] = ole.openstream(entry).read()
            except Exception as exc:
                raise ContainerError(
                    "读取流 %r 失败: %s -- 容器可能被截断或损坏" % (name, exc)
                ) from exc
        return streams
    finally:
        ole.close()


class CbxContainer:
    """A parsed .cbx container: stream map + verifier probe + payload decryption."""

    def __init__(self, streams: Mapping[str, bytes], source: str = "<memory>") -> None:
        self._streams: Dict[str, bytes] = dict(streams)
        self._source = source

    # -- construction -----------------------------------------------------

    @classmethod
    def from_file(cls, path: PathLike) -> "CbxContainer":
        """Parse a .cbx file (read-only).  Corrupt input raises ContainerError."""
        streams = _read_cfb_streams(path)
        return cls(streams, source=os.fspath(path))

    # -- introspection ----------------------------------------------------

    @property
    def verifier(self) -> Tuple[Optional[bytes], Optional[bytes]]:
        """``(salt, hash)`` from the DataSpaceInfo trailer, or ``(None, None)``."""
        blob = self._streams.get(STREAM_DATASPACEINFO, b"")
        return crypto._parse_verifier(blob)

    @property
    def has_verifier(self) -> bool:
        salt, digest = self.verifier
        return salt is not None and digest is not None

    def info(self) -> ContainerInfo:
        payload = self._streams.get(STREAM_ENCRYPTEDPACKAGE, b"")
        declared = -1
        if len(payload) >= _LENGTH_PREFIX_LEN:
            declared = int.from_bytes(payload[:_LENGTH_PREFIX_LEN], "little", signed=True)
        return ContainerInfo(
            source=self._source,
            has_verifier=self.has_verifier,
            declared_length=declared,
            payload_length=len(payload),
            stream_names=tuple(sorted(self._streams)),
        )

    # -- password handling --------------------------------------------------

    def probe_password(self, password: str) -> Optional[bool]:
        """Check ``password`` against the file's verifier.

        Returns True/False when a verifier is present; returns None ("unknown") for
        legacy files without a verifier, where only a full decrypt attempt can tell.
        """
        salt, digest = self.verifier
        if salt is None or digest is None:
            return None
        return crypto.verifier_matches(password, salt, digest)

    def _payload_parts(self) -> Tuple[int, bytes, bytes]:
        """Split EncryptedPackage into (declared length, iv, ciphertext) with validation."""
        if STREAM_ENCRYPTEDPACKAGE not in self._streams:
            raise ContainerError(
                "容器 %s 缺少 EncryptedPackage 流 -- 不是 CipherBox 加密封装"
                % self._source
            )
        payload = self._streams[STREAM_ENCRYPTEDPACKAGE]
        if len(payload) < _MIN_PAYLOAD_LEN:
            raise ContainerError(
                "EncryptedPackage 载荷过短 (%d 字节, 至少 %d) -- 容器被截断或损坏"
                % (len(payload), _MIN_PAYLOAD_LEN)
            )
        declared = int.from_bytes(payload[:_LENGTH_PREFIX_LEN], "little", signed=True)
        iv = payload[_LENGTH_PREFIX_LEN : _LENGTH_PREFIX_LEN + crypto.IV_LEN]
        cipher_text = payload[_LENGTH_PREFIX_LEN + crypto.IV_LEN :]
        if not cipher_text or len(cipher_text) % 16:
            raise ContainerError(
                "密文长度 %d 非 16 字节对齐 -- 容器被截断或损坏" % len(cipher_text)
            )
        return declared, iv, cipher_text

    def _decrypt_with(self, password: str, iv: bytes, cipher_text: bytes) -> bytes:
        """Decrypt with one candidate; ValueError from padding propagates."""
        return crypto.aes_cbc(crypto.derive_key(password), iv, cipher_text, encrypt=False)

    def decrypt(self, passwords: Iterable[str]) -> Tuple[bytes, str]:
        """Decrypt the EncryptedPackage payload.

        ``passwords`` are the cached key-version candidates (current first).  Returns
        ``(plaintext, password_used)`` so the caller can record the key version.

        Raises :class:`WrongKeyError` (密钥错误) when no candidate works, and
        :class:`ContainerError` when the container itself is corrupt.
        """
        candidates = [p for p in passwords if p]
        if not candidates:
            raise WrongKeyError("密钥错误: 未提供任何候选口令/密钥版本")
        _declared, iv, cipher_text = self._payload_parts()

        salt, digest = self.verifier
        if salt is not None and digest is not None:
            # Verifier is authoritative: reject wrong passwords before decrypting.
            matches = [
                p for p in candidates if crypto.verifier_matches(p, salt, digest)
            ]
            if not matches:
                raise WrongKeyError(
                    "密钥错误: %d 个候选口令均未通过文件校验值 (verifier) 验证"
                    % len(candidates)
                )
            password = matches[0]
            try:
                plain = self._decrypt_with(password, iv, cipher_text)
            except ValueError as exc:
                raise ContainerError(
                    "校验值匹配但解密失败 (padding 非法) -- 容器已损坏: %s" % exc
                ) from exc
            return plain, password

        # Legacy file without a verifier: try every cached version; success means
        # padding valid AND an OOXML ZIP payload (PK\x03\x04).
        for password in candidates:
            try:
                plain = self._decrypt_with(password, iv, cipher_text)
            except ValueError:
                continue  # padding invalid -> wrong candidate
            if plain.startswith(OOXML_MAGIC):
                return plain, password
        raise WrongKeyError(
            "密钥错误: 无校验值的旧版容器, %d 个候选版本均无法解密 "
            "(padding 或 OOXML magic 校验失败)" % len(candidates)
        )


# ---------------------------------------------------------------------------
# Convenience wrappers
# ---------------------------------------------------------------------------


def probe_file(path: PathLike, password: str) -> Optional[bool]:
    """Verifier probe on a .cbx file: True/False, or None for legacy files."""
    return CbxContainer.from_file(path).probe_password(password)


def decrypt_file(path: PathLike, passwords: Iterable[str]) -> Tuple[bytes, str]:
    """Decrypt a .cbx file; returns (plaintext, password_used)."""
    return CbxContainer.from_file(path).decrypt(passwords)
