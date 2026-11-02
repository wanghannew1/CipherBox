"""Agent client configuration: parse config/client.json + DPAPI employee token.

The file is machine-written by ``deploy/install.ps1`` (todo 21) with these
keys: ``server_url, ca_cert_file, protected_dir, temp_root, service_profile,
controlled_profile, session_dir, keycache, audit_queue``.  Relative values
inside the JSON resolve against the repository root; the ``--token-file``
path resolves against the current directory (standard CLI semantics).

The employee token never sits plaintext on disk: install.ps1 writes it
DPAPI-protected (CurrentUser scope); it is decrypted here via
``agent/key_manager.dpapi_decrypt`` (reused, not duplicated).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from agent.key_manager import dpapi_decrypt

REPO_ROOT = Path(__file__).resolve().parents[1]

REQUIRED_KEYS = (
    "server_url", "ca_cert_file", "protected_dir", "temp_root",
    "service_profile", "controlled_profile", "session_dir", "keycache",
    "audit_queue",
)

# Only these are filesystem paths; server_url is a URL and must stay verbatim.
PATH_KEYS = frozenset(REQUIRED_KEYS) - {"server_url"}


class ConfigError(Exception):
    """Client config or token file is missing, malformed, or undecryptable."""


@dataclass(frozen=True, slots=True)
class AgentConfig:
    """Resolved client configuration (immutable after load)."""

    server_url: str
    ca_cert_file: str  # "" = no pinned CA (system trust)
    protected_dir: str
    temp_root: str
    service_profile: str
    controlled_profile: str
    session_dir: str
    keycache: str
    audit_queue: str

    @property
    def ca_bundle(self) -> str | None:
        return self.ca_cert_file or None


@dataclass(frozen=True, slots=True)
class LoadedConfig:
    """AgentConfig plus the DPAPI-decrypted employee token (never logged)."""

    config: AgentConfig
    token: str


def load_config(config_path: str | Path, token_file: str | Path) -> LoadedConfig:
    """Parse client.json, resolve paths, and DPAPI-decrypt the employee token."""
    path = Path(config_path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as exc:
        raise ConfigError(f"client config not found: {path}") from exc
    except OSError as exc:
        raise ConfigError(f"cannot read client config {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"client config {path} is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"client config {path} must be a JSON object")

    missing = [key for key in REQUIRED_KEYS if key not in raw]
    if missing:
        raise ConfigError(f"client config missing keys: {', '.join(missing)}")
    values = {
        key: (_resolve(str(raw[key])) if key in PATH_KEYS else str(raw[key]))
        for key in REQUIRED_KEYS
    }
    config = AgentConfig(**values)

    token = _load_token(token_file)
    return LoadedConfig(config=config, token=token)


def _resolve(value: str) -> str:
    """Normalize one path; relative paths anchor at the repository root."""
    if not value:
        return value  # "" = "unset" (e.g. no CA pin) — never anchor it
    if not os.path.isabs(value):
        return os.path.normpath(os.path.join(str(REPO_ROOT), value))
    return os.path.normpath(value)


def _load_token(token_file: str | Path) -> str:
    path = Path(token_file)
    try:
        encrypted = path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read token file {path}: {exc}") from exc
    try:
        plain = dpapi_decrypt(encrypted)
    except Exception as exc:
        raise ConfigError(
            f"DPAPI decrypt failed for {path} "
            f"(token may be bound to another user or machine): {exc}"
        ) from exc
    token = plain.decode("utf-8", errors="replace").strip()
    if not token:
        raise ConfigError(f"token file {path} decrypts to an empty value")
    return token
