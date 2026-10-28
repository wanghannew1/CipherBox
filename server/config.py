"""Server configuration for the cipherbox LAN key/audit server (plan todo 5).

Central place for bind address, HTTPS port, certificate/CA paths, the SQLite
database path, and the token TTL. Every value can be overridden via
environment variables so deployment (todo 20) does not need to edit code:

    CIPHERBOX_HOST       bind address            (default 0.0.0.0)
    CIPHERBOX_PORT       HTTPS port              (default 8443, TLS only)
    CIPHERBOX_DB         SQLite file path        (default server/cipherbox.db)
    CIPHERBOX_CERT_DIR   dir holding ca.crt/server.crt/server.key
                                                  (default server/certs)

The server NEVER opens a plain HTTP listener (no redirect either — a redirect
would make the client send one cleartext request carrying the Bearer token).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

SERVER_ROOT = Path(__file__).resolve().parent

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8443  # HTTPS only; no HTTP port is ever bound.
TOKEN_TTL_DAYS = 90


@dataclass(frozen=True)
class ServerConfig:
    """Resolved runtime configuration (immutable after load)."""

    host: str
    port: int
    db_path: Path
    cert_dir: Path
    ca_cert: Path
    server_cert: Path
    server_key: Path
    token_ttl_days: int = TOKEN_TTL_DAYS


def load_config(
    *,
    host: str | None = None,
    port: int | None = None,
    db_path: str | Path | None = None,
    cert_dir: str | Path | None = None,
) -> ServerConfig:
    """Build a ServerConfig from explicit args, falling back to env/defaults."""
    resolved_host = host if host is not None else os.environ.get("CIPHERBOX_HOST", DEFAULT_HOST)
    resolved_port = port if port is not None else int(os.environ.get("CIPHERBOX_PORT", DEFAULT_PORT))
    resolved_db = Path(
        db_path if db_path is not None else os.environ.get("CIPHERBOX_DB", str(SERVER_ROOT / "cipherbox.db"))
    )
    resolved_cert_dir = Path(
        cert_dir
        if cert_dir is not None
        else os.environ.get("CIPHERBOX_CERT_DIR", str(SERVER_ROOT / "certs"))
    )
    return ServerConfig(
        host=resolved_host,
        port=resolved_port,
        db_path=resolved_db,
        cert_dir=resolved_cert_dir,
        ca_cert=resolved_cert_dir / "ca.crt",
        server_cert=resolved_cert_dir / "server.crt",
        server_key=resolved_cert_dir / "server.key",
    )
