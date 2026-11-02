"""Master-key issuance/rotation (todo 6 implements).

- `POST /key` (authenticated) returns the FULL version set
  `{"versions": [{"version": n, "key": <64-hex>}, ...], "current": n}` so
  clients sync the whole set and never need to guess a version number.
- Keys are generated with `secrets.token_hex(32)` (64 hex chars, 256-bit
  entropy) — no weak passwords.
- `POST /admin/rotate` (admin only) appends a new version; old versions are
  RETAINED for decrypting old files (forward-only rotation).
- Keys live only in the DB.
"""

from __future__ import annotations

import secrets
import sqlite3
from datetime import datetime, timezone
from typing import Any

from . import database

KEY_HEX_LEN = 64  # 256-bit key -> 64 hex chars


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def get_version_set(conn: sqlite3.Connection) -> dict[str, Any]:
    """Return the full key-version set ordered ascending."""
    versions = database.get_version_set(conn)
    return {
        "versions": [
            {"version": v.version, "key": v.key_hex} for v in versions
        ],
        "current": versions[-1].version if versions else None,
    }


def rotate(conn: sqlite3.Connection) -> dict[str, Any]:
    """Generate and append a new key version (admin only).

    Returns {"version": n, "key": <64-hex>, "current": n} for the newly
    appended version. Old versions are retained.
    """
    rows = database.get_version_set(conn)
    new_version = (rows[-1].version + 1) if rows else 1
    key_hex = secrets.token_hex(32)
    database.insert_key(conn, new_version, key_hex, _utcnow_iso())
    conn.commit()
    return {
        "version": new_version,
        "key": key_hex,
        "current": new_version,
    }
