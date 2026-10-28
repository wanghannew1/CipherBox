"""Master-key issuance/rotation — RESERVED INTERFACE (todo 6 implements).

Contract for todo 6 (plan lines 115-120):
- `POST /key` (authenticated) returns the FULL version set
  `{"versions": [{"version": n, "key": <64-hex>}, ...], "current": n}` so
  clients sync the whole set and never need to guess a version number.
- Keys are generated with `secrets.token_hex(32)` (64 hex chars, 256-bit
  entropy) — no weak passwords.
- `POST /admin/rotate` (admin only) appends a new version; old versions are
  RETAINED for decrypting old files (forward-only rotation).
- Keys live only in the DB, DPAPI-wrapped under the dedicated service
  account context (todo 20 (6)).

Until todo 6 lands, `get_version_set` returns the placeholder envelope the
todo-5 acceptance requires (`GET /key` -> 200 with a placeholder body).
"""

from __future__ import annotations

import sqlite3
from typing import Any


def get_version_set(conn: sqlite3.Connection) -> dict[str, Any]:
    """Return the full key-version set. Placeholder until todo 6."""
    return {"versions": [], "current": None}


def rotate(conn: sqlite3.Connection) -> dict[str, Any]:
    """Generate and append a new key version. Reserved for todo 6."""
    raise NotImplementedError("key rotation is implemented in todo 6")
