"""Employee token lifecycle: issue / verify / renew / revoke.

Design rules (plan todo 5):
- Only the SHA-256 hex digest of a token is ever stored (`employees.token_hash`).
- TTL is 90 days from `issued_at`.
- Renewal slides `expires_at` to now + TTL and is only valid for a
  non-expired, non-revoked token.
- Revocation sets `revoked = 1`; revoked or expired tokens verify as None
  so the API layer answers a uniform 401 with no information leak.

All functions accept an optional `now` so tests can derive expiry
explicitly instead of sleeping or freezing the clock.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Literal

from . import db

Level = Literal["admin", "employee"]

TOKEN_TTL = timedelta(days=90)

_TS_FMT = "%Y-%m-%dT%H:%M:%S.%f%z"


def _iso(ts: datetime) -> str:
    # Uniform microseconds + offset keeps stored strings strictly ordered
    # and round-trippable via datetime.fromisoformat.
    return ts.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hash_token(token: str) -> str:
    """SHA-256 hex digest of a plaintext bearer token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_token(
    conn: sqlite3.Connection,
    employee: str,
    level: Level,
    *,
    now: datetime | None = None,
) -> str:
    """Issue a new token; returns the plaintext (shown to the caller once)."""
    issued = now if now is not None else _utcnow()
    token = secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO employees (token_hash, employee, level, issued_at, expires_at, revoked)"
        " VALUES (?, ?, ?, ?, ?, 0)",
        (hash_token(token), employee, level, _iso(issued), _iso(issued + TOKEN_TTL)),
    )
    conn.commit()
    return token


def verify_token(
    conn: sqlite3.Connection,
    token: str,
    *,
    now: datetime | None = None,
) -> db.EmployeeToken | None:
    """Resolve a plaintext token to its record, or None.

    Unknown, revoked, and expired tokens all collapse to None so callers
    cannot distinguish them (no information leak).
    """
    if not token:
        return None
    at = now if now is not None else _utcnow()
    rec = db.get_by_hash(conn, hash_token(token))
    if rec is None or rec.revoked:
        return None
    if datetime.fromisoformat(rec.expires_at) <= at:
        return None
    return rec


def renew_token(
    conn: sqlite3.Connection,
    token_hash: str,
    *,
    now: datetime | None = None,
) -> datetime | None:
    """Slide expires_at to now + TTL for a still-valid token.

    Returns the new expires_at, or None if the token is no longer valid
    (defensive re-check; the auth dependency has already verified it).
    """
    at = now if now is not None else _utcnow()
    new_expiry = at + TOKEN_TTL
    cur = conn.execute(
        "UPDATE employees SET expires_at = ?"
        " WHERE token_hash = ? AND revoked = 0 AND expires_at > ?",
        (_iso(new_expiry), token_hash, _iso(at)),
    )
    conn.commit()
    if cur.rowcount != 1:
        return None
    return new_expiry


def revoke_employee(conn: sqlite3.Connection, employee: str) -> int:
    """Revoke every active token of one employee; returns rows revoked."""
    cur = conn.execute(
        "UPDATE employees SET revoked = 1 WHERE employee = ? AND revoked = 0",
        (employee,),
    )
    conn.commit()
    return cur.rowcount
