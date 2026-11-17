"""Admin UI support: dashboard summary data (read-only aggregates).

The admin console page (`server/static/admin.html`) needs one call that
returns everything the overview cards + tables render:

    GET /admin/summary  (admin Bearer token) ->
    {
      "keys":     [{"version": n, "created_at": iso}, ...],   # newest first
      "current":  n,                                          # highest version
      "employees":[{"employee","level","tokens","active_tokens",
                    "revoked_tokens","latest_expiry"}, ...],
      "event_count": n,
      "chain":    {"head": hex, "count": n}                   # meta anchors
    }

Deliberately EXCLUDES key material (`keys.key_hex`): the console is meant to
be screen-sharable; agents still fetch material via GET /key as before.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any

from . import audit

__all__ = ["employee_summary", "key_meta", "build_summary"]


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def key_meta(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Key versions WITHOUT key material, newest first."""
    rows = conn.execute(
        "SELECT version, created_at FROM keys ORDER BY version DESC"
    ).fetchall()
    return [
        {"version": int(r["version"]), "created_at": r["created_at"]} for r in rows
    ]


def employee_summary(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Per-employee token rollup, ordered by name.

    active = not revoked AND expires_at > now (ISO strings with the same
    fixed-width format compare correctly lexicographically).
    """
    now = _utcnow_iso()
    rows = conn.execute(
        "SELECT employee,"
        " MAX(level) AS level,"
        " COUNT(*) AS tokens,"
        " SUM(CASE WHEN revoked = 0 AND expires_at > ? THEN 1 ELSE 0 END) AS active_tokens,"
        " SUM(revoked) AS revoked_tokens,"
        " MAX(expires_at) AS latest_expiry"
        " FROM employees GROUP BY employee ORDER BY employee",
        (now,),
    ).fetchall()
    return [
        {
            "employee": r["employee"],
            "level": r["level"],
            "tokens": int(r["tokens"]),
            "active_tokens": int(r["active_tokens"] or 0),
            "revoked_tokens": int(r["revoked_tokens"] or 0),
            "latest_expiry": r["latest_expiry"],
        }
        for r in rows
    ]


def build_summary(conn: sqlite3.Connection) -> dict[str, Any]:
    """Everything the console overview renders, in one response."""
    count_row = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()
    keys = key_meta(conn)
    return {
        "keys": keys,
        "current": keys[0]["version"] if keys else None,
        "employees": employee_summary(conn),
        "event_count": int(count_row["c"]),
        "chain": {
            "head": audit.get_meta(conn, "chain_head"),
            "count": audit.get_meta(conn, "chain_count"),
        },
    }
