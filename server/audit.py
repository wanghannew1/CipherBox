"""Audit event recording (todo 7 implements).

Contract:
- `POST /events` (authenticated) persists
  `events(id, ts, employee, file_hash, action, key_version, machine, ok, prev_hash, mac)`.
- `employee` is ALWAYS resolved server-side from the Bearer token (the
  `employees.employee` column); a same-named request-body field is rejected
  with 422 so nobody can impersonate another employee.
- `file_hash` = sha256 of the PLAINTEXT content; the server never receives
  or stores file content — metadata JSON only.
- `GET /events` (admin) supports pagination and filtering by
  `key_version` / `action` / `employee`.

HMAC chain (todo 7 + todo 27):
- Every row gets row-level HMAC (key = server HMAC key, never logged).
- `prev_hash` = previous row's `mac`; genesis row uses HMAC(key, "genesis").
- In addition to per-row chain, a running chain head `meta(chain_head, chain_count)`
  is maintained OUTSIDE the events table, updated in the same transaction.
  chain_head_n = HMAC(key, chain_head_{n-1} || mac_n).
  This cannot be recomputed from table data alone, so whole-table rollback is
  detectable.
"""

from __future__ import annotations

import hmac
import sqlite3
from datetime import datetime, timezone
from typing import Any

from . import database
from .models import AuditEvent, EmployeeToken

_GENESIS_SEED = b"cipherbox-audit-genesis"


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _chain_mac(key: bytes, message: bytes) -> str:
    return hmac.new(key, message, hashlib.sha256).hexdigest()


import hashlib  # noqa: E402  (placed after use to keep module docstring at top)


def _genesis_mac(key: bytes) -> str:
    return _chain_mac(key, _GENESIS_SEED)


def _mac_for_event(key: bytes, prev_hash: str, fields: tuple) -> str:
    """Row-level mac = HMAC(key, prev_hash || ts || employee || file_hash || action || key_version || machine || ok)."""
    payload = prev_hash.encode("utf-8") + b"|" + b"|".join(
        str(f).encode("utf-8") for f in fields
    )
    return _chain_mac(key, payload)


def _new_event_id(conn: sqlite3.Connection) -> int:
    """Return next event id (AUTOINCREMENT-safe peek)."""
    row = conn.execute("SELECT COALESCE(MAX(id), 0) AS m FROM events").fetchone()
    return int(row["m"]) + 1


def record_event(
    conn: sqlite3.Connection,
    rec: EmployeeToken,
    payload: dict[str, Any],
    *,
    hmac_key: bytes,
) -> dict[str, Any]:
    """Persist one audit event with HMAC chain + running chain-head anchor.

    Raises ValueError(422-equivalent) if payload contains a forbidden
    `employee` field (impersonation) or missing/invalid `file_hash`.
    """
    # employee is ALWAYS resolved server-side from the token — never from body.
    if "employee" in payload:
        raise ValueError("request body must not contain 'employee' (resolved from token)")

    file_hash = payload.get("file_hash")
    if not isinstance(file_hash, str) or len(file_hash) != 64:
        raise ValueError("'file_hash' must be a 64-char hex sha256")
    try:
        int(file_hash, 16)
    except ValueError:
        raise ValueError("'file_hash' must be valid hexadecimal")

    action = str(payload.get("action", ""))
    key_version = payload.get("key_version")
    machine = payload.get("machine")
    ok = bool(payload.get("ok", True))

    ts = _utcnow_iso()
    event_id = _new_event_id(conn)

    last = database.get_last_event(conn)
    prev_hash = last.mac if last is not None else _genesis_mac(hmac_key)

    mac_fields = (ts, rec.employee, file_hash, action, key_version, machine, ok)
    mac = _mac_for_event(hmac_key, prev_hash, mac_fields)

    database.insert_event(
        conn,
        ts=ts,
        employee=rec.employee,
        file_hash=file_hash,
        action=action,
        key_version=key_version,
        machine=machine,
        ok=ok,
        prev_hash=prev_hash,
        mac=mac,
    )

    # Update running chain-head anchor OUTSIDE the events table (same transaction).
    # chain_head_n = HMAC(key, chain_head_{n-1} || mac_n); initial = HMAC(key, "genesis").
    current_head = get_meta(conn, "chain_head")
    if current_head is None:
        current_head = _genesis_mac(hmac_key)
    chain_head = _chain_mac(hmac_key, (current_head + mac).encode("utf-8"))
    count = database.count_events(conn)
    _upsert_meta(conn, "chain_head", chain_head)
    _upsert_meta(conn, "chain_count", str(count))

    return {
        "recorded": True,
        "id": event_id,
        "employee": rec.employee,
        "mac": mac,
        "prev_hash": prev_hash,
    }


def query_events(
    conn: sqlite3.Connection,
    *,
    key_version: int | None = None,
    action: str | None = None,
    employee: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[AuditEvent]:
    """Paginated admin query with key_version/action/employee filters."""
    return database.query_events(
        conn,
        key_version=key_version,
        action=action,
        employee=employee,
        limit=limit,
        offset=offset,
    )


# ---------------------------------------------------------------------------
# meta key-value store (chain_head / chain_count anchor, outside events table)
# ---------------------------------------------------------------------------

_META_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def _ensure_meta(conn: sqlite3.Connection) -> None:
    conn.execute(_META_SCHEMA)


def _upsert_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    _ensure_meta(conn)
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?, ?)"
        " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def get_meta(conn: sqlite3.Connection, key: str) -> str | None:
    _ensure_meta(conn)
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row is not None else None


def verify_audit_chain(conn: sqlite3.Connection, hmac_key: bytes) -> dict[str, Any]:
    """Verify the full HMAC chain + running chain-head anchor.

    Returns {"ok": True, "count": N} or raises ValueError with the offending
    row id / reason on first failure.
    """
    events = database.query_events(conn, limit=10_000_000, offset=0)
    if not events:
        expected_head = _genesis_mac(hmac_key)
        stored_head = get_meta(conn, "chain_head")
        stored_count = get_meta(conn, "chain_count")
        # No events: anchor may be absent (nothing ever recorded) or equal genesis.
        if stored_head is not None and stored_head != expected_head:
            raise ValueError("chain_head mismatch on empty table")
        if stored_count is not None and stored_count != "0":
            raise ValueError("chain_count mismatch on empty table")
        return {"ok": True, "count": 0}

    prev_hash = _genesis_mac(hmac_key)
    running_head = _genesis_mac(hmac_key)
    count = 0

    for ev in events:
        count += 1
        # 1. id monotonic, no gaps
        if ev.id != count:
            raise ValueError(f"id gap or non-monotonic at row {ev.id}, expected {count}")
        # 2. prev_hash links to previous mac
        if ev.prev_hash != prev_hash:
            raise ValueError(f"prev_hash mismatch at row {ev.id}")
        # 3. row-level mac recomputed matches stored mac
        mac_fields = (ev.ts, ev.employee, ev.file_hash, ev.action, ev.key_version, ev.machine, ev.ok)
        expected_mac = _mac_for_event(hmac_key, ev.prev_hash, mac_fields)
        if ev.mac != expected_mac:
            raise ValueError(f"mac mismatch at row {ev.id}")
        # 4. running chain head
        running_head = _chain_mac(hmac_key, (running_head + ev.mac).encode("utf-8"))
        prev_hash = ev.mac

    # 5. running chain-head anchor must match meta
    stored_head = get_meta(conn, "chain_head")
    stored_count = get_meta(conn, "chain_count")
    if stored_head != running_head:
        raise ValueError("chain_head anchor mismatch (whole-table rollback?)")
    if stored_count != str(count):
        raise ValueError(f"chain_count anchor mismatch: stored {stored_count}, actual {count}")

    return {"ok": True, "count": count}
