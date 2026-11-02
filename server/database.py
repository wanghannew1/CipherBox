"""SQLite connection and session management for the cipherbox server.

Schema (plan todo 5 / 6 / 7):

    employees(token_hash, employee, level, issued_at, expires_at, revoked)
    keys(version, key_hex, created_at)                      -- todo 6: master-key version set
    events(id, ts, employee, file_hash, action, key_version, machine, ok, prev_hash, mac)  -- todo 7

A fresh connection per request keeps usage thread-safe without
check_same_thread hacks (FastAPI runs sync endpoints in a threadpool).
`session()` is the unit-of-work context manager: commit on clean exit,
rollback on exception, always close.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .models import AuditEvent, EmployeeToken, KeyVersion

SCHEMA = """
CREATE TABLE IF NOT EXISTS employees (
    token_hash TEXT PRIMARY KEY,
    employee   TEXT NOT NULL,
    level      TEXT NOT NULL CHECK (level IN ('admin', 'employee')),
    issued_at  TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1))
);

CREATE TABLE IF NOT EXISTS keys (
    version    INTEGER PRIMARY KEY,
    key_hex    TEXT NOT NULL CHECK (length(key_hex) = 64),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    employee    TEXT NOT NULL,
    file_hash   TEXT NOT NULL CHECK (length(file_hash) = 64),
    action      TEXT NOT NULL,
    key_version INTEGER,
    machine     TEXT,
    ok          INTEGER NOT NULL DEFAULT 1 CHECK (ok IN (0, 1)),
    prev_hash   TEXT NOT NULL DEFAULT '',
    mac         TEXT NOT NULL DEFAULT ''
);
"""


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Open a connection with row access by column name."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def session(db_path: str | Path) -> Iterator[sqlite3.Connection]:
    """Transactional session: commit on success, rollback on error, close always."""
    conn = connect(db_path)
    try:
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_schema(db_path: str | Path) -> None:
    """Create the employees table if it does not exist yet."""
    path = Path(db_path)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    with session(path) as conn:
        conn.executescript(SCHEMA)


def get_by_hash(conn: sqlite3.Connection, token_hash: str) -> EmployeeToken | None:
    """Look up one employee token row by its SHA-256 hex digest."""
    row = conn.execute(
        "SELECT token_hash, employee, level, issued_at, expires_at, revoked"
        " FROM employees WHERE token_hash = ?",
        (token_hash,),
    ).fetchone()
    return EmployeeToken.from_row(row) if row is not None else None


# ---------------------------------------------------------------------------
# keys (todo 6)
# ---------------------------------------------------------------------------

def insert_key(conn: sqlite3.Connection, version: int, key_hex: str, created_at: str) -> None:
    """Append one master-key version. Fails if version already exists."""
    conn.execute(
        "INSERT INTO keys (version, key_hex, created_at) VALUES (?, ?, ?)",
        (version, key_hex, created_at),
    )


def get_version_set(conn: sqlite3.Connection) -> list[KeyVersion]:
    """Return all master-key versions ordered ascending."""
    rows = conn.execute(
        "SELECT version, key_hex, created_at FROM keys ORDER BY version ASC"
    ).fetchall()
    return [KeyVersion.from_row(r) for r in rows]


def get_current_key(conn: sqlite3.Connection) -> KeyVersion | None:
    """Return the highest-version key (current), or None when empty."""
    rows = conn.execute(
        "SELECT version, key_hex, created_at FROM keys ORDER BY version DESC LIMIT 1"
    ).fetchall()
    return KeyVersion.from_row(rows[0]) if rows else None


# ---------------------------------------------------------------------------
# events (todo 7)
# ---------------------------------------------------------------------------

def insert_event(
    conn: sqlite3.Connection,
    ts: str,
    employee: str,
    file_hash: str,
    action: str,
    key_version: int | None,
    machine: str | None,
    ok: bool,
    prev_hash: str,
    mac: str,
) -> int:
    """Insert one audit event row, return its new id."""
    cur = conn.execute(
        "INSERT INTO events (ts, employee, file_hash, action, key_version, machine, ok, prev_hash, mac)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (ts, employee, file_hash, action, key_version, machine, 1 if ok else 0, prev_hash, mac),
    )
    return int(cur.lastrowid)


def get_last_event(conn: sqlite3.Connection) -> AuditEvent | None:
    """Return the most recent event by id (used to build the hash chain)."""
    rows = conn.execute(
        "SELECT id, ts, employee, file_hash, action, key_version, machine, ok, prev_hash, mac"
        " FROM events ORDER BY id DESC LIMIT 1"
    ).fetchall()
    return AuditEvent.from_row(rows[0]) if rows else None


def query_events(
    conn: sqlite3.Connection,
    *,
    key_version: int | None = None,
    action: str | None = None,
    employee: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[AuditEvent]:
    """Paginated admin query with optional filters."""
    clauses: list[str] = []
    params: list[object] = []
    if key_version is not None:
        clauses.append("key_version = ?")
        params.append(key_version)
    if action is not None:
        clauses.append("action = ?")
        params.append(action)
    if employee is not None:
        clauses.append("employee = ?")
        params.append(employee)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    rows = conn.execute(
        f"SELECT id, ts, employee, file_hash, action, key_version, machine, ok, prev_hash, mac"
        f" FROM events{where} ORDER BY id ASC LIMIT ? OFFSET ?",
        (*params, limit, offset),
    ).fetchall()
    return [AuditEvent.from_row(r) for r in rows]


def count_events(conn: sqlite3.Connection) -> int:
    """Total event count (for chain verification)."""
    row = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()
    return int(row["c"])
