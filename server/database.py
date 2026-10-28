"""SQLite connection and session management for the cipherbox server.

Schema (plan todo 5):

    employees(token_hash, employee, level, issued_at, expires_at, revoked)

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

from .models import EmployeeToken

SCHEMA = """
CREATE TABLE IF NOT EXISTS employees (
    token_hash TEXT PRIMARY KEY,
    employee   TEXT NOT NULL,
    level      TEXT NOT NULL CHECK (level IN ('admin', 'employee')),
    issued_at  TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1))
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
