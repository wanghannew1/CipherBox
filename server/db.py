"""SQLite schema and connection helpers for the cipherbox server.

Single table per plan todo 5:

    employees(token_hash, employee, level, issued_at, expires_at, revoked)

Only a SHA-256 hex digest of the bearer token is stored, never the
plaintext token itself. `employee` is the employee identifier column;
`level` distinguishes 'admin' from 'employee'.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

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


@dataclass(frozen=True)
class EmployeeToken:
    """Row shape of one issued employee token."""

    token_hash: str
    employee: str
    level: str
    issued_at: str
    expires_at: str
    revoked: bool

    @staticmethod
    def from_row(row: sqlite3.Row) -> "EmployeeToken":
        return EmployeeToken(
            token_hash=row["token_hash"],
            employee=row["employee"],
            level=row["level"],
            issued_at=row["issued_at"],
            expires_at=row["expires_at"],
            revoked=bool(row["revoked"]),
        )


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Open a connection with row access by column name.

    A fresh connection per request keeps usage thread-safe without
    check_same_thread hacks (FastAPI runs sync endpoints in a threadpool).
    """
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def init_schema(db_path: str | Path) -> None:
    """Create the employees table if it does not exist yet."""
    path = Path(db_path)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def get_by_hash(conn: sqlite3.Connection, token_hash: str) -> EmployeeToken | None:
    row = conn.execute(
        "SELECT token_hash, employee, level, issued_at, expires_at, revoked"
        " FROM employees WHERE token_hash = ?",
        (token_hash,),
    ).fetchone()
    return EmployeeToken.from_row(row) if row is not None else None
