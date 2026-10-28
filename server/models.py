"""Data models for the cipherbox server (plan todo 5).

The plan allows `sqlite3` or SQLAlchemy; we deliberately use the stdlib
`sqlite3` module (no extra install, consistent with the "FastAPI + SQLite
(sqlite3 内置)" requirement), so models are frozen dataclasses mirroring the
DB row shapes instead of ORM classes.

    employees(token_hash, employee, level, issued_at, expires_at, revoked)

Only a SHA-256 hex digest of the bearer token is ever stored, never the
plaintext token itself. `employee` is the employee identifier column (audit
events resolve their `employee` field from it, todo 7); `level` distinguishes
'admin' from 'employee'.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Literal

Level = Literal["admin", "employee"]


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
