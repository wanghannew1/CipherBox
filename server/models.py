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


@dataclass(frozen=True)
class KeyVersion:
    """One master-key version row."""

    version: int
    key_hex: str
    created_at: str

    @staticmethod
    def from_row(row: sqlite3.Row) -> "KeyVersion":
        return KeyVersion(
            version=row["version"],
            key_hex=row["key_hex"],
            created_at=row["created_at"],
        )


@dataclass(frozen=True)
class AuditEvent:
    """Row shape of one audit event."""

    id: int
    ts: str
    employee: str
    file_hash: str
    action: str
    key_version: int | None
    machine: str | None
    ok: bool
    prev_hash: str
    mac: str

    @staticmethod
    def from_row(row: sqlite3.Row) -> "AuditEvent":
        return AuditEvent(
            id=row["id"],
            ts=row["ts"],
            employee=row["employee"],
            file_hash=row["file_hash"],
            action=row["action"],
            key_version=row["key_version"],
            machine=row["machine"],
            ok=bool(row["ok"]),
            prev_hash=row["prev_hash"],
            mac=row["mac"],
        )
