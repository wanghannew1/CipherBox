"""Audit event recording — RESERVED INTERFACE (todo 7 implements).

Contract for todo 7 (plan lines 122-127):
- `POST /events` (authenticated) persists
  `events(id, ts, employee, file_hash, action, key_version, machine, ok, prev_hash, mac)`.
- `employee` is ALWAYS resolved server-side from the Bearer token (the
  `employees.employee` column); a same-named request-body field is rejected
  with 422 so nobody can impersonate another employee.
- `file_hash` = sha256 of the PLAINTEXT content; the server never receives
  or stores file content — metadata JSON only.
- `GET /events` (admin) supports pagination and filtering by
  `key_version` / `action` / `employee`.

Until todo 7 lands, `record_event` only acknowledges receipt so the todo-5
skeleton can verify the auth/revocation gate on `/events`.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from .models import EmployeeToken


def record_event(
    conn: sqlite3.Connection,
    rec: EmployeeToken,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Record one audit event. Placeholder until todo 7 (no persistence yet).

    `rec` is the authenticated token record — todo 7 derives `employee` from
    `rec.employee`, never from the request body.
    """
    return {"recorded": False, "detail": "audit pipeline lands in todo 7", "employee": rec.employee}


def query_events(conn: sqlite3.Connection, **filters: Any) -> list[dict[str, Any]]:
    """Paginated admin query with key_version/action/employee filters. Reserved for todo 7."""
    raise NotImplementedError("audit query is implemented in todo 7")
