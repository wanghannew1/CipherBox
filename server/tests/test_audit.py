"""Tests for plan todo 7: audit event recording with HMAC chain + chain-head anchor."""

from __future__ import annotations

import re
import sqlite3
from datetime import timedelta, timezone
from pathlib import Path
from typing import Iterator

import pytest
from fastapi.testclient import TestClient

from server import auth, database
from server.app import _UNAUTHORIZED_DETAIL, create_app
from server.audit import verify_audit_chain
from server.config import TOKEN_TTL_DAYS
from server.models import EmployeeToken

NOW = __import__("datetime").datetime.now(timezone.utc)


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "test.db"


@pytest.fixture()
def hmac_key_file(tmp_path: Path) -> Path:
    p = tmp_path / "hmac.key"
    p.write_bytes(b"\x01" * 32)
    return p


@pytest.fixture()
def client(db_path: Path, hmac_key_file: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("CIPHERBOX_HMAC_KEY_FILE", str(hmac_key_file))
    return TestClient(create_app(db_path=db_path))


@pytest.fixture()
def conn(db_path: Path) -> Iterator[sqlite3.Connection]:
    database.init_schema(db_path)
    c = database.connect(db_path)
    yield c
    c.close()


def _issue(conn: sqlite3.Connection, employee: str = "emp-1",
           level: auth.Level = "employee",
           *, age: timedelta = timedelta(0)) -> str:
    return auth.issue_token(conn, employee, level, now=NOW - age)


HMAC_KEY = b"\x01" * 32


# --- /events record ----------------------------------------------------------

def test_events_200_persists_with_hmac_chain(client: TestClient, conn: sqlite3.Connection) -> None:
    token = _issue(conn, employee="alice")
    resp = client.post(
        "/events",
        headers={"Authorization": f"Bearer {token}"},
        json={"action": "encrypt", "file_hash": "0" * 64, "key_version": 1, "machine": "PC-01", "ok": True},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["recorded"] is True
    assert body["employee"] == "alice"
    assert "mac" in body and len(body["mac"]) == 64
    assert "prev_hash" in body

    # DB row should be there
    rows = database.query_events(conn)
    assert len(rows) == 1
    assert rows[0].employee == "alice"
    assert rows[0].prev_hash != ""  # genesis-derived


def test_events_422_employee_in_body(client: TestClient, conn: sqlite3.Connection) -> None:
    """request body must not contain 'employee' (impersonation)."""
    token = _issue(conn, employee="alice")
    resp = client.post(
        "/events",
        headers={"Authorization": f"Bearer {token}"},
        json={"employee": "bob", "action": "encrypt", "file_hash": "0" * 64},
    )
    assert resp.status_code == 422


def test_events_422_bad_file_hash(client: TestClient, conn: sqlite3.Connection) -> None:
    token = _issue(conn, employee="alice")
    for bad in ["", "0" * 63, "0" * 65, "zz" * 32, None]:
        resp = client.post(
            "/events",
            headers={"Authorization": f"Bearer {token}"},
            json={"action": "encrypt", "file_hash": bad},
        )
        assert resp.status_code == 422, f"hash={bad!r}"


def test_events_chain_links_across_rows(client: TestClient, conn: sqlite3.Connection) -> None:
    token = _issue(conn, employee="alice")
    prev = ""
    for i in range(5):
        resp = client.post(
            "/events",
            headers={"Authorization": f"Bearer {token}"},
            json={"action": "encrypt", "file_hash": ("%064d" % i), "key_version": i + 1},
        )
        assert resp.status_code == 200
        body = resp.json()
        if i == 0:
            assert body["prev_hash"] != ""
        else:
            assert body["prev_hash"] == prev
        prev = body["mac"]

    rows = database.query_events(conn)
    assert len(rows) == 5
    assert rows[0].id == 1
    assert rows[-1].id == 5


# --- query_events ------------------------------------------------------------

def test_query_events_filters_and_pagination(client: TestClient, conn: sqlite3.Connection) -> None:
    tok_a = _issue(conn, employee="alice")
    tok_b = _issue(conn, employee="bob")
    client.post("/events", headers={"Authorization": f"Bearer {tok_a}"},
                json={"action": "encrypt", "file_hash": "a" * 64, "key_version": 1})
    client.post("/events", headers={"Authorization": f"Bearer {tok_b}"},
                json={"action": "export", "file_hash": "b" * 64, "key_version": 1})
    client.post("/events", headers={"Authorization": f"Bearer {tok_a}"},
                json={"action": "encrypt", "file_hash": "c" * 64, "key_version": 2})

    admin = _issue(conn, employee="boss", level="admin")

    # filter by employee
    rows = database.query_events(conn, employee="alice")
    assert len(rows) == 2
    assert all(r.employee == "alice" for r in rows)

    # filter by action
    rows = database.query_events(conn, action="export")
    assert len(rows) == 1
    assert rows[0].employee == "bob"

    # filter by key_version
    rows = database.query_events(conn, key_version=2)
    assert len(rows) == 1
    assert rows[0].file_hash == "c" * 64

    # pagination
    rows = database.query_events(conn, limit=2, offset=0)
    assert len(rows) == 2
    rows = database.query_events(conn, limit=2, offset=2)
    assert len(rows) == 1


# --- verify_audit_chain ------------------------------------------------------

def test_verify_chain_ok(conn: sqlite3.Connection) -> None:
    from server.audit import record_event
    rec = EmployeeToken(token_hash="x", employee="alice", level="employee",
                        issued_at="2024-01-01T00:00:00+00:00",
                        expires_at="2025-01-01T00:00:00+00:00", revoked=False)
    for i in range(3):
        record_event(conn, rec, {"action": "encrypt", "file_hash": ("%064d" % i)},
                     hmac_key=HMAC_KEY)
    result = verify_audit_chain(conn, HMAC_KEY)
    assert result == {"ok": True, "count": 3}


def test_verify_chain_empty_ok(conn: sqlite3.Connection) -> None:
    result = verify_audit_chain(conn, HMAC_KEY)
    assert result == {"ok": True, "count": 0}


def test_verify_chain_detects_row_tamper(conn: sqlite3.Connection) -> None:
    from server.audit import record_event
    rec = EmployeeToken(token_hash="x", employee="alice", level="employee",
                        issued_at="2024-01-01T00:00:00+00:00",
                        expires_at="2025-01-01T00:00:00+00:00", revoked=False)
    record_event(conn, rec, {"action": "encrypt", "file_hash": "0" * 64}, hmac_key=HMAC_KEY)
    record_event(conn, rec, {"action": "encrypt", "file_hash": "1" * 64}, hmac_key=HMAC_KEY)

    # tamper: flip one mac byte
    conn.execute("UPDATE events SET mac = substr(mac, 1, 62) || 'zz' WHERE id = 2")
    conn.commit()

    with pytest.raises(Exception) as excinfo:
        verify_audit_chain(conn, HMAC_KEY)
    assert "mac mismatch" in str(excinfo.value).lower() or "prev_hash" in str(excinfo.value).lower()


def test_verify_chain_detects_deleted_tail(conn: sqlite3.Connection) -> None:
    from server.audit import record_event
    rec = EmployeeToken(token_hash="x", employee="alice", level="employee",
                        issued_at="2024-01-01T00:00:00+00:00",
                        expires_at="2025-01-01T00:00:00+00:00", revoked=False)
    record_event(conn, rec, {"action": "encrypt", "file_hash": "0" * 64}, hmac_key=HMAC_KEY)
    record_event(conn, rec, {"action": "encrypt", "file_hash": "1" * 64}, hmac_key=HMAC_KEY)

    conn.execute("DELETE FROM events WHERE id = 2")
    conn.commit()

    with pytest.raises(Exception) as excinfo:
        verify_audit_chain(conn, HMAC_KEY)
    assert "gap" in str(excinfo.value).lower() or "mismatch" in str(excinfo.value).lower()


def test_verify_chain_detects_whole_table_rollback(conn: sqlite3.Connection) -> None:
    """Stored chain_head/chain_count cannot be recomputed from table data alone."""
    from server.audit import record_event
    rec = EmployeeToken(token_hash="x", employee="alice", level="employee",
                        issued_at="2024-01-01T00:00:00+00:00",
                        expires_at="2025-01-01T00:00:00+00:00", revoked=False)
    record_event(conn, rec, {"action": "encrypt", "file_hash": "0" * 64}, hmac_key=HMAC_KEY)
    record_event(conn, rec, {"action": "encrypt", "file_hash": "1" * 64}, hmac_key=HMAC_KEY)

    # Simulate attacker replacing events+meta with an older snapshot:
    # delete row 2, then set chain_head/chain_count to match the (now shorter) table
    # as if it were recomputed from the remaining rows.
    conn.execute("DELETE FROM events WHERE id = 2")
    conn.execute("UPDATE meta SET value = '1' WHERE key = 'chain_count'")
    conn.commit()

    with pytest.raises(Exception) as excinfo:
        verify_audit_chain(conn, HMAC_KEY)
    assert "anchor" in str(excinfo.value).lower() or "mismatch" in str(excinfo.value).lower()


# --- DB-layer: audit CRUD ----------------------------------------------------

def test_db_insert_event(conn: sqlite3.Connection) -> None:
    from server.audit import record_event
    rec = EmployeeToken(token_hash="x", employee="alice", level="employee",
                        issued_at="2024-01-01T00:00:00+00:00",
                        expires_at="2025-01-01T00:00:00+00:00", revoked=False)
    body = record_event(conn, rec, {"action": "encrypt", "file_hash": "a" * 64},
                        hmac_key=HMAC_KEY)
    assert body["recorded"] is True
    assert body["id"] == 1

    ev = database.get_last_event(conn)
    assert ev is not None
    assert ev.employee == "alice"
    assert ev.action == "encrypt"
    assert ev.file_hash == "a" * 64
    assert ev.ok is True
    assert ev.prev_hash != ""

    count = database.count_events(conn)
    assert count == 1
