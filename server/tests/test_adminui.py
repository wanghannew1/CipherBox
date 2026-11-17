"""Tests for the admin console endpoints (todo 17-adjacent feature):

- GET  /admin/ui            static page, no auth (page itself carries no data)
- GET  /admin/summary       admin-only dashboard payload (NO key material)
- POST /admin/verify_chain  admin-only full HMAC chain + anchor check

Auth matrix follows the same contract as every other /admin endpoint:
missing/malformed -> 401 uniform detail, employee-level -> 403.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from server import auth, database
from server.app import _UNAUTHORIZED_DETAIL, create_app


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "adminui.db"


@pytest.fixture()
def hmac_key_file(tmp_path: Path) -> Path:
    p = tmp_path / "hmac.key"
    p.write_bytes(b"\x02" * 32)
    return p


@pytest.fixture()
def client(db_path: Path, hmac_key_file: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("CIPHERBOX_HMAC_KEY_FILE", str(hmac_key_file))
    return TestClient(create_app(db_path=db_path))


@pytest.fixture()
def conn(db_path: Path) -> sqlite3.Connection:
    database.init_schema(db_path)
    c = database.connect(db_path)
    yield c
    c.close()


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# GET /admin/ui — static page
# ---------------------------------------------------------------------------

def test_admin_ui_served_without_auth(client: TestClient) -> None:
    r = client.get("/admin/ui")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert "CipherBox" in r.text
    # page must not embed any secret material
    assert "key_hex" not in r.text


def test_admin_ui_no_store(client: TestClient) -> None:
    r = client.get("/admin/ui")
    assert r.headers.get("cache-control") == "no-store"


# ---------------------------------------------------------------------------
# GET /admin/summary — auth matrix + payload shape
# ---------------------------------------------------------------------------

def test_summary_auth_matrix(client: TestClient, conn: sqlite3.Connection) -> None:
    emp = auth.issue_token(conn, "emp-1", "employee")
    adm = auth.issue_token(conn, "boss-1", "admin")

    # no token -> uniform 401
    r = client.get("/admin/summary")
    assert r.status_code == 401
    assert r.json()["detail"] == _UNAUTHORIZED_DETAIL

    # employee-level -> 403
    r = client.get("/admin/summary", headers=_auth(emp))
    assert r.status_code == 403

    # admin -> 200
    r = client.get("/admin/summary", headers=_auth(adm))
    assert r.status_code == 200


def test_summary_payload_shape_and_content(
    client: TestClient, conn: sqlite3.Connection
) -> None:
    adm = auth.issue_token(conn, "boss-1", "admin")
    emp = auth.issue_token(conn, "emp-1", "employee")

    r = client.post("/admin/rotate", headers=_auth(adm))
    assert r.status_code == 200
    r = client.post("/admin/rotate", headers=_auth(adm))
    assert r.status_code == 200

    # one audit event from the employee
    r = client.post("/events", headers=_auth(emp),
                    json={"action": "encrypt", "file_hash": "a" * 64,
                          "key_version": 2, "machine": "PC-UI"})
    assert r.status_code == 200

    r = client.get("/admin/summary", headers=_auth(adm))
    body = r.json()
    assert [k["version"] for k in body["keys"]] == [2, 1]  # newest first
    assert body["current"] == 2
    assert body["event_count"] == 1
    assert body["chain"]["count"] == "1"
    assert body["chain"]["head"] is not None

    # per-employee rollup: boss-1 (1 active admin token), emp-1 (1 active)
    by_name = {e["employee"]: e for e in body["employees"]}
    assert by_name["boss-1"]["level"] == "admin"
    assert by_name["boss-1"]["active_tokens"] == 1
    assert by_name["emp-1"]["active_tokens"] == 1


def test_summary_excludes_key_material(
    client: TestClient, conn: sqlite3.Connection
) -> None:
    adm = auth.issue_token(conn, "boss-1", "admin")
    client.post("/admin/rotate", headers=_auth(adm))
    body = client.get("/admin/summary", headers=_auth(adm)).json()
    # key versions carry version + created_at only, never the 64-hex material
    assert set(body["keys"][0].keys()) == {"version", "created_at"}


def test_summary_marks_revoked_and_expired(
    client: TestClient, conn: sqlite3.Connection
) -> None:
    from datetime import datetime, timedelta, timezone

    adm = auth.issue_token(conn, "boss-1", "admin")
    gone = auth.issue_token(conn, "leaver", "employee")
    auth.revoke_employee(conn, "leaver")
    stale = auth.issue_token(conn, "stale", "employee",
                             now=datetime.now(timezone.utc) - timedelta(days=91))

    body = client.get("/admin/summary", headers=_auth(adm)).json()
    by_name = {e["employee"]: e for e in body["employees"]}
    assert by_name["leaver"]["active_tokens"] == 0
    assert by_name["leaver"]["revoked_tokens"] == 1
    assert by_name["stale"]["active_tokens"] == 0  # expired, not revoked
    assert by_name["boss-1"]["active_tokens"] == 1
    # keep flake8 quiet about the unused-looking token handle
    assert auth.hash_token(gone) or True


# ---------------------------------------------------------------------------
# POST /admin/verify_chain
# ---------------------------------------------------------------------------

def test_verify_chain_auth(client: TestClient, conn: sqlite3.Connection) -> None:
    emp = auth.issue_token(conn, "emp-1", "employee")
    assert client.post("/admin/verify_chain").status_code == 401
    assert client.post("/admin/verify_chain", headers=_auth(emp)).status_code == 403


def test_verify_chain_ok_empty(client: TestClient, conn: sqlite3.Connection) -> None:
    adm = auth.issue_token(conn, "boss-1", "admin")
    r = client.post("/admin/verify_chain", headers=_auth(adm))
    assert r.status_code == 200
    assert r.json() == {"ok": True, "count": 0}


def test_verify_chain_ok_after_events(
    client: TestClient, conn: sqlite3.Connection
) -> None:
    adm = auth.issue_token(conn, "boss-1", "admin")
    emp = auth.issue_token(conn, "emp-1", "employee")
    for h in ("a" * 64, "b" * 64):
        r = client.post("/events", headers=_auth(emp),
                        json={"action": "encrypt", "file_hash": h})
        assert r.status_code == 200
    r = client.post("/admin/verify_chain", headers=_auth(adm))
    assert r.json() == {"ok": True, "count": 2}


def test_verify_chain_detects_tamper(
    client: TestClient, conn: sqlite3.Connection, db_path: Path
) -> None:
    adm = auth.issue_token(conn, "boss-1", "admin")
    emp = auth.issue_token(conn, "emp-1", "employee")
    r = client.post("/events", headers=_auth(emp),
                    json={"action": "encrypt", "file_hash": "c" * 64})
    assert r.status_code == 200

    # tamper directly in SQLite: flip one stored field
    raw = sqlite3.connect(str(db_path))
    try:
        raw.execute("UPDATE events SET action = 'forged' WHERE id = 1")
        raw.commit()
    finally:
        raw.close()

    r = client.post("/admin/verify_chain", headers=_auth(adm))
    body = r.json()
    assert body["ok"] is False
    assert "row 1" in body["error"]
