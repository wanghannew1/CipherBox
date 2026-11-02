"""Tests for plan todo 6: master-key issuance/rotation (/key, /admin/rotate)."""

from __future__ import annotations

import re
import secrets
import sqlite3
from datetime import timedelta, timezone
from pathlib import Path
from typing import Iterator

import pytest
from fastapi.testclient import TestClient

from server import auth, database
from server.app import _UNAUTHORIZED_DETAIL, create_app
from server.config import TOKEN_TTL_DAYS
from server.models import EmployeeToken

SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
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


# --- /key happy path ----------------------------------------------------------

def test_key_200_empty_initially(client: TestClient, conn: sqlite3.Connection) -> None:
    """No keys yet -> empty version set, current None."""
    token = _issue(conn)
    resp = client.get("/key", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"versions": [], "current": None}


def test_key_401_without_token(client: TestClient) -> None:
    resp = client.get("/key")
    assert resp.status_code == 401
    assert resp.json() == {"detail": _UNAUTHORIZED_DETAIL}


# --- /admin/rotate ------------------------------------------------------------

def test_rotate_200_admin_returns_new_version(client: TestClient, conn: sqlite3.Connection) -> None:
    admin = _issue(conn, employee="boss", level="admin")
    resp = client.post("/admin/rotate",
                       headers={"Authorization": f"Bearer {admin}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["version"] == 1
    assert SHA256_HEX.match(body["key"]), "key must be 64-hex (256-bit)"
    assert body["current"] == 1


def test_rotate_returns_full_version_set(client: TestClient, conn: sqlite3.Connection) -> None:
    admin = _issue(conn, employee="boss", level="admin")
    client.post("/admin/rotate", headers={"Authorization": f"Bearer {admin}"})
    client.post("/admin/rotate", headers={"Authorization": f"Bearer {admin}"})

    resp = client.get("/key", headers={"Authorization": f"Bearer {_issue(conn)}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["current"] == 2
    assert len(body["versions"]) == 2
    assert [v["version"] for v in body["versions"]] == [1, 2]
    assert all(SHA256_HEX.match(v["key"]) for v in body["versions"])
    assert body["versions"][0]["key"] != body["versions"][1]["key"]


def test_rotate_401_without_auth(client: TestClient) -> None:
    resp = client.post("/admin/rotate")
    assert resp.status_code == 401


def test_rotate_403_non_admin(client: TestClient, conn: sqlite3.Connection) -> None:
    token = _issue(conn, level="employee")
    resp = client.post("/admin/rotate",
                       headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


# --- DB-layer: key persistence ----------------------------------------------

def test_db_insert_and_get_version_set(conn: sqlite3.Connection) -> None:
    from server import key_manager
    # empty
    assert key_manager.get_version_set(conn) == {"versions": [], "current": None}

    r1 = key_manager.rotate(conn)
    assert r1["version"] == 1
    r2 = key_manager.rotate(conn)
    assert r2["version"] == 2

    vs = key_manager.get_version_set(conn)
    assert vs["current"] == 2
    assert len(vs["versions"]) == 2
    assert vs["versions"][0]["version"] == 1
    assert vs["versions"][1]["version"] == 2

    cur = database.get_current_key(conn)
    assert cur is not None
    assert cur.version == 2
    assert SHA256_HEX.match(cur.key_hex)
