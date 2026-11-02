"""Tests for plan todo 5: health, bearer auth, TTL/renew/revoke.

Determinism notes (adversarial: flaky_tests / stale_state):
- Every test gets a fresh SQLite file via tmp_path (no cross-test leakage).
- No sleeps and no clock freezing: expiry is derived explicitly by issuing
  tokens with a backdated `issued_at`, so ordering margins are days wide.
- Assertions check exact status codes, response bodies, and the stored DB
  values (a stored token must be a 64-char sha256 hex, never plaintext).
"""

from __future__ import annotations

import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

import pytest
from fastapi.testclient import TestClient

from server import auth, database
from server.app import _UNAUTHORIZED_DETAIL, create_app
from server.config import DEFAULT_PORT, TOKEN_TTL_DAYS, load_config
from server.models import EmployeeToken

SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
NOW = datetime.now(timezone.utc)


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "test.db"


@pytest.fixture()
def hmac_key_file(tmp_path: Path) -> Path:
    p = tmp_path / "hmac.key"
    p.write_bytes(b"\x01" * 32)  # 256-bit dev HMAC key
    return p


@pytest.fixture()
def client(db_path: Path, hmac_key_file: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("CIPHERBOX_HMAC_KEY_FILE", str(hmac_key_file))
    return TestClient(create_app(db_path=db_path))


@pytest.fixture()
def conn(db_path: Path) -> Iterator[sqlite3.Connection]:
    database.init_schema(db_path)  # direct-DB tests must not depend on the client fixture
    c = database.connect(db_path)
    yield c
    c.close()


def _issue(conn: sqlite3.Connection, employee: str = "emp-1",
           level: auth.Level = "employee",
           *, age: timedelta = timedelta(0)) -> str:
    return auth.issue_token(conn, employee, level, now=NOW - age)


def _stored(conn: sqlite3.Connection, token: str) -> EmployeeToken:
    rec = database.get_by_hash(conn, auth.hash_token(token))
    assert rec is not None
    return rec


# --- config -------------------------------------------------------------------

def test_config_defaults() -> None:
    cfg = load_config()
    assert cfg.port == 8443  # HTTPS-only port per plan todo 5
    assert DEFAULT_PORT == 8443
    assert cfg.token_ttl_days == 90
    assert TOKEN_TTL_DAYS == 90
    assert cfg.ca_cert.name == "ca.crt"
    assert cfg.server_cert.name == "server.crt"
    assert cfg.server_key.name == "server.key"


# --- health -----------------------------------------------------------------

def test_health_200_without_auth(client: TestClient) -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


# --- /key happy path ----------------------------------------------------------

def test_key_200_with_valid_token(client: TestClient, conn: sqlite3.Connection) -> None:
    token = _issue(conn)
    resp = client.get("/key", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"versions": [], "current": None}  # todo-5 placeholder envelope


# --- 401 matrix: missing / malformed / unknown --------------------------------

def test_key_401_missing_header(client: TestClient) -> None:
    resp = client.get("/key")
    assert resp.status_code == 401
    assert resp.json() == {"detail": _UNAUTHORIZED_DETAIL}


@pytest.mark.parametrize(
    "header",
    [
        "Token abc123",            # wrong scheme
        "Bearer",                  # scheme without credential
        f"Bearer  ",               # collapsed to scheme only
        f"bearer",                 # bare word
        f"Basic {secrets.token_urlsafe(8)}",  # basic auth is not bearer
        f"Bearer tok1 tok2",       # extra segment
    ],
)
def test_key_401_malformed_header(client: TestClient, header: str) -> None:
    resp = client.get("/key", headers={"Authorization": header})
    assert resp.status_code == 401
    assert resp.json() == {"detail": _UNAUTHORIZED_DETAIL}


def test_key_401_unknown_token(client: TestClient) -> None:
    resp = client.get(
        "/key", headers={"Authorization": f"Bearer {secrets.token_urlsafe(32)}"}
    )
    assert resp.status_code == 401
    assert resp.json() == {"detail": _UNAUTHORIZED_DETAIL}


# --- /events auth gate (placeholder until todo 7) ------------------------------

def test_events_200_with_valid_token(client: TestClient, conn: sqlite3.Connection) -> None:
    token = _issue(conn, employee="emp-events")
    resp = client.post(
        "/events",
        headers={"Authorization": f"Bearer {token}"},
        json={"action": "encrypt", "file_hash": "0" * 64},
    )
    assert resp.status_code == 200
    # Placeholder ack; employee resolved server-side from the token.
    assert resp.json()["employee"] == "emp-events"


def test_events_401_missing_and_unknown_token(client: TestClient) -> None:
    resp = client.post("/events", json={})
    assert resp.status_code == 401
    assert resp.json() == {"detail": _UNAUTHORIZED_DETAIL}

    resp = client.post(
        "/events",
        headers={"Authorization": f"Bearer {secrets.token_urlsafe(32)}"},
        json={},
    )
    assert resp.status_code == 401
    assert resp.json() == {"detail": _UNAUTHORIZED_DETAIL}


def test_events_401_revoked_and_expired(client: TestClient, conn: sqlite3.Connection) -> None:
    revoked_tok = _issue(conn, employee="emp-revoked")
    assert auth.revoke_employee(conn, "emp-revoked") == 1
    resp = client.post(
        "/events", headers={"Authorization": f"Bearer {revoked_tok}"}, json={}
    )
    assert resp.status_code == 401
    assert resp.json() == {"detail": _UNAUTHORIZED_DETAIL}

    expired_tok = _issue(conn, age=timedelta(days=91))
    resp = client.post(
        "/events", headers={"Authorization": f"Bearer {expired_tok}"}, json={}
    )
    assert resp.status_code == 401
    assert resp.json() == {"detail": _UNAUTHORIZED_DETAIL}


# --- renew --------------------------------------------------------------------

def test_renew_extends_expires_at(client: TestClient, conn: sqlite3.Connection) -> None:
    # Issued 30 days ago -> still valid, expires at now+60d. Renewal must
    # slide it to ~now+90d; the 30-day margin makes this fully deterministic.
    token = _issue(conn, age=timedelta(days=30))
    before = _stored(conn, token).expires_at

    resp = client.post("/token/renew", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body_expiry = resp.json()["expires_at"]

    after = _stored(conn, token).expires_at
    assert body_expiry == after  # response reflects the stored value
    before_dt = datetime.fromisoformat(before)
    after_dt = datetime.fromisoformat(after)
    assert after_dt > before_dt
    assert after_dt - before_dt >= timedelta(days=29)  # extended, not rewritten


def test_renew_401_without_token(client: TestClient) -> None:
    resp = client.post("/token/renew")
    assert resp.status_code == 401
    assert resp.json() == {"detail": _UNAUTHORIZED_DETAIL}


# --- revoked ------------------------------------------------------------------

def test_revoked_token_401_on_key_and_renew(
    client: TestClient, conn: sqlite3.Connection
) -> None:
    token = _issue(conn)
    assert auth.revoke_employee(conn, "emp-1") == 1

    resp = client.get("/key", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401
    assert resp.json() == {"detail": _UNAUTHORIZED_DETAIL}

    resp = client.post("/token/renew", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401
    assert resp.json() == {"detail": _UNAUTHORIZED_DETAIL}


# --- expired ------------------------------------------------------------------

def test_expired_token_401_on_key_and_renew(
    client: TestClient, conn: sqlite3.Connection
) -> None:
    # Issued 91 days ago with a 90-day TTL -> expired yesterday.
    token = _issue(conn, age=timedelta(days=91))
    assert datetime.fromisoformat(_stored(conn, token).expires_at) < NOW

    resp = client.get("/key", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401
    assert resp.json() == {"detail": _UNAUTHORIZED_DETAIL}

    resp = client.post("/token/renew", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401
    assert resp.json() == {"detail": _UNAUTHORIZED_DETAIL}


# --- admin revoke endpoint ------------------------------------------------------

def test_non_admin_revoke_403(client: TestClient, conn: sqlite3.Connection) -> None:
    token = _issue(conn, level="employee")
    resp = client.post(
        "/admin/revoke",
        headers={"Authorization": f"Bearer {token}"},
        json={"employee": "someone"},
    )
    assert resp.status_code == 403


def test_admin_revoke_200_and_token_dies(
    client: TestClient, conn: sqlite3.Connection
) -> None:
    admin = _issue(conn, employee="boss", level="admin")
    victim = _issue(conn, employee="victim-1")

    resp = client.post(
        "/admin/revoke",
        headers={"Authorization": f"Bearer {admin}"},
        json={"employee": "victim-1"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"revoked": 1}

    assert _stored(conn, victim).revoked is True
    resp = client.get("/key", headers={"Authorization": f"Bearer {victim}"})
    assert resp.status_code == 401
    assert resp.json() == {"detail": _UNAUTHORIZED_DETAIL}


def test_admin_revoke_401_without_auth(client: TestClient) -> None:
    resp = client.post("/admin/revoke", json={"employee": "x"})
    assert resp.status_code == 401
    assert resp.json() == {"detail": _UNAUTHORIZED_DETAIL}


# --- storage hygiene ------------------------------------------------------------

def test_token_plaintext_never_stored(conn: sqlite3.Connection) -> None:
    token = _issue(conn, employee="hash-check")
    row = conn.execute(
        "SELECT token_hash, employee, level, issued_at, expires_at, revoked"
        " FROM employees WHERE employee = ?",
        ("hash-check",),
    ).fetchone()
    assert row is not None

    stored = row["token_hash"]
    assert SHA256_HEX.match(stored), "stored value must be a sha256 hex digest"
    assert stored == auth.hash_token(token)
    assert stored != token
    # Plaintext appears in no column of the row.
    assert all(token not in str(v) for v in tuple(row))
