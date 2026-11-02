"""Tests for plan todo 9: server integration test (real uvicorn HTTPS process).

Starts a real uvicorn server on 127.0.0.1:8443 with TLS, then uses `requests`
(verify=self-signed CA) to walk the full link:

    health -> /key (empty) -> /admin/rotate -> /key (v1) -> /admin/rotate
    -> /key (v1+v2) -> /events (encrypt) -> GET /events (admin query)

Asserts HTTP status codes, response bodies, and that audit rows land in SQLite.
"""

from __future__ import annotations

import os
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SERVER_ROOT = REPO_ROOT / "server"
CERTS_DIR = SERVER_ROOT / "certs"
CA_CRT = CERTS_DIR / "ca.crt"

UVICORN_CMD = [
    sys.executable, "-m", "uvicorn", "server.app:create_app", "--factory",
    "--host", "127.0.0.1", "--port", "8443",
    "--ssl-certfile", str(CERTS_DIR / "server.crt"),
    "--ssl-keyfile", str(CERTS_DIR / "server.key"),
]


def _wait_for_health(base: str, timeout: float = 20.0) -> None:
    import requests  # import here so module import doesn't fail without requests
    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        try:
            r = requests.get(f"{base}/health", verify=str(CA_CRT), timeout=2)
            if r.status_code == 200:
                return
        except Exception as exc:  # connection refused while starting
            last_err = exc
        time.sleep(0.3)
    raise RuntimeError(f"server did not become healthy: {last_err}")


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "integration.db"


@pytest.fixture()
def hmac_key_file(tmp_path: Path) -> Path:
    p = tmp_path / "hmac.key"
    p.write_bytes(b"\x01" * 32)
    return p


@pytest.fixture()
def base_url(db_path: Path, hmac_key_file: Path):
    """Start real uvicorn HTTPS server, yield base URL, teardown on exit."""
    env = dict(os.environ)
    env["CIPHERBOX_DB"] = str(db_path)
    env["CIPHERBOX_HOST"] = "127.0.0.1"
    env["CIPHERBOX_PORT"] = "8443"
    env["CIPHERBOX_CERT_DIR"] = str(CERTS_DIR)
    env["CIPHERBOX_HMAC_KEY_FILE"] = str(hmac_key_file)

    proc = subprocess.Popen(UVICORN_CMD, env=env, cwd=REPO_ROOT,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    try:
        _wait_for_health("https://127.0.0.1:8443")
        yield "https://127.0.0.1:8443"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _issue_token(db_path: Path, employee: str = "emp-int",
                 level: str = "employee") -> str:
    """Issue a token directly against the temp SQLite (bypasses HTTP)."""
    sys.path.insert(0, str(SERVER_ROOT))
    from server import auth, database
    database.init_schema(db_path)
    conn = database.connect(db_path)
    try:
        return auth.issue_token(conn, employee, level)
    finally:
        conn.close()


def _admin_token(db_path: Path) -> str:
    return _issue_token(db_path, employee="boss-int", level="admin")


# ---------------------------------------------------------------------------
# full HTTPS link
# ---------------------------------------------------------------------------

def test_https_full_link(base_url: str, db_path: Path) -> None:
    import requests

    emp = _issue_token(db_path)
    adm = _admin_token(db_path)

    # 1) health (no auth)
    r = requests.get(f"{base_url}/health", verify=str(CA_CRT))
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}

    # 2) /key empty initially
    r = requests.get(f"{base_url}/key", headers={"Authorization": f"Bearer {emp}"},
                     verify=str(CA_CRT))
    assert r.status_code == 200
    assert r.json() == {"versions": [], "current": None}

    # 3) rotate v1 (admin)
    r = requests.post(f"{base_url}/admin/rotate",
                      headers={"Authorization": f"Bearer {adm}"}, verify=str(CA_CRT))
    assert r.status_code == 200
    assert r.json()["version"] == 1
    assert len(r.json()["key"]) == 64

    # 4) /key returns v1
    r = requests.get(f"{base_url}/key", headers={"Authorization": f"Bearer {emp}"},
                     verify=str(CA_CRT))
    assert r.status_code == 200
    body = r.json()
    assert body["current"] == 1
    assert len(body["versions"]) == 1

    # 5) rotate v2 (admin)
    r = requests.post(f"{base_url}/admin/rotate",
                      headers={"Authorization": f"Bearer {adm}"}, verify=str(CA_CRT))
    assert r.status_code == 200
    assert r.json()["version"] == 2

    # 6) /key returns v1+v2
    r = requests.get(f"{base_url}/key", headers={"Authorization": f"Bearer {emp}"},
                     verify=str(CA_CRT))
    assert r.status_code == 200
    body = r.json()
    assert body["current"] == 2
    assert [v["version"] for v in body["versions"]] == [1, 2]

    # 7) POST /events (encrypt)
    r = requests.post(f"{base_url}/events",
                      headers={"Authorization": f"Bearer {emp}"},
                      json={"action": "encrypt", "file_hash": "a" * 64,
                            "key_version": 2, "machine": "PC-INTEG", "ok": True},
                      verify=str(CA_CRT))
    assert r.status_code == 200
    assert r.json()["recorded"] is True
    assert r.json()["employee"] == "emp-int"

    # 8) GET /events (admin query) -> row present with key_version=2
    r = requests.get(f"{base_url}/events",
                     headers={"Authorization": f"Bearer {adm}"},
                     params={"key_version": 2}, verify=str(CA_CRT))
    assert r.status_code == 200
    data = r.json()
    assert data["count"] == 1
    assert data["events"][0]["employee"] == "emp-int"
    assert data["events"][0]["action"] == "encrypt"
    assert data["events"][0]["key_version"] == 2
    assert len(data["events"][0]["mac"]) == 64
    assert len(data["events"][0]["prev_hash"]) == 64

    # 9) DB-level: sqlite can read the audit row directly
    import sqlite3 as _sqlite3
    conn = _sqlite3.connect(str(db_path))
    try:
        row = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()
        assert row[0] == 1
    finally:
        conn.close()


def test_https_revoked_token_401(base_url: str, db_path: Path) -> None:
    import requests

    emp = _issue_token(db_path, employee="revoked-int")
    adm = _admin_token(db_path)

    # revoke via admin endpoint
    r = requests.post(f"{base_url}/admin/revoke",
                      headers={"Authorization": f"Bearer {adm}"},
                      json={"employee": "revoked-int"}, verify=str(CA_CRT))
    assert r.status_code == 200

    # revoked token -> 401 on /key
    r = requests.get(f"{base_url}/key", headers={"Authorization": f"Bearer {emp}"},
                     verify=str(CA_CRT))
    assert r.status_code == 401


def test_https_plain_http_refused(base_url: str, db_path: Path) -> None:
    """Server must never speak plain HTTP (no redirect, no listener)."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        # HTTP port is the same 8443 but without TLS -> connection should fail
        # (TLS server will not speak plaintext; the TLS handshake itself fails).
        s.connect(("127.0.0.1", 8443))
        s.sendall(b"GET /health HTTP/1.0\r\nHost: x\r\n\r\n")
        data = s.recv(1024)
        # A TLS server responding to plaintext typically closes or errors;
        # we just assert we did NOT get a clean HTTP 200.
        assert b"HTTP/1.1 200" not in data
    finally:
        s.close()
