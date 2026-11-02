"""Tests for plan todo 27: `python -m server.verify_audit` CLI contract.

Proves the audit HMAC-chain + chain-head-anchor verifier detects tampering:
row-field tamper, tail delete, tail delete WITH forged meta anchor (plan
L273: the running chain cannot be replayed from table data alone), and
middle-row id gaps. CLI-level tests run the documented command via
subprocess (cwd = repo root); `main()` is also exercised directly.
"""

from __future__ import annotations

import pytest

import sqlite3
import subprocess
import sys
from pathlib import Path

from server.audit import record_event
from server.database import init_schema, connect
from server.models import EmployeeToken
from server.verify_audit import main

REPO_ROOT = Path(__file__).resolve().parents[2]
HMAC_KEY = b"\x01" * 32


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "test.db"


@pytest.fixture()
def hmac_key_file(tmp_path: Path) -> Path:
    p = tmp_path / "hmac.key"
    p.write_bytes(HMAC_KEY)
    return p


@pytest.fixture()
def conn(db_path: Path) -> sqlite3.Connection:
    init_schema(db_path)
    c = connect(db_path)
    yield c
    c.close()


def _seed_events(conn: sqlite3.Connection, n: int) -> None:
    """Record n chained events and commit so a separate process sees them."""
    rec = EmployeeToken(token_hash="x", employee="alice", level="employee",
                        issued_at="2024-01-01T00:00:00+00:00",
                        expires_at="2025-01-01T00:00:00+00:00", revoked=False)
    for i in range(n):
        record_event(conn, rec, {"action": "encrypt", "file_hash": ("%064d" % i)},
                     hmac_key=HMAC_KEY)
    conn.commit()


def _run_cli(db: Path, key_file: Path) -> subprocess.CompletedProcess[str]:
    """Run the documented command: python -m server.verify_audit <db> <hmac_key>."""
    return subprocess.run(
        [sys.executable, "-m", "server.verify_audit", str(db), str(key_file)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


# --- CLI: clean databases pass -------------------------------------------------

def test_cli_clean_populated_db_exits_zero(db_path: Path, conn: sqlite3.Connection,
                                           hmac_key_file: Path) -> None:
    _seed_events(conn, 4)
    conn.close()
    proc = _run_cli(db_path, hmac_key_file)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "OK: audit chain verified (4 events)" in proc.stdout


def test_cli_empty_db_exits_zero(db_path: Path, hmac_key_file: Path) -> None:
    init_schema(db_path)  # no events: anchor absent -> valid empty ledger
    proc = _run_cli(db_path, hmac_key_file)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "OK: audit chain verified (0 events)" in proc.stdout


# --- CLI: tampering is detected with row/reason in output ----------------------

def test_cli_detects_tampered_row_field(db_path: Path, conn: sqlite3.Connection,
                                        hmac_key_file: Path) -> None:
    _seed_events(conn, 3)
    conn.execute("UPDATE events SET employee = 'mallory' WHERE id = 2")
    conn.commit()
    conn.close()
    proc = _run_cli(db_path, hmac_key_file)
    assert proc.returncode != 0
    assert "FAIL" in proc.stdout
    assert "mac mismatch at row 2" in proc.stdout


def test_cli_detects_tail_delete(db_path: Path, conn: sqlite3.Connection,
                                 hmac_key_file: Path) -> None:
    _seed_events(conn, 5)
    conn.execute("DELETE FROM events WHERE id > 3")
    conn.commit()
    conn.close()
    proc = _run_cli(db_path, hmac_key_file)
    assert proc.returncode != 0
    assert "FAIL" in proc.stdout
    assert "chain_head anchor mismatch" in proc.stdout


def test_cli_detects_tail_delete_with_forged_meta(db_path: Path, conn: sqlite3.Connection,
                                                  hmac_key_file: Path) -> None:
    """Plan L273: delete tail N rows AND forge the anchor from table data.

    The attacker copies the new last row's mac into meta.chain_head and sets
    chain_count to the remaining row count — the strongest forgery possible
    from table data alone. The running chain head cannot be replayed from
    table data, so the verifier must STILL detect it.
    """
    _seed_events(conn, 5)
    conn.execute("DELETE FROM events WHERE id > 3")
    last_mac = conn.execute("SELECT mac FROM events WHERE id = 3").fetchone()["mac"]
    conn.execute("UPDATE meta SET value = ? WHERE key = 'chain_head'", (last_mac,))
    conn.execute("UPDATE meta SET value = '3' WHERE key = 'chain_count'")
    conn.commit()
    # Given-pin: the forgery is realistic (meta now matches what the table shows).
    forged = {r["key"]: r["value"] for r in
              conn.execute("SELECT key, value FROM meta WHERE key IN ('chain_head', 'chain_count')")}
    assert forged == {"chain_head": last_mac, "chain_count": "3"}
    conn.close()

    proc = _run_cli(db_path, hmac_key_file)
    assert proc.returncode != 0
    assert "FAIL" in proc.stdout
    assert "chain_head anchor mismatch" in proc.stdout


def test_cli_detects_middle_row_delete(db_path: Path, conn: sqlite3.Connection,
                                       hmac_key_file: Path) -> None:
    _seed_events(conn, 3)
    conn.execute("DELETE FROM events WHERE id = 2")
    conn.commit()
    conn.close()
    proc = _run_cli(db_path, hmac_key_file)
    assert proc.returncode != 0
    assert "FAIL" in proc.stdout
    assert "id gap" in proc.stdout
    assert "row 3" in proc.stdout  # offending row is located


# --- direct API: main(argv) contract -------------------------------------------

def test_main_clean_db_returns_zero(db_path: Path, conn: sqlite3.Connection,
                                    hmac_key_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _seed_events(conn, 2)
    conn.close()
    assert main([str(db_path), str(hmac_key_file)]) == 0
    assert "OK: audit chain verified (2 events)" in capsys.readouterr().out


def test_main_tampered_row_returns_one_and_locates_row(
        db_path: Path, conn: sqlite3.Connection, hmac_key_file: Path,
        capsys: pytest.CaptureFixture[str]) -> None:
    _seed_events(conn, 3)
    conn.execute("UPDATE events SET file_hash = '%s' WHERE id = 1" % ("f" * 64))
    conn.commit()
    conn.close()
    assert main([str(db_path), str(hmac_key_file)]) == 1
    assert "mac mismatch at row 1" in capsys.readouterr().out


def test_main_missing_db_returns_one(tmp_path: Path, hmac_key_file: Path,
                                     capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(tmp_path / "nope.db"), str(hmac_key_file)]) == 1
    assert "database not found" in capsys.readouterr().out


def test_main_missing_key_file_returns_one(db_path: Path, tmp_path: Path,
                                           capsys: pytest.CaptureFixture[str]) -> None:
    init_schema(db_path)
    assert main([str(db_path), str(tmp_path / "nope.key")]) == 1
    assert "key file not found" in capsys.readouterr().out
