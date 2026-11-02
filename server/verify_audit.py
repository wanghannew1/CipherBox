"""cipherbox audit chain verification (plan todo 27).

Usage:

    python -m server.verify_audit [db_path] [hmac_key_file]

Exits 0 when the full HMAC chain + running chain-head anchor verify; exits
non-zero (and prints the offending row / reason) on first failure.
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

from .audit import verify_audit_chain
from .database import init_schema

DEFAULT_DB = Path(__file__).resolve().parents[1] / "server" / "cipherbox.db"


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    db_path = Path(argv[0]) if len(argv) > 0 else DEFAULT_DB
    hmac_key_file = Path(argv[1]) if len(argv) > 1 else None

    if not db_path.exists():
        print(f"FAIL: database not found: {db_path}")
        return 1

    if hmac_key_file is None:
        # Default: look for hmac.key next to the repo root.
        hmac_key_file = Path(__file__).resolve().parents[2] / "hmac.key"
    if not hmac_key_file.exists():
        print(f"FAIL: HMAC key file not found: {hmac_key_file}")
        print("  Set CIPHERBOX_HMAC_KEY_FILE or pass the key file path as argument 2.")
        return 1

    hmac_key = hmac_key_file.read_bytes().strip()
    init_schema(str(db_path))
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        result = verify_audit_chain(conn, hmac_key)
        print(f"OK: audit chain verified ({result['count']} events)")
        return 0
    except ValueError as exc:
        print(f"FAIL: {exc}")
        return 1
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
