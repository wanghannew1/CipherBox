"""Seed a local cipherbox server database + HMAC audit key for TESTING.

Local test helper (NOT the production bootstrap — that is deploy/
server_bootstrap.ps1, todo 20).  Creates the SQLite schema, seeds exactly one
admin and one employee token via ``server.auth`` (``secrets.token_urlsafe(32)``,
only the SHA-256 digest is stored, employee column set), writes a 32-byte
``os.urandom`` HMAC key file for the audit chain, and prints the two plaintext
tokens ONCE — sanctioned for one-time distribution by plan todo 20.
Nothing else is written.

Example:
    python deploy/seed_local.py --db server\\cipherbox.db --hmac-out server\\audit-hmac.key
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_REPO_ROOT = str(Path(__file__).resolve().parents[1])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from server import auth, database, key_manager  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="seed_local", description="seed a local cipherbox server DB (test helper)")
    parser.add_argument("--db", default=os.path.join(_REPO_ROOT, "server", "cipherbox.db"),
                        help="SQLite database path (default: server/cipherbox.db)")
    parser.add_argument("--hmac-out", default=os.path.join(_REPO_ROOT, "server", "audit-hmac.key"),
                        help="where to write the 32-byte HMAC audit key")
    parser.add_argument("--admin-name", default="admin")
    parser.add_argument("--employee-name", default="employee1")
    args = parser.parse_args(argv)

    database.init_schema(args.db)
    with database.session(args.db) as conn:
        admin_token = auth.issue_token(conn, args.admin_name, "admin")
        employee_token = auth.issue_token(conn, args.employee_name, "employee")
        key_set = key_manager.rotate(conn)  # 初始主密钥 v1：保证 /key 首次即非空

    hmac_key = os.urandom(32)
    with open(args.hmac_out, "wb") as fh:
        fh.write(hmac_key)

    print(f"[seed] db: {args.db}")
    print(f"[seed] hmac key file: {args.hmac_out} (32 random bytes; ACL-restrict it)")
    print(f"[seed] master key: v{key_set['current']} issued (key material NOT printed)")
    print(f"[seed] hmac key file: {args.hmac_out} (32 random bytes; ACL-restrict it)")
    print(f"[seed] admin token (shown ONCE - store securely): {admin_token}")
    print(f"[seed] employee token (shown ONCE - store securely): {employee_token}")
    print("[seed] if either token leaks, revoke + reissue via the admin API.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
