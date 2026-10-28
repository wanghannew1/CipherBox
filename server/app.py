"""cipherbox LAN key/audit server — FastAPI application factory (plan todo 5).

HTTPS-ONLY design: the server binds port 8443 with TLS and NEVER binds a
plain HTTP listener (no redirect server either — a redirect would make the
client send one cleartext request carrying the Bearer token).

Generate the self-signed CA + server certificate first:

    server\\.venv\\Scripts\\python.exe deploy\\gen_certs.py

Run (exact command; cert/key paths from server/config.py defaults):

    server\\.venv\\Scripts\\python.exe -m uvicorn server.app:create_app --factory ^
        --host 0.0.0.0 --port 8443 ^
        --ssl-certfile server\\certs\\server.crt --ssl-keyfile server\\certs\\server.key

The SQLite path defaults to server/cipherbox.db and can be overridden with
the CIPHERBOX_DB environment variable (see server/config.py for all knobs).
Real TLS end-to-end verification is todo 9's integration test; this module
only guarantees the app mounts behind TLS and never opens an HTTP port.

Auth contract (todo 5):
- GET /health is unauthenticated.
- Every other endpoint requires `Authorization: Bearer <token>`.
- Missing / malformed / unknown / expired / revoked token -> uniform 401
  ("invalid or missing credentials"), no information leak.
- POST /token/renew (valid token) slides expires_at by +90 days.
- POST /admin/revoke (admin level only) revokes all tokens of an employee;
  non-admin callers get 403.
- GET /key and POST /events both pass through the same revocation check
  (placeholder bodies until todo 6 / todo 7).
"""

from __future__ import annotations

import sqlite3
from datetime import timezone
from pathlib import Path
from typing import Annotated, Any, Iterator

from fastapi import Body, Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from . import audit, auth, database, key_manager
from .config import ServerConfig, load_config
from .models import EmployeeToken

_UNAUTHORIZED_DETAIL = "invalid or missing credentials"


def _unauthorized() -> HTTPException:
    # Single canonical 401 for every auth failure mode — no information leak.
    return HTTPException(
        status_code=401,
        detail=_UNAUTHORIZED_DETAIL,
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_db(request: Request) -> Iterator[sqlite3.Connection]:
    conn = database.connect(request.app.state.db_path)
    try:
        yield conn
    finally:
        conn.close()


DbConn = Annotated[sqlite3.Connection, Depends(get_db)]


def bearer_token(request: Request) -> str:
    """Extract the Bearer credential, rejecting anything malformed with 401."""
    header = request.headers.get("Authorization")
    if header is None:
        raise _unauthorized()
    parts = header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        raise _unauthorized()
    return parts[1]


def current_employee(
    token: Annotated[str, Depends(bearer_token)],
    conn: DbConn,
) -> EmployeeToken:
    rec = auth.verify_token(conn, token)
    if rec is None:
        raise _unauthorized()
    return rec


def require_admin(
    rec: Annotated[EmployeeToken, Depends(current_employee)],
) -> EmployeeToken:
    if rec.level != "admin":
        raise HTTPException(status_code=403, detail="admin privileges required")
    return rec


CurrentEmployee = Annotated[EmployeeToken, Depends(current_employee)]
AdminEmployee = Annotated[EmployeeToken, Depends(require_admin)]


class RevokeRequest(BaseModel):
    employee: str = Field(min_length=1, max_length=256)


def create_app(
    config: ServerConfig | None = None,
    db_path: str | Path | None = None,
) -> FastAPI:
    """Application factory; `uvicorn server.app:create_app --factory`.

    `db_path` overrides config.db_path (tests inject a tmp_path SQLite file).
    """
    if config is None:
        config = load_config(db_path=db_path)
    elif db_path is not None:
        config = load_config(host=config.host, port=config.port, db_path=db_path, cert_dir=config.cert_dir)
    database.init_schema(config.db_path)

    app = FastAPI(title="cipherbox-server")
    app.state.config = config
    app.state.db_path = str(config.db_path)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/key")
    def get_key(rec: CurrentEmployee, conn: DbConn) -> dict[str, Any]:
        # Placeholder envelope only; todo 6 implements real key issuance.
        return key_manager.get_version_set(conn)

    @app.post("/events")
    def post_event(
        rec: CurrentEmployee,
        conn: DbConn,
        payload: dict[str, Any] = Body(default_factory=dict),
    ) -> dict[str, Any]:
        # Auth-gated placeholder; todo 7 implements real persistence + 422s.
        return audit.record_event(conn, rec, payload)

    @app.post("/token/renew")
    def renew(rec: CurrentEmployee, conn: DbConn) -> dict[str, str]:
        new_expiry = auth.renew_token(conn, rec.token_hash)
        if new_expiry is None:
            raise _unauthorized()
        # Same UTC rendering as the stored value (auth._iso format).
        return {
            "expires_at": new_expiry.astimezone(timezone.utc).isoformat(
                timespec="microseconds"
            )
        }

    @app.post("/admin/revoke")
    def revoke(body: RevokeRequest, admin: AdminEmployee, conn: DbConn) -> dict[str, int]:
        return {"revoked": auth.revoke_employee(conn, body.employee)}

    return app
