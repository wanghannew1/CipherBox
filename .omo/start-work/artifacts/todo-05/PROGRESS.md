# todo-05 PROGRESS — 服务器骨架 + 每员工令牌认证（TTL/续期/吊销）+ 健康检查（HTTPS）

[START] plan todo5 contract read (lines 108-113) + Scope + Verification strategy; env verified: Win, python 3.11.7 (anaconda), openssl on PATH; scope = server/ only, lo-encryption-demo untouched.
[STEP] artifacts dir created; next: write server/{app,db,auth}.py + tests + requirements + make_certs.ps1.
[STEP] wrote server/db.py (schema employees(token_hash, employee, level, issued_at, expires_at, revoked)), server/auth.py (sha256-hash-only storage, TTL=90d, issue/verify/renew/revoke with explicit `now` param), server/app.py (factory create_app, /health open, uniform 401 dep, /key placeholder envelope, /token/renew, /admin/revoke admin-only->403, uvicorn --factory HTTPS-8443 command documented in docstring), server/tests/test_auth.py (18 cases, tmp_path DB per test, backdated issued_at instead of sleeps), server/requirements.txt, server/scripts/make_certs.ps1 (CA+server cert+SAN+chain verify), .gitignore += .venv/ + server/certs/ + server/*.db. No tokens/keys logged anywhere (no logging of Authorization header; uvicorn access log has no headers).
[STEP] venv created (7.9s) + pip install -r requirements.txt exit 0 (15.2s).
[FIX] test_token_plaintext_never_stored failed once (no such table) — conn fixture now calls db.init_schema itself so direct-DB tests don't depend on the client fixture. Re-run: 18 passed.
[FIX] make_certs.ps1 two real-env fixes: (1) $PSScriptRoot unreliable in param() default on PS5.1 -> resolve default in body with MyInvocation fallback; (2) anaconda OpenSSL has no default openssl.cnf ('req' hard-fails) -> script writes a minimal cnf and sets OPENSSL_CONF for its own process.
[VERIFY] make_certs.ps1 exit 0 (1.5s): CA + server cert (SAN DNS:localhost/IP:127.0.0.1) + in-script `openssl verify` chain OK; transcript make-certs.txt.
[VERIFY] TLS smoke (tls-smoke.txt): documented uvicorn --factory command bound 127.0.0.1:8443 with certs; httpx verify=ca.crt GET /health -> 200 {"status":"ok"}; plain HTTP -> curl exit 52 (TLS-only port refused cleartext); uvicorn killed in finally. NOTE: Windows curl.exe is Schannel — cannot honor --cacert; pinning checks must use Python (todo 9 note).
[VERIFY] pytest: run1 `server/.venv/Scripts/python.exe -m pytest server/tests/test_auth.py -q` = 18 passed exit 0; full `pytest server/tests -q` captured to pytest-auth.txt (18 passed, exit 0, 0.70s); determinism rerun captured to pytest-auth-rerun.txt (18 passed, exit 0). One warning: StarletteDeprecationWarning TestClient/httpx -> httpx2 (harmless today, risk noted).
[COMMIT] edd9ed2 `feat(server): FastAPI skeleton + employee token auth (TTL/renew/revoke)` — 7 files, 704 insertions, nothing else staged (dry-run verified). Pre-existing Wave 0 parallel changes (ledger.jsonl, todo-03/04 artifacts, lo-encryption-demo spike scripts, opencode.json) left untouched. server/cipherbox.db smoke side-effect deleted; .venv/ + certs/ + *.db git-ignored, .omo/ not committed.

## Adversarial observables
- misleading_success_output: tests assert exact status codes AND full bodies (401 `{"detail":"invalid or missing credentials"}` uniform; /key placeholder `{"versions": [], "current": None}`; revoke `{"revoked": 1}`) AND stored DB values (`token_hash == sha256(token)`, 64-hex regex, plaintext absent from every column). Cert smoke asserted `200 {"status":"ok"}` over a CA-pinned TLS handshake, not mere process liveness.
- stale_state: fresh tmp_path SQLite per test (both fixtures init schema independently); rerun transcript shows identical 18-passed — no cross-test leakage.
- flaky_tests: no sleeps, no clock freezing; expiry derived by backdating `issued_at` (30d valid / 91d expired); renew assertion margin >=29 days; suite ~0.7-0.9s.
- hung_or_long_commands: all commands bounded <=120s; observed venv 7.9s, pip 15.2s, pytest <=1.2s, make_certs 1.5s, smoke ~11s incl. capped 10s readiness poll; smoke kills uvicorn in finally — no open-ended waits.
- prompt_injection: N/A — no external/untrusted content processed (plan text + own code only).
- cancel_resume: N/A — single uninterrupted execution, no resume needed.
- dirty_worktree: parallel Wave 0 dirty entries observed (see [COMMIT]) and excluded; `git add --dry-run` + `git diff --cached --stat` proved only the 7 task files staged; git index.lock never hit (retry loop armed, unused).
- repeated_interruptions: N/A — none occurred.

[DONE] todo-05 complete.
