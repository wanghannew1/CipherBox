"""TLS smoke for todo 5 (artifact script, not committed):

1. Start real uvicorn on 127.0.0.1:8443 with the generated certs (factory app).
2. HTTPS GET /health pinned to our CA -> expect 200 {"status":"ok"}.
3. HTTPS GET /key WITHOUT token -> expect 401 (protected over TLS too).
4. Plain HTTP GET to the same port -> must be REFUSED (TLS-only listener).
5. Kill uvicorn in `finally` (no orphan processes).
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import httpx

REPO = Path(__file__).resolve().parents[4]
PY = REPO / "server" / ".venv" / "Scripts" / "python.exe"
CERTS = REPO / "server" / "certs"
DB = REPO / "server" / "cipherbox-smoke.db"

BASE = "https://127.0.0.1:8443"


def main() -> int:
    DB.unlink(missing_ok=True)
    proc = subprocess.Popen(
        [str(PY), "-m", "uvicorn", "server.app:create_app", "--factory",
         "--host", "127.0.0.1", "--port", "8443",
         "--ssl-certfile", str(CERTS / "server.crt"),
         "--ssl-keyfile", str(CERTS / "server.key")],
        cwd=REPO,
        env={**os.environ, "CIPHERBOX_DB": str(DB)},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        # Bounded readiness poll (10 s cap).
        deadline = time.monotonic() + 10
        while True:
            if proc.poll() is not None:
                err = proc.stderr.read().decode("utf-8", "replace") if proc.stderr else ""
                print(f"FAIL: uvicorn exited early rc={proc.returncode}\n{err}")
                return 1
            try:
                r = httpx.get(f"{BASE}/health", verify=str(CERTS / "ca.crt"), timeout=2.0)
                if r.status_code == 200:
                    break
            except httpx.TransportError:
                pass
            if time.monotonic() > deadline:
                print("FAIL: readiness timeout after 10s")
                return 1
            time.sleep(0.25)

        ok = True

        r = httpx.get(f"{BASE}/health", verify=str(CERTS / "ca.crt"), timeout=5.0)
        print(f"HTTPS /health -> {r.status_code} {r.text.strip()}")
        ok &= r.status_code == 200 and r.json() == {"status": "ok"}

        r = httpx.get(f"{BASE}/key", verify=str(CERTS / "ca.crt"), timeout=5.0)
        print(f"HTTPS /key (no token) -> {r.status_code} {r.text.strip()}")
        ok &= r.status_code == 401

        try:
            httpx.get(f"http://127.0.0.1:8443/health", timeout=5.0)
            print("FAIL: plain HTTP was answered")
            ok = False
        except httpx.TransportError as exc:
            print(f"plain HTTP /health -> REFUSED ({type(exc).__name__})")

        print("RESULT: PASS" if ok else "RESULT: FAIL")
        return 0 if ok else 1
    finally:
        proc.kill()
        proc.wait(timeout=10)
        DB.unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
