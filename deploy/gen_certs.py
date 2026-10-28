"""Generate the self-signed CA + server certificate for cipherbox HTTPS (plan todo 5).

Pure-Python wrapper around the OpenSSL CLI (OpenSSL must be on PATH; the
bundled LibreOffice python is NOT required — any Python 3.11+ works):

    server\\.venv\\Scripts\\python.exe deploy\\gen_certs.py [--force]

Outputs into ``server/certs/`` (git-ignored, ACL-locked down by todo 20):

    ca.key / ca.crt      local CA (clients pin ca.crt)
    server.key           server private key
    server.crt           server certificate signed by the CA (SAN: localhost / 127.0.0.1)
    ca.srl               CA serial state

The script is idempotent: existing material is kept unless ``--force`` is
given. It writes a minimal openssl.cnf + SAN extfile into the output dir
because some Windows OpenSSL builds ship without a default config (which
makes ``req`` hard-fail). ``openssl verify`` checks the chain at the end.

Exit codes: 0 success; 2 openssl not found / command failure.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO_ROOT / "server" / "certs"
DEFAULT_SANS = ["DNS:localhost", "IP:127.0.0.1"]
CA_DAYS = 3650
SERVER_DAYS = 825  # ~27 months; rotate via deploy rerun with --force.

_MINIMAL_CNF = """\
[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = cipherbox
"""

_EXTFILE_TMPL = """\
subjectAltName = {sans}
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
"""


def _run(openssl: str, args: list[str], *, env: dict[str, str]) -> None:
    cmd = [openssl, *args]
    proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        sys.stderr.write(f"ERROR: {' '.join(cmd)}\n{proc.stderr}\n")
        raise SystemExit(2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate cipherbox self-signed CA + server cert.")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output dir (default server/certs)")
    parser.add_argument("--force", action="store_true", help="overwrite existing material")
    parser.add_argument("--san", action="append", default=None,
                        help="extra SAN entry, e.g. --san DNS:cipherbox.local --san IP:192.168.1.10")
    args = parser.parse_args(argv)

    openssl = shutil.which("openssl")
    if openssl is None:
        sys.stderr.write("ERROR: openssl not found on PATH. Install OpenSSL (e.g. via Git for "
                         "Windows or LibreOffice bundle) and retry.\n")
        return 2

    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    ca_key, ca_crt = out / "ca.key", out / "ca.crt"
    srv_key, srv_crt, srv_csr = out / "server.key", out / "server.crt", out / "server.csr"

    if not args.force and all(p.exists() for p in (ca_key, ca_crt, srv_key, srv_crt)):
        print(f"SKIP: certificate material already exists in {out} (use --force to regenerate)")
        return 0

    env = dict(os.environ)
    with tempfile.TemporaryDirectory(prefix="cipherbox-cnf-", dir=out) as tmp:
        tmpdir = Path(tmp)
        cnf = tmpdir / "openssl.cnf"
        cnf.write_text(_MINIMAL_CNF, encoding="utf-8")
        env["OPENSSL_CONF"] = str(cnf)

        sans = DEFAULT_SANS + (args.san or [])
        extfile = tmpdir / "san.ext"
        extfile.write_text(_EXTFILE_TMPL.format(sans=",".join(sans)), encoding="utf-8")

        # 1) CA (self-signed root).
        _run(openssl, ["req", "-x509", "-newkey", "rsa:4096", "-sha256", "-days", str(CA_DAYS),
                       "-nodes", "-keyout", str(ca_key), "-out", str(ca_crt),
                       "-subj", "/CN=cipherbox-local-CA"], env=env)
        # 2) Server key + CSR.
        _run(openssl, ["genrsa", "-out", str(srv_key), "2048"], env=env)
        _run(openssl, ["req", "-new", "-key", str(srv_key), "-out", str(srv_csr),
                       "-subj", "/CN=cipherbox-server"], env=env)
        # 3) Sign the CSR with the CA, copying SAN/ext usage from the extfile.
        _run(openssl, ["x509", "-req", "-in", str(srv_csr), "-CA", str(ca_crt),
                       "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(srv_crt),
                       "-days", str(SERVER_DAYS), "-sha256",
                       "-extfile", str(extfile)], env=env)
        # 4) Verify the chain before declaring success.
        _run(openssl, ["verify", "-CAfile", str(ca_crt), str(srv_crt)], env=env)

    srv_csr.unlink(missing_ok=True)
    print(f"OK: CA + server certificate written to {out}")
    print(f"  ca.crt     -> {ca_crt}  (distribute to clients for pinning)")
    print(f"  server.crt -> {srv_crt}")
    print(f"  server.key -> {srv_key}  (keep private; ACL = service account + admins)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
