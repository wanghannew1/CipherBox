"""CipherBoxDataSpace engine deployment into a LibreOffice profile.

The forced-encrypt save (CryptoType="CipherBoxDataSpace") needs the cipherbox
crypto engine registered in the office that performs the store.  The resident
service office gets it from ``start_soffice.ps1``; the CONTROLLED GUI office
uses the shared ``controlled`` profile and used to boot WITHOUT the engine --
every payload store failed with ``SfxBaseModel::impl_store ... Io Write/16``
(live 2026-11-18), the interceptor refused, and plaintext was never written
(fail-closed) but the whole "save lands encrypted" feature stayed dead.

Deployment mirrors ``start_soffice.ps1`` exactly (the recipe is
real-machine-proven there):

1. the engine modules ``cipherbox.py`` + ``cipherbox_crypto.py`` side by side
   under ``<profile>/user/Scripts/python/`` (hash-guarded copy -- BOTH files,
   the engine imports its sibling);
2. ``<profile>/user/extensions/shared/cipherbox/components.rdb`` mapping the
   service name to the Python loader + module URL;
3. ``<profile>/user/extensions/shared/registry/com.sun.star.comp.deployment.
   component.PackageRegistryBackend/unorc`` pointing UNO_SERVICES at the rdb.

A bare module copy does NOT register the service -- the rdb + unorc are
required.  Idempotent: files are written only when absent or hash-different.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

REPO_ROOT = str(Path(__file__).resolve().parents[1])
ENGINE_SRC_DIR = os.path.join(REPO_ROOT, "lo-encryption-demo", "src")
ENGINE_MODULES = ("cipherbox.py", "cipherbox_crypto.py")

_COMPONENT_BACKEND = (
    "user/extensions/shared/registry/"
    "com.sun.star.comp.deployment.component.PackageRegistryBackend"
)

_UNORC = "ORIGIN=$ORIGIN\nUNO_SERVICES=?$SHARED_EXTENSIONS_USER/cipherbox/components.rdb\n"

_RDB = """<?xml version="1.0"?>
<components xmlns="http://openoffice.org/2010/uno-components">
    <component loader="com.sun.star.loader.Python" uri="vnd.openoffice.pymodule:{module_url}">
        <implementation name="com.cipherbox.CipherBoxDataSpace">
            <service name="com.sun.star.comp.oox.crypto.CipherBoxDataSpace"/>
        </implementation>
    </component>
</components>
"""


def _file_hash(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_if_changed(path: str, data: str | bytes, log) -> None:
    desired = data.encode("ascii") if isinstance(data, str) else data
    try:
        with open(path, "rb") as fh:
            if fh.read() == desired:
                return  # unchanged
    except OSError:
        pass
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(desired)
    log(f"[agent] engine deploy: wrote {path}")


def ensure_cipherbox_engine(profile_dir: str, *,
                            src_dir: str = ENGINE_SRC_DIR,
                            log=print) -> None:
    """Deploy the engine modules + registration into ``profile_dir``.

    Call BEFORE launching a soffice on this profile (the engine registry is
    read at office boot).  Raises on copy/IO failure -- a missing engine
    means every encrypted save fails later; loud is better than silent.
    """
    profile = Path(profile_dir)
    engine_dir = profile / "user" / "Scripts" / "python"
    ext_dir = profile / "user" / "extensions" / "shared" / "cipherbox"
    backend_dir = profile / _COMPONENT_BACKEND

    for name in ENGINE_MODULES:
        src = os.path.join(src_dir, name)
        dst = engine_dir / name
        if not os.path.isfile(src):
            raise FileNotFoundError(f"engine source missing: {src}")
        if dst.is_file() and _file_hash(str(dst)) == _file_hash(src):
            continue  # hash-guarded: unchanged
        engine_dir.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(open(src, "rb").read())
        log(f"[agent] engine deploy: {src} -> {dst}")

    profile_url = profile.as_uri()
    module_url = profile_url + "/user/Scripts/python/cipherbox"
    _write_if_changed(str(ext_dir / "components.rdb"),
                      _RDB.format(module_url=module_url), log)
    _write_if_changed(str(backend_dir / "unorc"), _UNORC, log)
