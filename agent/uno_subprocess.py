"""One-shot UNO encryption worker for LibreOffice's bundled python.

System python cannot import pyuno (it is version-locked to LO's python 3.13),
and LO's python lacks the resident agent's dependencies (watchdog/olefile) —
so the resident agent delegates each encryption to THIS module running under
LO's python.  Import chain is deliberately stdlib + agent.uno_driver only.

    stdin:   one JSON object {"plain": "...", "cbx": "...", "password": "..."}
             (the password travels via stdin, never argv)
    stdout:  one JSON line {"ok": true} | {"ok": false, "error": "<message>"}
    exit:    0 on success, 1 on encryption failure, 2 on bad usage/input
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_REPO_ROOT = str(Path(__file__).resolve().parents[1])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from agent.uno_driver import UnoDriver, UnoDriverError  # noqa: E402


def _respond(payload: dict) -> None:
    print(json.dumps(payload, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv != ["encrypt"]:
        _respond({"ok": False, "error": f"usage: python -m agent.uno_subprocess encrypt (got {argv!r})"})
        return 2
    try:
        request = json.loads(sys.stdin.read())
    except json.JSONDecodeError as exc:
        _respond({"ok": False, "error": f"invalid stdin JSON: {exc}"})
        return 2
    if (not isinstance(request, dict)
            or not all(isinstance(request.get(key), str) and request.get(key)
                       for key in ("plain", "cbx", "password"))):
        _respond({"ok": False, "error": 'stdin must be {"plain","cbx","password"} non-empty strings'})
        return 2
    try:
        UnoDriver().encrypt_to_cbx(request["plain"], request["cbx"], request["password"])
    except UnoDriverError as exc:
        _respond({"ok": False, "error": str(exc)})
        return 1
    except Exception as exc:  # worker boundary: any failure -> JSON response
        _respond({"ok": False, "error": f"encryption failed: {exc}"})
        return 1
    _respond({"ok": True})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
