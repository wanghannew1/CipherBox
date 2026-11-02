"""Subprocess-delegation tests for agent/uno_driver.py.

System python can NEVER import pyuno (version-locked to LO's bundled python
3.13), so with no injectable uno module the driver must delegate each
encryption to ``python -m agent.uno_subprocess`` under LibreOffice's python.
Faked here: ``_default_uno`` raises ImportError, ``subprocess.run`` is a
recording fake that also simulates the worker's artifact.  Proves:

* the password travels in the stdin payload, NEVER in argv;
* the spawn is bounded (timeout=120) and cwd = repo root;
* ok-path returns after the claimed artifact exists; {"ok": false},
  rc != 0, timeout, and missing-LO-python all raise UnoDriverError
  ("subprocess") with the password scrubbed from the failure tail;
* an injected fake uno module never touches subprocess.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent.tests.test_uno_driver_unit import CFB_OUTPUT, FakeUno, make_plain
from agent.uno_driver import PIPE_URL, REPO_ROOT, UnoDriver, UnoDriverError


class TestSubprocessDelegation:
    @staticmethod
    def _import_failing_driver(monkeypatch) -> UnoDriver:
        def raise_import_error():
            raise ImportError(
                "Module use of python313.dll conflicts with this version of Python")

        monkeypatch.setattr("agent.uno_driver._default_uno", raise_import_error)
        return UnoDriver()  # no injected module -> delegation path

    @staticmethod
    def _fake_run(monkeypatch, *, returncode: int = 0,
                  stdout: str = '{"ok": true}', stderr: str = "",
                  write_cbx: bool = True) -> dict:
        recorded: dict = {}

        def fake_run(args, **kwargs):
            recorded["args"] = list(args)
            recorded["input"] = kwargs.get("input")
            recorded["timeout"] = kwargs.get("timeout")
            recorded["cwd"] = kwargs.get("cwd")
            recorded["called"] = True
            if write_cbx and kwargs.get("input"):
                payload = json.loads(kwargs["input"])
                with open(payload["cbx"], "wb") as fh:  # simulate the worker artifact
                    fh.write(CFB_OUTPUT)
            import subprocess
            return subprocess.CompletedProcess(args, returncode, stdout, stderr)

        monkeypatch.setattr("subprocess.run", fake_run)
        return recorded

    def test_delegates_password_via_stdin_not_argv(self, tmp_path: Path, monkeypatch):
        plain = make_plain(tmp_path)
        recorded = self._fake_run(monkeypatch)
        driver = self._import_failing_driver(monkeypatch)

        driver.encrypt_to_cbx(str(plain), str(plain) + ".cbx", "secret-pw-1")

        assert recorded["called"] is True
        argv = " ".join(str(arg) for arg in recorded["args"])
        assert "secret-pw-1" not in argv
        assert recorded["args"][1:] == ["-m", "agent.uno_subprocess", "encrypt"]
        payload = json.loads(recorded["input"])
        assert payload["password"] == "secret-pw-1"
        assert payload["cbx"].endswith("a.docx.cbx")

    def test_subprocess_bounds_and_cwd(self, tmp_path: Path, monkeypatch):
        plain = make_plain(tmp_path)
        recorded = self._fake_run(monkeypatch)
        driver = self._import_failing_driver(monkeypatch)

        driver.encrypt_to_cbx(str(plain), str(plain) + ".cbx", "pw")

        assert recorded["timeout"] == 120
        assert recorded["cwd"] == REPO_ROOT

    def test_ok_false_response_raises_typed(self, tmp_path: Path, monkeypatch):
        plain = make_plain(tmp_path)
        self._fake_run(monkeypatch, returncode=0,
                       stdout=json.dumps({"ok": False, "error": "UNO connect failed: dead"}))
        driver = self._import_failing_driver(monkeypatch)

        with pytest.raises(UnoDriverError) as excinfo:
            driver.encrypt_to_cbx(str(plain), str(plain) + ".cbx", "pw")

        assert excinfo.value.stage == "subprocess"
        assert "dead" in str(excinfo.value)

    def test_nonzero_rc_raises_typed(self, tmp_path: Path, monkeypatch):
        plain = make_plain(tmp_path)
        self._fake_run(monkeypatch, returncode=3, stderr="Traceback: boom")
        driver = self._import_failing_driver(monkeypatch)

        with pytest.raises(UnoDriverError) as excinfo:
            driver.encrypt_to_cbx(str(plain), str(plain) + ".cbx", "pw")

        assert excinfo.value.stage == "subprocess"
        assert "boom" in str(excinfo.value)

    def test_timeout_raises_typed(self, tmp_path: Path, monkeypatch):
        import subprocess

        plain = make_plain(tmp_path)

        def timed_out(args, **kwargs):
            raise subprocess.TimeoutExpired(args, 120)

        monkeypatch.setattr("subprocess.run", timed_out)
        driver = self._import_failing_driver(monkeypatch)

        with pytest.raises(UnoDriverError) as excinfo:
            driver.encrypt_to_cbx(str(plain), str(plain) + ".cbx", "pw")

        assert excinfo.value.stage == "subprocess"
        assert "timed out" in str(excinfo.value)

    def test_missing_lo_python_raises_with_guidance(self, tmp_path: Path, monkeypatch):
        plain = make_plain(tmp_path)
        recorded = self._fake_run(monkeypatch)
        monkeypatch.setenv("CIPHERBOX_LO_PYTHON", str(tmp_path / "absent" / "python.exe"))
        driver = self._import_failing_driver(monkeypatch)

        with pytest.raises(UnoDriverError) as excinfo:
            driver.encrypt_to_cbx(str(plain), str(plain) + ".cbx", "pw")

        assert excinfo.value.stage == "subprocess"
        assert "CIPHERBOX_LO_PYTHON" in str(excinfo.value)
        assert recorded.get("called") is None  # never spawned anything

    def test_env_override_selects_lo_python(self, tmp_path: Path, monkeypatch):
        plain = make_plain(tmp_path)
        lo_python = tmp_path / "python.exe"
        lo_python.write_bytes(b"")  # just needs to exist
        recorded = self._fake_run(monkeypatch)
        monkeypatch.setenv("CIPHERBOX_LO_PYTHON", str(lo_python))
        driver = self._import_failing_driver(monkeypatch)

        driver.encrypt_to_cbx(str(plain), str(plain) + ".cbx", "pw")

        assert recorded["args"][0] == str(lo_python)

    def test_failure_tail_scrubs_password(self, tmp_path: Path, monkeypatch):
        plain = make_plain(tmp_path)
        self._fake_run(monkeypatch, returncode=1,
                       stderr="oops secret-pw-leak leaked in traceback")
        driver = self._import_failing_driver(monkeypatch)

        with pytest.raises(UnoDriverError) as excinfo:
            driver.encrypt_to_cbx(str(plain), str(plain) + ".cbx", "secret-pw-leak")

        assert "secret-pw-leak" not in str(excinfo.value)
        assert "***" in str(excinfo.value)

    def test_ok_claim_without_artifact_rejected(self, tmp_path: Path, monkeypatch):
        plain = make_plain(tmp_path)
        cbx = tmp_path / "a.docx.cbx"
        self._fake_run(monkeypatch, write_cbx=False)  # fake writes nothing
        driver = self._import_failing_driver(monkeypatch)

        with pytest.raises(UnoDriverError) as excinfo:
            driver.encrypt_to_cbx(str(plain), str(cbx), "pw")

        assert "missing" in str(excinfo.value)

    def test_injected_fake_module_never_touches_subprocess(self, tmp_path: Path, monkeypatch):
        def forbidden(*args, **kwargs):
            raise AssertionError("subprocess must not be used with injected uno module")

        monkeypatch.setattr("subprocess.run", forbidden)
        fake = FakeUno()
        plain = make_plain(tmp_path)
        driver = UnoDriver(uno_module=fake)

        driver.encrypt_to_cbx(str(plain), str(plain) + ".cbx", "pw")

        assert fake.resolve_urls == [PIPE_URL]  # in-process path only
