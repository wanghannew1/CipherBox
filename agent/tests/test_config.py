"""Config-loader and build_runtime wiring tests for the agent composition root.

DPAPI runs unmocked (works on this machine — same pattern as the existing
opener/key-manager DPAPI tests).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from agent.__main__ import build_runtime
from agent.config import REPO_ROOT, ConfigError, load_config
from agent.key_manager import dpapi_encrypt


def _client_json(tmp_path: Path) -> dict:
    return {
        "server_url": "https://cipherbox.example:8443",
        "ca_cert_file": "",
        "protected_dir": "S:\\",
        "temp_root": r"S:\.cipherbox-tmp",
        "service_profile": r"S:\.cipherbox-profile\service",
        "controlled_profile": r"S:\.cipherbox-profile\controlled",
        "session_dir": r"S:\appdata-ish\sessions",
        "keycache": "config-relative/keycache.dat",
        "audit_queue": r"S:\appdata-ish\audit-queue.json",
    }


class TestLoadConfig:
    def test_parses_paths_and_dpapi_token(self, tmp_path: Path):
        token_file = tmp_path / "token.dpapi"
        token_file.write_bytes(dpapi_encrypt(b"employee-token-1"))
        config_file = tmp_path / "client.json"
        config_file.write_text(json.dumps(_client_json(tmp_path)), encoding="utf-8")

        loaded = load_config(config_file, token_file)

        assert loaded.token == "employee-token-1"
        assert loaded.config.server_url == "https://cipherbox.example:8443"
        assert loaded.config.protected_dir == os.path.normpath("S:\\")
        assert loaded.config.temp_root == os.path.normpath(r"S:\.cipherbox-tmp")
        # relative config values anchor at the repository root
        assert loaded.config.keycache == os.path.normpath(
            os.path.join(str(REPO_ROOT), "config-relative", "keycache.dat"))
        assert loaded.config.ca_bundle is None  # empty ca_cert_file -> no pin

    def test_pinned_ca_bundle(self, tmp_path: Path):
        values = _client_json(tmp_path)
        values["ca_cert_file"] = r"C:\certs\ca.crt"
        config_file = tmp_path / "client.json"
        config_file.write_text(json.dumps(values), encoding="utf-8")
        token_file = tmp_path / "token.dpapi"
        token_file.write_bytes(dpapi_encrypt(b"tok"))

        loaded = load_config(config_file, token_file)
        assert loaded.config.ca_bundle == r"C:\certs\ca.crt"

    def test_missing_key_rejected(self, tmp_path: Path):
        values = _client_json(tmp_path)
        del values["keycache"]
        config_file = tmp_path / "client.json"
        config_file.write_text(json.dumps(values), encoding="utf-8")

        with pytest.raises(ConfigError) as excinfo:
            load_config(config_file, tmp_path / "token.dpapi")
        assert "keycache" in str(excinfo.value)

    def test_undecryptable_token_rejected(self, tmp_path: Path):
        config_file = tmp_path / "client.json"
        config_file.write_text(json.dumps(_client_json(tmp_path)), encoding="utf-8")
        token_file = tmp_path / "token.dpapi"
        token_file.write_bytes(os.urandom(64))  # not a DPAPI blob

        with pytest.raises(ConfigError) as excinfo:
            load_config(config_file, token_file)
        assert "DPAPI" in str(excinfo.value)

    def test_missing_token_file_rejected(self, tmp_path: Path):
        config_file = tmp_path / "client.json"
        config_file.write_text(json.dumps(_client_json(tmp_path)), encoding="utf-8")

        with pytest.raises(ConfigError):
            load_config(config_file, tmp_path / "absent.dpapi")

    def test_missing_config_file_rejected(self, tmp_path: Path):
        with pytest.raises(ConfigError) as excinfo:
            load_config(tmp_path / "absent.json", tmp_path / "token.dpapi")
        assert "not found" in str(excinfo.value)


class TestBuildRuntime:
    def test_watcher_and_pipe_wired(self, tmp_path: Path):
        values = _client_json(tmp_path)
        values["protected_dir"] = str(tmp_path / "protected")
        values["temp_root"] = str(tmp_path / "tmp")
        values["session_dir"] = str(tmp_path / "sessions")
        values["keycache"] = str(tmp_path / "keycache.dat")
        values["audit_queue"] = str(tmp_path / "audit-queue.json")
        (tmp_path / "protected").mkdir()
        token_file = tmp_path / "token.dpapi"
        token_file.write_bytes(dpapi_encrypt(b"tok"))
        config_file = tmp_path / "client.json"
        config_file.write_text(json.dumps(values), encoding="utf-8")
        loaded = load_config(config_file, token_file)

        rt = build_runtime(loaded, with_watcher=True,
                           pipe_name=r"\\.\pipe\cipherbox-buildtest-" + os.urandom(4).hex())

        assert rt.watcher is not None
        assert rt.watcher.protected_root == os.path.normpath(str(tmp_path / "protected"))
        assert rt.pipe_server.pipe_name.startswith(r"\\.\pipe\cipherbox-buildtest-")
        rt.pipe_server.stop()
        rt.pipe_server.close()
