"""Launcher tests against a real pipe server with a fake session handler.

Covers: successful forward, detached-agent spawn then connect (the fake
spawn brings up a REAL pipe server on the launcher's pipe name), spawn
failure, and the bounded-wait loud failure when the agent never appears.
"""

from __future__ import annotations

import json
import os
import threading
import uuid

import pytest

from agent import launcher
from agent.ipc import OpenPipeServer


def make_unique_name() -> str:
    return r"\\.\pipe\cipherbox-launcher-test-" + uuid.uuid4().hex


def start_server(handler, name: str | None = None) -> tuple[OpenPipeServer, threading.Thread]:
    server = OpenPipeServer(handler, name or make_unique_name())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    assert server.listening.wait(5), "server never started listening"
    return server, thread


def test_forward_ok(capsys):
    received: list[str] = []

    def handler(path: str) -> dict:
        received.append(path)
        return {"ok": True, "changed": False, "re_encrypted": False}

    server, thread = start_server(handler)
    try:
        rc = launcher.main([r"S:\a.docx.cbx", "--pipe", server.pipe_name])
    finally:
        server.stop()
        thread.join(timeout=5)

    assert rc == 0
    assert received == [os.path.abspath(r"S:\a.docx.cbx")]
    printed = json.loads(capsys.readouterr().out)
    assert printed == {"ok": True, "changed": False, "re_encrypted": False}


def test_refusal_is_printed_and_nonzero(capsys):
    server, thread = start_server(
        lambda path: {"ok": False, "error": "busy: another controlled session is active"})
    try:
        rc = launcher.main([r"S:\a.docx.cbx", "--pipe", server.pipe_name])
    finally:
        server.stop()
        thread.join(timeout=5)

    assert rc == 2
    err = capsys.readouterr().err
    assert "busy" in err


def test_spawn_then_connect(monkeypatch):
    """Pipe absent -> spawn agent -> bounded poll -> request succeeds."""
    pipe_name = make_unique_name()
    holders: list[tuple[OpenPipeServer, threading.Thread]] = []

    def fake_spawn() -> bool:
        holders.append(start_server(
            lambda path: {"ok": True, "changed": True, "re_encrypted": True},
            name=pipe_name))
        return True  # the fake agent is now listening on the launcher's pipe

    monkeypatch.setattr(launcher, "spawn_agent", fake_spawn)
    try:
        rc = launcher.main([r"S:\b.docx.cbx", "--pipe", pipe_name], spawn_wait_s=5.0)
    finally:
        if holders:
            holders[0][0].stop()
            holders[0][1].join(timeout=5)

    assert rc == 0


def test_spawn_failure_is_loud(monkeypatch, capsys):
    monkeypatch.setattr(launcher, "spawn_agent", lambda: False)
    rc = launcher.main([r"S:\c.docx.cbx", "--pipe", make_unique_name()])
    assert rc == 3
    assert "cannot start" in capsys.readouterr().err


def test_agent_never_appears_fails_loudly(monkeypatch, capsys):
    monkeypatch.setattr(launcher, "spawn_agent", lambda: True)  # spawns nothing
    rc = launcher.main([r"S:\d.docx.cbx", "--pipe", make_unique_name()],
                       spawn_wait_s=0.2)
    assert rc == 3
    assert "did not become reachable" in capsys.readouterr().err
