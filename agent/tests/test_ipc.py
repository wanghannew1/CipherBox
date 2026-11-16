"""Round-trip tests for agent/ipc.py: real named pipe + real threads.

Exercises the ctypes transport end to end (pywin32 is broken on this
workstation, so the ctypes path IS the production path): a real
``OpenPipeServer`` thread plus a real ``connect_and_request`` client.
Synchronization uses events only — no sleeps, no clock dependence.
"""

from __future__ import annotations

import threading
import time
import uuid

import pytest

from agent.ipc import OpenPipeServer, PipeError, connect_and_request


def make_unique_name() -> str:
    return r"\\.\pipe\cipherbox-test-" + uuid.uuid4().hex


def start_server(handler) -> tuple[OpenPipeServer, threading.Thread]:
    server = OpenPipeServer(handler, make_unique_name())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    assert server.listening.wait(5), "server never started listening"
    return server, thread


def stop_server(server: OpenPipeServer, thread: threading.Thread) -> None:
    server.stop()
    thread.join(timeout=5)
    assert not thread.is_alive(), "server thread did not stop"


class TestOpenPipeServer:
    def test_open_request_round_trip(self):
        received: list[str] = []

        def handler(path: str) -> dict:
            received.append(path)
            return {"ok": True, "path": path}

        server, thread = start_server(handler)
        try:
            response = connect_and_request(
                server.pipe_name, {"cmd": "open", "path": r"S:\reports\a.docx.cbx"})
        finally:
            stop_server(server, thread)

        assert response == {"ok": True, "path": r"S:\reports\a.docx.cbx"}
        assert received == [r"S:\reports\a.docx.cbx"]

    def test_serves_requests_serially(self):
        requests: list[str] = []

        def handler(path: str) -> dict:
            requests.append(path)
            return {"ok": True, "n": len(requests)}

        server, thread = start_server(handler)
        try:
            first = connect_and_request(
                server.pipe_name, {"cmd": "open", "path": r"S:\one.cbx"})
            second = connect_and_request(
                server.pipe_name, {"cmd": "open", "path": r"S:\two.cbx"})
        finally:
            stop_server(server, thread)

        assert first == {"ok": True, "n": 1}
        assert second == {"ok": True, "n": 2}
        assert requests == [r"S:\one.cbx", r"S:\two.cbx"]

    def test_unknown_cmd_rejected(self):
        server, thread = start_server(lambda path: {"ok": True})
        try:
            response = connect_and_request(
                server.pipe_name, {"cmd": "delete", "path": r"S:\x.cbx"})
        finally:
            stop_server(server, thread)
        assert response["ok"] is False
        assert "cmd" in response["error"]

    def test_missing_path_rejected(self):
        server, thread = start_server(lambda path: {"ok": True})
        try:
            response = connect_and_request(server.pipe_name, {"cmd": "open"})
        finally:
            stop_server(server, thread)
        assert response == {"ok": False, "error": "missing 'path' in open request"}

    def test_handler_exception_becomes_error_response(self):
        def handler(path: str) -> dict:
            raise RuntimeError("boom")

        server, thread = start_server(handler)
        try:
            response = connect_and_request(
                server.pipe_name, {"cmd": "open", "path": r"S:\x.cbx"})
        finally:
            stop_server(server, thread)
        assert response["ok"] is False
        assert "boom" in response["error"]


class TestRouterCommands:
    """Dict-routed servers serve the link-worker channel (key/audit, todo 17)."""

    def _router_server(self, handlers: dict):
        server = OpenPipeServer(handlers, make_unique_name())
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        assert server.listening.wait(5), "server never started listening"
        return server, thread

    def test_key_command_round_trip(self):
        def handle_key(request: dict) -> dict:
            assert request == {"cmd": "key"}
            return {"ok": True, "key": "k3", "version": 3}

        server, thread = self._router_server({"key": handle_key})
        try:
            response = connect_and_request(server.pipe_name, {"cmd": "key"})
        finally:
            stop_server(server, thread)
        assert response == {"ok": True, "key": "k3", "version": 3}

    def test_audit_command_receives_full_request(self):
        received: list[dict] = []

        def handle_audit(request: dict) -> dict:
            received.append(request)
            return {"ok": True}

        server, thread = self._router_server({"audit": handle_audit})
        try:
            response = connect_and_request(server.pipe_name, {
                "cmd": "audit", "action": "encrypt",
                "file_hash": "ab" * 32, "key_version": None, "ok": True})
        finally:
            stop_server(server, thread)
        assert response == {"ok": True}
        assert received[0]["action"] == "encrypt"
        assert received[0]["ok"] is True

    def test_router_rejects_unlisted_cmd_and_lists_supported(self):
        server, thread = self._router_server({"key": lambda r: {"ok": True}})
        try:
            response = connect_and_request(server.pipe_name, {"cmd": "open"})
        finally:
            stop_server(server, thread)
        assert response["ok"] is False
        assert "key" in response["error"]

    def test_router_handler_exception_becomes_error_response(self):
        def handle_key(request: dict) -> dict:
            raise RuntimeError("no key")

        server, thread = self._router_server({"key": handle_key})
        try:
            response = connect_and_request(server.pipe_name, {"cmd": "key"})
        finally:
            stop_server(server, thread)
        assert response["ok"] is False
        assert "no key" in response["error"]


class TestStaleStandbyInstance:
    def test_stale_standby_survives_and_keeps_serving(self, monkeypatch):
        """A client that connects to the standby instance and hangs up before
        the server accepts it (launcher timeout during a long session) leaves
        the instance stale: ConnectNamedPipe fails with ERROR_NO_DATA (232).
        The server must discard the stale instance and keep serving."""
        import ctypes

        from agent import winpipe

        real_connect = winpipe.kernel32.ConnectNamedPipe
        state = {"calls": 0}

        def fake_connect(handle, overlapped_ref):
            state["calls"] += 1
            if state["calls"] == 1:
                ctypes.set_last_error(232)  # ERROR_NO_DATA: stale standby
                return 0
            return real_connect(handle, overlapped_ref)

        monkeypatch.setattr(winpipe.kernel32, "ConnectNamedPipe", fake_connect)

        received: list[str] = []

        def handler(path: str) -> dict:
            received.append(path)
            return {"ok": True, "path": path}

        server, thread = start_server(handler)

        def request_with_race_retry() -> dict:
            # The first client open can land on the instance the fake makes
            # stale (discarded before the replacement exists) — that race is
            # the scenario under test, so the request retries until the
            # rebuilt instance answers (bounded).
            deadline = time.monotonic() + 5.0
            while True:
                try:
                    return connect_and_request(
                        server.pipe_name, {"cmd": "open", "path": r"S:\x.cbx"})
                except PipeError:
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(0.01)

        try:
            response = request_with_race_retry()
        finally:
            stop_server(server, thread)

        assert state["calls"] >= 1, "stale path never exercised"
        assert response == {"ok": True, "path": r"S:\x.cbx"}
        assert received == [r"S:\x.cbx"]


class TestConnectAndRequest:
    def test_absent_pipe_raises_typed_error(self):
        name = make_unique_name()  # never created
        with pytest.raises(PipeError) as excinfo:
            connect_and_request(name, {"cmd": "open", "path": "x"}, timeout_s=1.0)
        assert excinfo.value.pipe_absent
