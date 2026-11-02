"""Round-trip tests for agent/ipc.py: real named pipe + real threads.

Exercises the ctypes transport end to end (pywin32 is broken on this
workstation, so the ctypes path IS the production path): a real
``OpenPipeServer`` thread plus a real ``connect_and_request`` client.
Synchronization uses events only — no sleeps, no clock dependence.
"""

from __future__ import annotations

import threading
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


class TestConnectAndRequest:
    def test_absent_pipe_raises_typed_error(self):
        name = make_unique_name()  # never created
        with pytest.raises(PipeError) as excinfo:
            connect_and_request(name, {"cmd": "open", "path": "x"}, timeout_s=1.0)
        assert excinfo.value.pipe_absent
