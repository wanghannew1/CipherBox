"""Tests for agent/audit.py (todo 15): report envelope, local DPAPI queue, replay.

HTTP is injected via http_post callback; no real server needed.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from agent.audit import (
    AuditReporter,
    DEFAULT_CAPACITY,
    QUEUE_FILE,
    _dpapi_decrypt,
    _dpapi_encrypt,
)

TOKEN = "agent-token-123"
SERVER = "https://cipherbox.example:8443"


# ---------------------------------------------------------------------------
# DPAPI round-trip
# ---------------------------------------------------------------------------

@pytest.mark.skipif(os.name != "nt", reason="DPAPI is Windows-only")
class TestDpapi:
    def test_encrypt_decrypt_roundtrip(self):
        plain = b"audit queue payload"
        enc = _dpapi_encrypt(plain)
        assert enc != plain
        assert _dpapi_decrypt(enc) == plain


# ---------------------------------------------------------------------------
# AuditReporter report / flush
# ---------------------------------------------------------------------------

class TestReport:
    def _make(self, tmp_path: Path, *, http_post=None, capacity=DEFAULT_CAPACITY):
        qf = str(tmp_path / "audit-queue.json")
        return AuditReporter(
            server_url=SERVER,
            token=TOKEN,
            queue_file=qf,
            capacity=capacity,
            http_post=http_post,
        ), qf

    def test_report_sent_immediately(self, tmp_path: Path):
        sent = []

        def post(event, timeout, ca):
            sent.append(event)

            class R:
                status_code = 200

            return R()

        rep, _ = self._make(tmp_path, http_post=post)
        ok = rep.report("encrypt", "a" * 64, 1, True)
        assert ok is True
        assert len(sent) == 1
        assert sent[0]["action"] == "encrypt"
        assert sent[0]["machine"]  # hostname set
        assert sent[0]["meta"] is False
        assert rep._queue == []

    def test_report_failure_queues(self, tmp_path: Path):
        def post(event, timeout, ca):
            raise ConnectionError("down")

        rep, _ = self._make(tmp_path, http_post=post)
        ok = rep.report("encrypt", "a" * 64, 1, True)
        assert ok is False
        assert len(rep._queue) == 1
        assert rep._queue[0]["action"] == "encrypt"
        assert rep._queue[0]["ok"] is True

    def test_flush_replays_queued(self, tmp_path: Path):
        sent = []

        def post(event, timeout, ca):
            sent.append(event)

            class R:
                status_code = 200

            return R()

        rep, _ = self._make(tmp_path, http_post=post)
        rep._enqueue(
            {"action": "encrypt", "file_hash": "a" * 64, "key_version": 1,
             "machine": rep.machine, "ok": True, "ts": 1.0}
        )
        rep._enqueue(
            {"action": "decrypt", "file_hash": "b" * 64, "key_version": 1,
             "machine": rep.machine, "ok": True, "ts": 2.0}
        )
        assert len(rep._queue) == 2
        n = rep.flush()
        assert n == 2
        assert len(rep._queue) == 0
        assert len(sent) == 2

    def test_flush_partial_failure_keeps_remaining(self, tmp_path: Path):
        calls = {"n": 0}

        def post(event, timeout, ca):
            calls["n"] += 1
            if calls["n"] == 1:
                raise ConnectionError("down")

            class R:
                status_code = 200

            return R()

        rep, _ = self._make(tmp_path, http_post=post)
        rep._enqueue(
            {"action": "encrypt", "file_hash": "a" * 64, "key_version": 1,
             "machine": rep.machine, "ok": True, "ts": 1.0}
        )
        rep._enqueue(
            {"action": "decrypt", "file_hash": "b" * 64, "key_version": 1,
             "machine": rep.machine, "ok": True, "ts": 2.0}
        )
        n = rep.flush()
        assert n == 1
        assert len(rep._queue) == 1


# ---------------------------------------------------------------------------
# Queue capacity overflow -> meta event
# ---------------------------------------------------------------------------

class TestQueueCapacity:
    def test_overflow_drops_oldest_and_meta(self, tmp_path: Path):
        def post(event, timeout, ca):
            raise ConnectionError("down")

        qf = str(tmp_path / "audit-queue.json")
        rep = AuditReporter(
            server_url=SERVER, token=TOKEN, queue_file=qf,
            capacity=3, http_post=post,
        )
        for i in range(5):
            rep.report("encrypt", ("%064d" % i), i, True)

        assert len(rep._queue) <= 3 + 1
        real_hashes = [e["file_hash"] for e in rep._queue if not e.get("meta")]
        assert "%064d" % 0 not in real_hashes
        assert "%064d" % 1 not in real_hashes
        assert "%064d" % 4 in real_hashes
        metas = [e for e in rep._queue if e.get("meta")]
        assert len(metas) >= 1
        assert metas[0]["ok"] is False
        assert "dropped" in metas[0]["error"]


# ---------------------------------------------------------------------------
# Queue persistence (DPAPI file)
# ---------------------------------------------------------------------------

class TestQueuePersistence:
    def test_queue_survives_reload(self, tmp_path: Path):
        def post(event, timeout, ca):
            raise ConnectionError("down")

        qf = str(tmp_path / "audit-queue.json")
        rep1 = AuditReporter(server_url=SERVER, token=TOKEN, queue_file=qf,
                             http_post=post)
        rep1.report("encrypt", "a" * 64, 1, True)
        assert len(rep1._queue) == 1

        rep2 = AuditReporter(server_url=SERVER, token=TOKEN, queue_file=qf,
                             http_post=post)
        assert len(rep2._queue) == 1
        assert rep2._queue[0]["action"] == "encrypt"

    def test_queue_file_encrypted_not_plaintext(self, tmp_path: Path):
        def post(event, timeout, ca):
            raise ConnectionError("down")

        qf = str(tmp_path / "audit-queue.json")
        rep = AuditReporter(server_url=SERVER, token=TOKEN, queue_file=qf,
                            http_post=post)
        rep.report("encrypt", "a" * 64, 1, True)
        raw = open(qf, "rb").read()
        assert b"encrypt" not in raw
        assert len(raw) > 0
