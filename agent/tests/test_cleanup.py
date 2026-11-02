"""Tests for agent/cleanup.py (todo 26): crash-recovery of orphan temp plaintext.

All paths injected via RecoveryConfig; DPAPI runs unmocked (real Windows);
no soffice, no S: volume, no sleeps (mtimes driven via os.utime).
"""

from __future__ import annotations

import hashlib
import io
import os
import time
import uuid
import zipfile
from pathlib import Path

import psutil
import pytest

from agent.cleanup import (
    CleanupError,
    RecoveryConfig,
    RecoveryReport,
    SupersededEntry,
    SupersededLedger,
    _default_kill_orphan_gui,
    find_plaintext_office_files,
    run_recovery,
    scan_plaintext_leaks,
)
from agent.opener import SessionRecord, SessionStore

PASSWORD_V9 = "current-master-key-v9"
CURRENT_VERSION = 9
OOXML_MAGIC = b"PK\x03\x04"
CFB_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def _zip_bytes(marker: bytes) -> bytes:
    """A minimal parseable OOXML-style ZIP carrying the marker."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("word/document.xml", marker.decode("latin-1"))
    return buf.getvalue()


ORIG = _zip_bytes(b"original-plaintext-AA")
CHANGED = _zip_bytes(b"edited-plaintext-BB")


# ---------------------------------------------------------------------------
# fakes + fixtures
# ---------------------------------------------------------------------------

class AuditRecorder:
    """Collects (action, file_hash, key_version, ok, error) tuples."""

    def __init__(self) -> None:
        self.events: list[tuple] = []

    def __call__(self, action, file_hash, key_version, ok, error) -> None:
        self.events.append((action, file_hash, key_version, ok, error))

    def first(self, action: str) -> tuple:
        return next(e for e in self.events if e[0] == action)


@pytest.fixture
def cfg(tmp_path: Path) -> RecoveryConfig:
    return RecoveryConfig(
        tmp_root=str(tmp_path / "tmp"),
        sessions_dir=str(tmp_path / "appdata" / "sessions"),
        quarantine_dir=str(tmp_path / "quarantine"),
        appdata_dir=str(tmp_path / "appdata"),
        temp_dir=str(tmp_path / "usertemp"),
        profile_scan_dirs=(
            str(tmp_path / "profiles" / "controlled" / "backup"),
            str(tmp_path / "profiles" / "service" / "backup"),
        ),
        stale_dir_seconds=0.0,
    )


@pytest.fixture
def recorder() -> AuditRecorder:
    return AuditRecorder()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write(path: str, data: bytes) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def make_session(
    cfg: RecoveryConfig,
    store: SessionStore,
    *,
    sid: str | None = None,
    orig: bytes = ORIG,
    current: bytes | None = None,
    cbx_bytes: bytes | None = b"OLD-CBX-CONTENT",
    ts: float = 1000.0,
) -> SessionRecord:
    """Create one orphan session record + temp file + target .cbx.

    ``current`` overrides the temp content (simulating edits after open).
    The .cbx is backdated below ``ts`` so the mtime guard passes by default.
    """
    sid = sid or str(uuid.uuid4())
    session_dir = os.path.join(cfg.tmp_root, sid)
    tmp_path = os.path.join(session_dir, "report.docx")
    _write(tmp_path, orig if current is None else current)
    cbx_path = os.path.join(os.path.dirname(cfg.tmp_root), "docs", f"{sid}.docx.cbx")
    if cbx_bytes is not None:
        _write(cbx_path, cbx_bytes)
        os.utime(cbx_path, (ts - 10.0, ts - 10.0))
    rec = SessionRecord(
        session_id=sid,
        cbx_path=cbx_path,
        tmp_path=tmp_path,
        orig_sha256=_sha(orig),
        key_version=3,
        ts=ts,
    )
    store.save(rec)
    return rec


class ReEncryptSpy:
    """Todo-14 style re-encrypt callback: records calls, writes new .cbx."""

    def __init__(self, fail: bool = False) -> None:
        self.calls: list[tuple[str, str, str]] = []
        self.fail = fail

    def __call__(self, tmp_path: str, cbx_path: str, password: str) -> None:
        self.calls.append((tmp_path, cbx_path, password))
        if self.fail:
            raise RuntimeError("UNO bridge dead")
        _write(cbx_path, b"NEW-CBX-CONTENT")


def wire(cfg: RecoveryConfig, recorder: AuditRecorder, **overrides) -> RecoveryConfig:
    cfg.audit_reporter = recorder
    cfg.get_current_key = lambda: (PASSWORD_V9, CURRENT_VERSION)
    for key, value in overrides.items():
        setattr(cfg, key, value)
    return cfg


def quarantine_entries(cfg: RecoveryConfig) -> list[str]:
    qdir = cfg.quarantine_dir
    if not os.path.isdir(qdir):
        return []
    return sorted(os.listdir(qdir))


# ---------------------------------------------------------------------------
# changed / unchanged temp
# ---------------------------------------------------------------------------

class TestChangedTemp:
    def test_changed_temp_reencrypted_and_cleaned(self, cfg, recorder):
        spy = ReEncryptSpy()
        store = SessionStore(cfg.sessions_dir)
        rec = make_session(cfg, store, orig=ORIG, current=CHANGED)
        wire(cfg, recorder, re_encrypt=spy)

        report = run_recovery(cfg)

        assert report.reencrypted == 1
        assert spy.calls == [(rec.tmp_path, rec.cbx_path, PASSWORD_V9)]
        with open(rec.cbx_path, "rb") as fh:
            assert fh.read() == b"NEW-CBX-CONTENT"
        assert not os.path.exists(rec.tmp_path)
        assert not os.path.exists(os.path.dirname(rec.tmp_path))  # session dir
        assert store.load(rec.session_id) is None  # record deleted
        # Re-encrypt audit carries the CURRENT key version (spec 3c).
        assert recorder.first("encrypt") == (
            "encrypt", _sha(CHANGED), CURRENT_VERSION, True, None,
        )

    def test_unchanged_temp_cleaned_without_reencrypt(self, cfg, recorder):
        spy = ReEncryptSpy()
        store = SessionStore(cfg.sessions_dir)
        rec = make_session(cfg, store, orig=ORIG)  # temp == orig
        wire(cfg, recorder, re_encrypt=spy)

        report = run_recovery(cfg)

        assert report.unchanged_cleaned == 1
        assert spy.calls == []  # no re-encrypt on unchanged temp
        with open(rec.cbx_path, "rb") as fh:
            assert fh.read() == b"OLD-CBX-CONTENT"  # .cbx untouched
        assert not os.path.exists(rec.tmp_path)
        assert store.load(rec.session_id) is None

    def test_unchanged_temp_missing_cbx_still_not_reencrypted(self, cfg, recorder):
        # Spec 3d is explicit: sha256 == orig -> no re-encrypt, even if .cbx gone.
        spy = ReEncryptSpy()
        store = SessionStore(cfg.sessions_dir)
        rec = make_session(cfg, store, orig=ORIG, cbx_bytes=None)
        wire(cfg, recorder, re_encrypt=spy)

        report = run_recovery(cfg)

        assert report.unchanged_cleaned == 1
        assert spy.calls == []
        assert not os.path.exists(rec.cbx_path)

    def test_reencrypt_failure_keeps_temp_and_record(self, cfg, recorder):
        spy = ReEncryptSpy(fail=True)
        store = SessionStore(cfg.sessions_dir)
        rec = make_session(cfg, store, orig=ORIG, current=CHANGED)
        wire(cfg, recorder, re_encrypt=spy)

        report = run_recovery(cfg)

        assert report.reencrypt_failed == 1
        assert os.path.exists(rec.tmp_path)  # retained for the next boot
        assert store.load(rec.session_id) is not None
        action, file_hash, key_version, ok, error = recorder.first("encrypt")
        assert (action, file_hash, key_version, ok) == (
            "encrypt", _sha(CHANGED), CURRENT_VERSION, False,
        )
        assert "UNO bridge dead" in error

    @pytest.mark.parametrize(
        "over, error_part, expected_kv",
        [
            ({"get_current_key": None, "key_manager": None}, "no key source", None),
            ({"re_encrypt": None}, "no re_encrypt callable", CURRENT_VERSION),
        ],
        ids=["no-key-source", "no-callback"],
    )
    def test_reencrypt_unavailable_keeps_temp(
        self, cfg, recorder, over, error_part, expected_kv,
    ):
        store = SessionStore(cfg.sessions_dir)
        rec = make_session(cfg, store, orig=ORIG, current=CHANGED)
        params = {"re_encrypt": ReEncryptSpy()}
        params.update(over)
        wire(cfg, recorder, **params)

        report = run_recovery(cfg)

        assert report.reencrypt_failed == 1
        assert os.path.exists(rec.tmp_path)
        action, _fh, key_version, ok, error = recorder.first("encrypt")
        assert (action, ok) == ("encrypt", False)
        assert key_version == expected_kv
        assert error_part in error



# ---------------------------------------------------------------------------
# mtime guard
# ---------------------------------------------------------------------------

class TestMtimeGuard:
    def test_target_cbx_newer_than_ts_quarantines_and_forbids_overwrite(
        self, cfg, recorder,
    ):
        spy = ReEncryptSpy()
        store = SessionStore(cfg.sessions_dir)
        rec = make_session(cfg, store, orig=ORIG, current=CHANGED, ts=1000.0)
        os.utime(rec.cbx_path, (1100.0, 1100.0))  # .cbx newer than session ts
        wire(cfg, recorder, re_encrypt=spy)

        report = run_recovery(cfg)

        assert report.quarantined_stale == 1
        assert spy.calls == []  # overwrite forbidden
        with open(rec.cbx_path, "rb") as fh:
            assert fh.read() == b"OLD-CBX-CONTENT"  # .cbx untouched
        assert not os.path.exists(rec.tmp_path)
        entries = quarantine_entries(cfg)
        assert len(entries) == 1 and entries[0].endswith("report.docx")
        action, file_hash, key_version, ok, _error = recorder.first("encrypt_stale")
        assert (action, file_hash, ok) == ("encrypt_stale", _sha(CHANGED), False)
        assert key_version == CURRENT_VERSION

    def test_target_cbx_older_than_ts_allows_reencrypt(self, cfg, recorder):
        spy = ReEncryptSpy()
        store = SessionStore(cfg.sessions_dir)
        rec = make_session(cfg, store, orig=ORIG, current=CHANGED, ts=1000.0)
        os.utime(rec.cbx_path, (500.0, 500.0))  # older -> guard passes
        wire(cfg, recorder, re_encrypt=spy)

        report = run_recovery(cfg)

        assert report.reencrypted == 1
        assert len(spy.calls) == 1


# ---------------------------------------------------------------------------
# corrupt temp
# ---------------------------------------------------------------------------

class TestCorruptTemp:
    def test_corrupt_temp_kills_gui_quarantines_preserves_cbx(self, cfg, recorder):
        killed: list[tuple[str, bool]] = []

        def fake_kill(tmp_path: str) -> int:
            # GUI must be killed BEFORE the temp is quarantined away.
            killed.append((tmp_path, os.path.exists(tmp_path)))
            return 1

        spy = ReEncryptSpy()
        store = SessionStore(cfg.sessions_dir)
        rec = make_session(cfg, store, orig=ORIG, current=b"garbage not a zip")
        wire(cfg, recorder, re_encrypt=spy, kill_orphan_gui=fake_kill)

        report = run_recovery(cfg)

        assert report.quarantined_corrupt == 1
        assert killed == [(rec.tmp_path, True)]  # killed first, temp still there
        with open(rec.cbx_path, "rb") as fh:
            assert fh.read() == b"OLD-CBX-CONTENT"  # original .cbx preserved
        assert not os.path.exists(rec.tmp_path)
        entries = quarantine_entries(cfg)
        assert len(entries) == 1 and entries[0].endswith("report.docx")
        action, file_hash, key_version, ok, _error = recorder.first(
            "recovery_corrupt_temp")
        assert (action, file_hash, key_version, ok) == (
            "recovery_corrupt_temp", _sha(b"garbage not a zip"),
            CURRENT_VERSION, False,
        )
        assert spy.calls == []

    def test_valid_zip_prefix_but_unparseable_is_corrupt(self, cfg, recorder):
        store = SessionStore(cfg.sessions_dir)
        rec = make_session(cfg, store, orig=ORIG, current=OOXML_MAGIC + b"trunc")
        wire(cfg, recorder, kill_orphan_gui=lambda _p: 0)

        report = run_recovery(cfg)

        assert report.quarantined_corrupt == 1
        assert len(quarantine_entries(cfg)) == 1

    def test_valid_zip_temp_passes_integrity(self, cfg, recorder):
        store = SessionStore(cfg.sessions_dir)
        content = _zip_bytes(b"word/document.xml body")
        rec = make_session(
            cfg, store, sid=str(uuid.uuid4()), orig=content, current=content)
        wire(cfg, recorder, re_encrypt=ReEncryptSpy())

        report = run_recovery(cfg)

        assert report.unchanged_cleaned == 1
        assert report.quarantined_corrupt == 0


# ---------------------------------------------------------------------------
# superseded ledger
# ---------------------------------------------------------------------------

class TestSupersededLedger:
    def test_ledger_hit_quarantines_without_overwrite(self, cfg, recorder):
        spy = ReEncryptSpy()
        store = SessionStore(cfg.sessions_dir)
        rec = make_session(cfg, store, orig=ORIG, current=CHANGED)
        ledger = SupersededLedger(cfg.ledger_file)
        ledger.add(SupersededEntry(
            source_path=rec.tmp_path,
            cbx_path=rec.cbx_path,
            sha256=_sha(b"newer-interceptor-content"),
            key_version=5,
            ts=1234.5,
        ))
        wire(cfg, recorder, re_encrypt=spy)

        report = run_recovery(cfg)

        assert report.quarantined_superseded == 1
        assert spy.calls == []  # never overwrite the interceptor's newer .cbx
        with open(rec.cbx_path, "rb") as fh:
            assert fh.read() == b"OLD-CBX-CONTENT"
        entries = quarantine_entries(cfg)
        assert len(entries) == 1 and entries[0].endswith("report.docx")
        action, file_hash, key_version, ok, _error = recorder.first(
            "encrypt_superseded")
        assert (action, file_hash, ok) == (
            "encrypt_superseded", _sha(CHANGED), False,
        )
        assert key_version == CURRENT_VERSION
        # Prune rule (plan L198): entry cleared once source_path is quarantined.
        assert ledger.load() == []

    def test_ledger_roundtrip_and_prune(self, cfg):
        ledger = SupersededLedger(cfg.ledger_file)
        entry = SupersededEntry(
            source_path=r"S:\docs\a.docx", cbx_path=r"S:\docs\a.docx.cbx",
            sha256="a" * 64, key_version=2, ts=42.0,
        )
        ledger.add(entry)

        reloaded = SupersededLedger(ledger.file_path)
        assert reloaded.load() == [entry]  # DPAPI persistence across instances

        assert reloaded.prune_source(r"s:\DOCS\A.DOCX") == 1  # case-folded
        assert reloaded.load() == []
        assert reloaded.prune_source(r"S:\docs\a.docx") == 0

    def test_ledger_prefix_prune_for_swept_dirs(self, cfg):
        ledger = SupersededLedger(cfg.ledger_file)
        sdir = os.path.join(cfg.tmp_root, str(uuid.uuid4()))
        ledger.add(SupersededEntry(
            source_path=os.path.join(sdir, "a.docx"),
            cbx_path=r"S:\docs\a.docx.cbx", sha256="b" * 64, key_version=1, ts=1.0,
        ))
        ledger.add(SupersededEntry(
            source_path=r"S:\docs\other.docx",
            cbx_path=r"S:\docs\other.docx.cbx", sha256="c" * 64, key_version=1, ts=1.0,
        ))

        removed = ledger.prune_prefix(sdir)

        assert removed == 1
        assert [e.source_path for e in ledger.load()] == [r"S:\docs\other.docx"]

    def test_unreadable_ledger_fails_closed(self, cfg, recorder):
        _write(cfg.ledger_file, b"not-dpapi-blob")
        store = SessionStore(cfg.sessions_dir)
        make_session(cfg, store, orig=ORIG, current=CHANGED)
        wire(cfg, recorder, re_encrypt=ReEncryptSpy())

        with pytest.raises(CleanupError, match="superseded ledger unreadable"):
            run_recovery(cfg)


# ---------------------------------------------------------------------------
# audit-queue replay (phase 1, before orphan recovery)
# ---------------------------------------------------------------------------

class TestQueueReplay:
    def test_queue_replayed_before_recovery_and_cleared(self, cfg, recorder):
        spy = ReEncryptSpy()
        store = SessionStore(cfg.sessions_dir)
        rec = make_session(cfg, store, orig=ORIG, current=CHANGED)
        # The queued interceptor report points at THIS session's .cbx: once
        # replayed it must block the recovery overwrite (replay ran first).
        line = (
            '{"file_hash": "%s", "key_version": 5, "source_path": "%s", '
            '"cbx_path": "%s", "ts": 123.0}'
            % (_sha(b"newer-content"),
               rec.tmp_path.replace("\\", "\\\\"),
               rec.cbx_path.replace("\\", "\\\\"))
        )
        queue_file = _write(
            os.path.join(cfg.audit_queue_dir, "events-001.jsonl"),
            (line + "\n").encode("utf-8"),
        )
        wire(cfg, recorder, re_encrypt=spy)

        report = run_recovery(cfg)

        assert report.queue_files_replayed == 1
        assert report.queue_events_replayed == 1
        assert not os.path.exists(queue_file)
        assert report.quarantined_superseded == 1
        assert spy.calls == []
        encrypt_event = ("encrypt", _sha(b"newer-content"), 5, True, None)
        assert encrypt_event in recorder.events
        assert recorder.events.index(encrypt_event) < recorder.events.index(
            recorder.first("encrypt_superseded"))

    def test_malformed_queue_file_quarantined_and_alerted(self, cfg, recorder):
        wire(cfg, recorder)
        bad = _write(
            os.path.join(cfg.audit_queue_dir, "broken.jsonl"),
            b'{"file_hash": "not-a-hash"}\n',
        )

        report = run_recovery(cfg)

        assert report.queue_files_malformed == 1
        assert not os.path.exists(bad)
        entries = quarantine_entries(cfg)
        assert len(entries) == 1 and entries[0].endswith("broken.jsonl")
        action, _fh, _kv, ok, error = recorder.first("recovery_queue_malformed")
        assert (action, ok) == ("recovery_queue_malformed", False)
        assert "broken.jsonl" in error

    def test_empty_or_missing_queue_is_noop(self, cfg, recorder):
        wire(cfg, recorder)
        report = run_recovery(cfg)
        assert report.queue_files_replayed == 0
        assert report.queue_events_replayed == 0


# ---------------------------------------------------------------------------
# stale session-directory sweep (phase 3)
# ---------------------------------------------------------------------------

class TestSweep:
    def test_sweep_exempts_named_dirs_quarantines_unknown_uuid_dirs(
        self, cfg, recorder,
    ):
        wire(cfg, recorder)
        service_file = _write(os.path.join(cfg.tmp_root, "service", "f.txt"), b"x")
        os.makedirs(os.path.join(cfg.tmp_root, "audit-queue"))
        orphan_tmp = _write(
            os.path.join(cfg.tmp_root, str(uuid.uuid4()), "leak.docx"),
            OOXML_MAGIC + b"orphan")
        _write(os.path.join(cfg.tmp_root, "spike-old", "keep.txt"), b"x")  # non-uuid
        # A dir whose record FILE exists (even DPAPI-unreadable) is protected.
        guarded_sid = str(uuid.uuid4())
        _write(os.path.join(cfg.tmp_root, guarded_sid, "held.docx"), b"x")
        _write(os.path.join(cfg.sessions_dir, f"{guarded_sid}.json"), b"garbage")

        report = run_recovery(cfg)

        assert report.dirs_swept == 1
        entries = quarantine_entries(cfg)
        assert len(entries) == 1
        assert os.path.exists(os.path.join(cfg.quarantine_dir, entries[0], "leak.docx"))
        assert not os.path.exists(os.path.dirname(orphan_tmp))  # swept dir gone
        assert os.path.exists(service_file)  # exempt
        assert os.path.isdir(os.path.join(cfg.tmp_root, "audit-queue"))  # exempt
        assert os.path.exists(os.path.join(cfg.tmp_root, "spike-old", "keep.txt"))
        assert os.path.exists(os.path.join(cfg.tmp_root, guarded_sid, "held.docx"))
        action, file_hash, _kv, ok, error = recorder.first("recovery_orphan_dir")
        assert (action, file_hash, ok) == ("recovery_orphan_dir", "0" * 64, False)
        assert os.path.dirname(orphan_tmp) in error

    def test_sweep_respects_staleness_threshold(self, cfg, recorder):
        wire(cfg, recorder, stale_dir_seconds=3600.0)
        fresh = _write(
            os.path.join(cfg.tmp_root, str(uuid.uuid4()), "new.docx"), b"x")
        stale_tmp = _write(
            os.path.join(cfg.tmp_root, str(uuid.uuid4()), "old.docx"), b"x")
        old = time.time() - 7200.0
        os.utime(os.path.dirname(stale_tmp), (old, old))  # backdate dir mtime

        report = run_recovery(cfg)

        assert report.dirs_swept == 1
        assert os.path.exists(fresh)  # too fresh, left for a later run
        assert len(quarantine_entries(cfg)) == 1

    def test_sweep_of_record_backed_dir_does_not_fire(self, cfg, recorder):
        # Unchanged session: phase 2 removes temp+dir+record, so phase 3 sees
        # nothing left to sweep.
        store = SessionStore(cfg.sessions_dir)
        make_session(cfg, store, orig=ORIG)
        wire(cfg, recorder, re_encrypt=ReEncryptSpy())

        report = run_recovery(cfg)

        assert report.unchanged_cleaned == 1
        assert report.dirs_swept == 0


# ---------------------------------------------------------------------------
# record-only cleanup + empty baseline
# ---------------------------------------------------------------------------

class TestRecordOnly:
    def test_missing_temp_removes_record_only(self, cfg, recorder):
        store = SessionStore(cfg.sessions_dir)
        rec = make_session(cfg, store, orig=ORIG)
        os.remove(rec.tmp_path)  # crash between temp-delete and record-delete
        wire(cfg, recorder)

        report = run_recovery(cfg)

        assert report.record_only_removed == 1
        assert store.load(rec.session_id) is None
        assert not os.path.exists(os.path.dirname(rec.tmp_path))

    def test_empty_state_zeroed_report(self, cfg, recorder):
        wire(cfg, recorder)
        report = run_recovery(cfg)
        assert report == RecoveryReport()


# ---------------------------------------------------------------------------
# plaintext-leak regression scans (%TEMP% + profile backup/AutoRecovery)
# ---------------------------------------------------------------------------

class TestPlaintextScan:
    def test_scan_temp_and_profile_backup_dirs(self, cfg):
        leak_temp = _write(
            os.path.join(cfg.temp_dir, "leak1.docx"), OOXML_MAGIC + b"zip")
        _write(os.path.join(cfg.temp_dir, "cipher.cbx"), CFB_MAGIC + b"cbf")
        _write(os.path.join(cfg.temp_dir, "notes.txt"), OOXML_MAGIC + b"zip")
        leak_backup = _write(
            os.path.join(cfg.profile_scan_dirs[0], "b.xlsx"), OOXML_MAGIC + b"zip")
        leak_bak = _write(
            os.path.join(cfg.profile_scan_dirs[1], "x.docx.bak"),
            OOXML_MAGIC + b"zip")
        _write(os.path.join(cfg.profile_scan_dirs[1], "safe.cbx"), CFB_MAGIC + b"cbf")

        hits = scan_plaintext_leaks(cfg)

        assert sorted(hits) == sorted([leak_temp, leak_backup, leak_bak])

    def test_find_plaintext_office_files_walks_recursively(self, tmp_path: Path):
        nested = _write(
            str(tmp_path / "sub" / "dir" / "deep.pptx"), OOXML_MAGIC + b"zip")
        assert find_plaintext_office_files([str(tmp_path)]) == [nested]

    def test_scan_missing_dirs_yield_no_hits(self, cfg):
        assert scan_plaintext_leaks(cfg) == []


# ---------------------------------------------------------------------------
# default kill helper (psutil enumeration logic, real processes untouched)
# ---------------------------------------------------------------------------

class TestDefaultKill:
    def test_default_kill_only_matches_soffice_cmdlines(self, monkeypatch):
        class FakeProc:
            def __init__(self, name, cmdline):
                self.info = {"name": name, "cmdline": cmdline}
                self.killed = False

            def kill(self):
                self.killed = True

        doc_tmp = r"S:\.cipherbox-tmp\u1\a.docx"
        procs = [
            FakeProc("soffice.bin", [r"C:\LO\soffice.bin", doc_tmp]),   # match
            FakeProc("soffice.bin", [r"C:\LO\soffice.bin", r"C:\x.docx"]),  # no
            FakeProc("winword.exe", [doc_tmp]),  # wrong process name
        ]
        monkeypatch.setattr(psutil, "process_iter", lambda _=None: procs)

        killed = _default_kill_orphan_gui(doc_tmp)

        assert killed == 1
        assert procs[0].killed and not procs[1].killed and not procs[2].killed
