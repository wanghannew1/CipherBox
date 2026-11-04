"""Crash-recovery cleanup of orphaned temp plaintext (plan todo 26).

Single synchronous entry point :func:`run_recovery` that the Agent calls at
startup BEFORE accepting any controlled-open request and BEFORE starting the
watcher (including its initial scan).  Strict order inside the run:

1. Replay ``<tmp_root>\\audit-queue\\`` (interceptor-dumped JSONL reports):
   each valid line supplements one ``action=encrypt`` audit event and appends
   one superseded-ledger entry; the file is deleted after successful replay,
   malformed files are quarantined + alerted.
2. Orphan session recovery: for every DPAPI session record (todo 14 format,
   ``%APPDATA%\\CipherBox\\sessions\\<uuid>.json``):
   a. integrity-check the temp plaintext (``PK\\x03\\x04`` magic + zip parse);
      corrupt -> kill orphan controlled GUI first, keep the original ``.cbx``,
      quarantine the temp, audit ``recovery_corrupt_temp``;
   b. consult the superseded ledger (plan L198): a recorded interceptor
      forced-save that superseded this session's ``.cbx`` -> quarantine the
      temp + audit ``encrypt_superseded``, never overwrite;
   c. temp sha256 != record ``orig_sha256`` -> mtime guard first (target
      ``.cbx`` mtime NEWER than record ``ts`` -> quarantine temp + audit
      ``encrypt_stale``, FORBID overwrite), else re-encrypt back to the
      session's own ``cbx_path`` with the CURRENT key via the todo-14
      re-encrypt callable (bypasses the todo-13 superseded rejection branch
      by construction); audit ``encrypt`` with key_version = current version;
   d. temp sha256 == ``orig_sha256`` -> no re-encrypt, clean up;
   e. delete the session record and the temp.
3. Stale session-directory sweep: UUID-named dirs under ``<tmp_root>`` with
   no matching session record are quarantined (+ ``recovery_orphan_dir``
   alert); the ``service`` and ``audit-queue`` subdirs are exempt.

``find_plaintext_office_files`` / :func:`scan_plaintext_leaks` keep the
``%TEMP%`` and profile backup/AutoRecovery scans as regression assertions.

Intercepted-report JSONL line schema (written by todo-17 interceptor when the
Agent was unreachable; conforming writer todo 17)::

    {"file_hash": "<64-hex plaintext sha256>", "key_version": 3,
     "source_path": "S:/dir/a.docx", "cbx_path": "S:/dir/a.docx.cbx",
     "ts": 1730000000.0}

All paths are injectable via :class:`RecoveryConfig`; defaults are the
documented production paths.  Windows-only (DPAPI, os.replace).  No sleeps.

Quarantine convention (plan L70): ``S:\\.cipherbox-quarantine\\``.
"""

# allow: SIZE_OK — todo 26 mandates a single agent/cleanup.py deliverable;
# the replay/recovery/sweep phases share RecoveryConfig+_Recovery state, the
# superseded ledger has exactly one caller today (extraction would be
# speculative), and the natural split targets (watcher.py, encryptor.py) are
# frozen by the task's MUST-NOT-MODIFY constraints.

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import uuid
import zipfile
from dataclasses import dataclass, field
from typing import Callable

if os.name != "nt":  # pragma: no cover - Windows-only agent
    raise ImportError("agent/cleanup.py is Windows-only")

from agent.container import OOXML_MAGIC
from agent.key_manager import KeyManager, KeyManagerError, dpapi_decrypt, dpapi_encrypt
from agent.opener import SESSION_DIR, SessionRecord, SessionStore

TMP_ROOT = r"S:\.cipherbox-tmp"
QUARANTINE_ROOT = r"S:\.cipherbox-quarantine"
EXEMPT_SESSION_SUBDIRS = frozenset({"service", "audit-queue"})
LEDGER_FILENAME = "superseded.json"

AuditFn = Callable[[str, str, int | None, bool, str | None], None]
ReEncryptFn = Callable[[str, str, str], None]
KillGuiFn = Callable[[str], int]
CurrentKeyFn = Callable[[], "tuple[str, int]"]

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


class CleanupError(Exception):
    """Recovery cannot proceed safely (ledger unreadable, no key source)."""


# ---------------------------------------------------------------------------
# Superseded ledger (plan L198: %APPDATA%\CipherBox\superseded.json, DPAPI)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SupersededEntry:
    source_path: str
    cbx_path: str
    sha256: str
    key_version: int | None
    ts: float


class SupersededLedger:
    """Persistent "interceptor forced-save superseded this plaintext" list.

    Entries are appended when the audit-queue replay registers interceptor
    reports; an entry is pruned when its ``source_path`` is deleted or
    quarantined (plan L198 prune rule).  DPAPI-encrypted at rest.
    """

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path

    def load(self) -> list[SupersededEntry]:
        if not os.path.exists(self.file_path):
            return []
        try:
            with open(self.file_path, "rb") as fh:
                blob = dpapi_decrypt(fh.read())
            payload = json.loads(blob.decode("utf-8"))
            return [
                SupersededEntry(
                    source_path=str(item["source_path"]),
                    cbx_path=str(item["cbx_path"]),
                    sha256=str(item["sha256"]),
                    key_version=item.get("key_version"),
                    ts=float(item.get("ts", 0.0)),
                )
                for item in payload
            ]
        except (KeyManagerError, OSError, json.JSONDecodeError,
                KeyError, TypeError, ValueError, UnicodeDecodeError) as exc:
            raise CleanupError(
                f"superseded ledger unreadable at {self.file_path}: {exc}"
            ) from exc

    def add(self, entry: SupersededEntry) -> None:
        entries = self.load()
        entries.append(entry)
        self._save(entries)

    def matches_session(self, cbx_path: str, tmp_path: str) -> list[SupersededEntry]:
        """Entries superseding this session's .cbx or its temp plaintext path."""
        cbx_n = os.path.normcase(cbx_path)
        tmp_n = os.path.normcase(tmp_path)
        return [
            e for e in self.load()
            if os.path.normcase(e.cbx_path) == cbx_n
            or os.path.normcase(e.source_path) == tmp_n
        ]

    def prune_source(self, source_path: str) -> int:
        target = os.path.normcase(source_path)
        entries = self.load()
        kept = [e for e in entries if os.path.normcase(e.source_path) != target]
        removed = len(entries) - len(kept)
        if removed:
            self._save(kept)
        return removed

    def prune_prefix(self, dir_path: str) -> int:
        prefix = os.path.normcase(os.path.join(dir_path, ""))
        entries = self.load()
        kept = [e for e in entries if not os.path.normcase(e.source_path).startswith(prefix)]
        removed = len(entries) - len(kept)
        if removed:
            self._save(kept)
        return removed

    def _save(self, entries: list[SupersededEntry]) -> None:
        parent = os.path.dirname(self.file_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        payload = [
            {
                "source_path": e.source_path,
                "cbx_path": e.cbx_path,
                "sha256": e.sha256,
                "key_version": e.key_version,
                "ts": e.ts,
            }
            for e in entries
        ]
        blob = json.dumps(payload, sort_keys=True).encode("utf-8")
        with open(self.file_path, "wb") as fh:
            fh.write(dpapi_encrypt(blob))


# ---------------------------------------------------------------------------
# Config / report
# ---------------------------------------------------------------------------

@dataclass
class RecoveryConfig:
    """All paths injectable; defaults are the documented production paths."""

    tmp_root: str = TMP_ROOT
    sessions_dir: str = SESSION_DIR
    quarantine_dir: str = QUARANTINE_ROOT
    appdata_dir: str = os.path.expandvars(r"%APPDATA%\CipherBox")
    audit_queue_dir: str | None = None  # default: <tmp_root>\audit-queue
    ledger_file: str | None = None  # default: <appdata_dir>\superseded.json
    temp_dir: str = field(default_factory=lambda: os.path.expandvars(r"%TEMP%"))
    profile_scan_dirs: "tuple[str, ...]" = field(default_factory=lambda: (
        r"S:\.cipherbox-profile\controlled\backup",
        r"S:\.cipherbox-profile\service\backup",
    ))
    stale_dir_seconds: float = 0.0  # sweep dirs at least this old; 0 = all
    audit_reporter: AuditFn | None = None
    re_encrypt: ReEncryptFn | None = None  # (tmp_path, cbx_path, password)
    get_current_key: CurrentKeyFn | None = None
    key_manager: KeyManager | None = None
    kill_orphan_gui: KillGuiFn | None = None  # (tmp_path) -> killed count

    def __post_init__(self) -> None:
        if self.audit_queue_dir is None:
            self.audit_queue_dir = os.path.join(self.tmp_root, "audit-queue")
        if self.ledger_file is None:
            self.ledger_file = os.path.join(self.appdata_dir, LEDGER_FILENAME)


@dataclass
class RecoveryReport:
    queue_files_replayed: int = 0
    queue_events_replayed: int = 0
    queue_files_malformed: int = 0
    reencrypted: int = 0
    unchanged_cleaned: int = 0
    quarantined_corrupt: int = 0
    quarantined_superseded: int = 0
    quarantined_stale: int = 0
    record_only_removed: int = 0
    reencrypt_failed: int = 0
    dirs_swept: int = 0


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _temp_intact(path: str) -> bool:
    """OOXML ZIP magic + parseable central directory (container.OOXML_MAGIC)."""
    try:
        with open(path, "rb") as fh:
            if fh.read(len(OOXML_MAGIC)) != OOXML_MAGIC:
                return False
        return zipfile.is_zipfile(path)
    except OSError:
        return False


def _quarantine(path: str, quarantine_dir: str) -> str:
    """Move a temp file/dir into the quarantine dir; returns destination."""
    os.makedirs(quarantine_dir, exist_ok=True)
    dest = os.path.join(quarantine_dir, f"{uuid.uuid4().hex}-{os.path.basename(path)}")
    os.replace(path, dest)
    return dest


def _default_kill_orphan_gui(tmp_path: str) -> int:
    """Terminate soffice processes bound to this temp doc or controlled profile."""
    import psutil

    target = os.path.normcase(os.path.abspath(tmp_path))
    profile = os.path.normcase(r"S:\.cipherbox-profile\controlled")
    killed = 0
    for proc in psutil.process_iter(["name", "cmdline"]):
        try:
            name = (proc.info["name"] or "").lower()
            if name not in ("soffice.bin", "soffice.exe"):
                continue
            cmdline = os.path.normcase(" ".join(proc.info["cmdline"] or []))
            if target in cmdline or profile in cmdline:
                proc.kill()
                killed += 1
        except Exception:  # psutil: NoSuchProcess/AccessDenied/ZombieProcess
            continue  # process vanished or is protected; leave the rest
    return killed


def _sha256_file(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _remove_file(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def _remove_dir(path: str) -> None:
    try:
        os.rmdir(path)
    except OSError:
        pass


def _resolve_current_key(config: RecoveryConfig) -> "tuple[str, int]":
    """Current key + version: injected callable, else KeyManager (todo 11 rule)."""
    if config.get_current_key is not None:
        return config.get_current_key()
    if config.key_manager is not None:
        cached = config.key_manager.current_key()
        return cached.key, cached.version
    raise CleanupError("no key source configured (get_current_key / key_manager)")


def _parse_queue_line(line: str) -> SupersededEntry | None:
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None
    file_hash = obj.get("file_hash")
    source_path = obj.get("source_path")
    cbx_path = obj.get("cbx_path")
    if not isinstance(file_hash, str) or not _HEX64.fullmatch(file_hash):
        return None
    if not isinstance(source_path, str) or not source_path:
        return None
    if not isinstance(cbx_path, str) or not cbx_path:
        return None
    key_version = obj.get("key_version")
    ts = obj.get("ts")
    return SupersededEntry(
        source_path=source_path,
        cbx_path=cbx_path,
        sha256=file_hash,
        key_version=key_version if isinstance(key_version, int) else None,
        ts=float(ts) if isinstance(ts, (int, float)) else time.time(),
    )


def _is_uuid_dirname(name: str) -> bool:
    try:
        return str(uuid.UUID(name)).lower() == name.lower()
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# recovery pipeline
# ---------------------------------------------------------------------------

class _Recovery:
    """Internal orchestrator: config + report + lazy current-key cache."""

    def __init__(self, config: RecoveryConfig, report: RecoveryReport) -> None:
        self.config = config
        self.report = report
        self.store = SessionStore(config.sessions_dir)
        self._key_cache: list[int] = []  # resolved current version (may be -1)

    def _audit(self, action: str, file_hash: str, ok: bool, error: str | None) -> None:
        if self.config.audit_reporter is None:
            return
        self.config.audit_reporter(action, file_hash, self._current_version(), ok, error)

    def _current_version(self) -> int | None:
        if not self._key_cache:
            try:
                _password, version = _resolve_current_key(self.config)
                self._key_cache.append(version)
            except CleanupError:
                self._key_cache.append(-1)
        version = self._key_cache[0]
        return None if version < 0 else version

    # -- phase 1: audit-queue replay (MUST run before orphan recovery) ----

    def replay_queue(self) -> None:
        queue_dir = self.config.audit_queue_dir
        if not queue_dir or not os.path.isdir(queue_dir):
            return
        ledger = SupersededLedger(self.config.ledger_file or "")
        for name in sorted(os.listdir(queue_dir)):
            path = os.path.join(queue_dir, name)
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    lines = fh.readlines()
            except OSError as exc:
                raise CleanupError(f"cannot read audit-queue file {path}: {exc}") from exc
            entries: list[SupersededEntry] = []
            for line in lines:
                stripped = line.strip()
                if not stripped:
                    continue
                entry = _parse_queue_line(stripped)
                if entry is None:
                    entries = []
                    break
                entries.append(entry)
            if not entries and any(line.strip() for line in lines):
                # Malformed content: preserve evidence, alert, keep queue clean.
                _quarantine(path, self.config.quarantine_dir)
                self.report.queue_files_malformed += 1
                self._audit(
                    "recovery_queue_malformed", "0" * 64, False,
                    f"unparseable audit-queue file quarantined: {name}",
                )
                continue
            for entry in entries:
                if self.config.audit_reporter is not None:
                    self.config.audit_reporter(
                        "encrypt", entry.sha256, entry.key_version, True, None
                    )
                ledger.add(entry)
                self.report.queue_events_replayed += 1
            os.remove(path)
            self.report.queue_files_replayed += 1

    # -- phase 2: orphan session recovery ---------------------------------

    def recover_sessions(self) -> None:
        for rec in self.store.list_orphans():
            self._recover_one(rec)

    def _recover_one(self, rec: SessionRecord) -> None:
        tmp_path = rec.tmp_path
        if not os.path.exists(tmp_path):
            self.store.delete(rec.session_id)
            _remove_dir(os.path.dirname(tmp_path))
            self.report.record_only_removed += 1
            return

        # Kill any lingering controlled GUI FIRST, for every branch: a live
        # soffice holding the temp would (a) break the deletes below on
        # Windows (sharing violation -> record deleted, plaintext stranded),
        # and (b) keep referencing the temp after cleanup ("file not found").
        self._kill_orphans(tmp_path)

        try:
            current_hash = _sha256_file(tmp_path)
        except OSError:
            current_hash = "0" * 64  # unreadable temp == integrity failure
        ledger = SupersededLedger(self.config.ledger_file or "")

        # a. integrity: corrupt -> keep .cbx, quarantine.
        if not _temp_intact(tmp_path):
            _quarantine(tmp_path, self.config.quarantine_dir)
            _remove_dir(os.path.dirname(tmp_path))
            ledger.prune_source(tmp_path)
            self._audit(
                "recovery_corrupt_temp", current_hash, False,
                f"temp plaintext failed OOXML integrity check; session {rec.session_id}",
            )
            self.store.delete(rec.session_id)
            self.report.quarantined_corrupt += 1
            return

        # b. superseded ledger: interceptor already updated this .cbx.
        if ledger.matches_session(rec.cbx_path, tmp_path):
            _quarantine(tmp_path, self.config.quarantine_dir)
            _remove_dir(os.path.dirname(tmp_path))
            ledger.prune_source(tmp_path)
            self._audit(
                "encrypt_superseded", current_hash, False,
                f"temp superseded by interceptor forced-save of {rec.cbx_path}",
            )
            self.store.delete(rec.session_id)
            self.report.quarantined_superseded += 1
            return

        # d. unchanged temp: no re-encrypt, clean up.
        if current_hash == rec.orig_sha256:
            _remove_file(tmp_path)
            _remove_dir(os.path.dirname(tmp_path))
            self.store.delete(rec.session_id)
            self.report.unchanged_cleaned += 1
            return

        # c. changed temp: mtime guard BEFORE any overwrite.
        if self._target_is_newer(rec):
            _quarantine(tmp_path, self.config.quarantine_dir)
            _remove_dir(os.path.dirname(tmp_path))
            ledger.prune_source(tmp_path)
            self._audit(
                "encrypt_stale", current_hash, False,
                f"target .cbx newer than session ts; overwrite forbidden "
                f"(session {rec.session_id})",
            )
            self.store.delete(rec.session_id)
            self.report.quarantined_stale += 1
            return

        self._re_encrypt_changed(rec, current_hash)

    def _target_is_newer(self, rec: SessionRecord) -> bool:
        """True when target .cbx mtime is strictly NEWER than record ts."""
        if not os.path.exists(rec.cbx_path):
            return False
        try:
            return os.path.getmtime(rec.cbx_path) > rec.ts
        except OSError:
            return False  # .cbx vanished mid-check: recreate via re-encrypt

    def _re_encrypt_changed(self, rec: SessionRecord, current_hash: str) -> None:
        """Todo-14 style re-encrypt to the session's OWN cbx_path (no superseded
        rejection branch).  On failure keep temp + record for the next boot."""
        try:
            password, _version = _resolve_current_key(self.config)
        except (CleanupError, KeyManagerError) as exc:
            # KeyManagerError: ensure_keys not yet run (offline boot) — keep
            # temp + record so the next startup (with keys) retries.
            self._audit("encrypt", current_hash, False, str(exc))
            self.report.reencrypt_failed += 1
            return
        if self.config.re_encrypt is None:
            self._audit(
                "encrypt", current_hash, False,
                "no re_encrypt callable configured; temp kept for next boot",
            )
            self.report.reencrypt_failed += 1
            return
        try:
            # Third-party UNO callback: any failure mode -> audit + retain data.
            self.config.re_encrypt(rec.tmp_path, rec.cbx_path, password)
        except Exception as exc:
            self._audit(
                "encrypt", current_hash, False,
                f"re-encrypt to {rec.cbx_path} failed: {exc}",
            )
            self.report.reencrypt_failed += 1
            return
        self._audit("encrypt", current_hash, True, None)
        _remove_file(rec.tmp_path)
        _remove_dir(os.path.dirname(rec.tmp_path))
        self.store.delete(rec.session_id)
        self.report.reencrypted += 1

    def _kill_orphans(self, tmp_path: str) -> int:
        kill = self.config.kill_orphan_gui or _default_kill_orphan_gui
        return kill(tmp_path)

    # -- phase 3: stale session-directory sweep ---------------------------

    def sweep_dirs(self) -> None:
        tmp_root = self.config.tmp_root
        if not os.path.isdir(tmp_root):
            return
        ledger = SupersededLedger(self.config.ledger_file or "")
        for name in sorted(os.listdir(tmp_root)):
            full = os.path.join(tmp_root, name)
            if not os.path.isdir(full):
                continue
            if name.lower() in EXEMPT_SESSION_SUBDIRS:
                continue
            if not _is_uuid_dirname(name):
                continue
            # A record file that exists but fails DPAPI still protects its dir.
            if os.path.exists(os.path.join(self.config.sessions_dir, f"{name}.json")):
                continue
            if self.config.stale_dir_seconds > 0:
                try:
                    age = time.time() - os.path.getmtime(full)
                except OSError:
                    age = float("inf")
                if age < self.config.stale_dir_seconds:
                    continue
            _quarantine(full, self.config.quarantine_dir)
            ledger.prune_prefix(full)
            self._audit(
                "recovery_orphan_dir", "0" * 64, False,
                f"session dir without session record swept: {full}",
            )
            self.report.dirs_swept += 1


def run_recovery(config: RecoveryConfig) -> RecoveryReport:
    """Single synchronous startup recovery entry point (todo 26).

    Strict order: audit-queue replay -> orphan session recovery -> stale
    session-dir sweep.  Raises :class:`CleanupError` when the superseded
    ledger is unreadable (fail-closed: recovery must not proceed without it).
    """
    report = RecoveryReport()
    recovery = _Recovery(config, report)
    recovery.replay_queue()
    recovery.recover_sessions()
    recovery.sweep_dirs()
    return report


# ---------------------------------------------------------------------------
# plaintext-leak regression scans (%TEMP% + profile backup/AutoRecovery)
# ---------------------------------------------------------------------------

def find_plaintext_office_files(
    dirs: "list[str] | tuple[str, ...]",
    *,
    extensions: "tuple[str, ...]" = (".docx", ".xlsx", ".pptx"),
    extra_extensions: "tuple[str, ...]" = (),
) -> list[str]:
    """Files with an office/extra extension whose content is plaintext ZIP
    (``PK\\x03\\x04``).  Ciphertext ``.cbx`` (CFB magic) is never matched."""
    exts = {e.lower() for e in (*extensions, *extra_extensions)}
    hits: list[str] = []
    for root_dir in dirs:
        if not os.path.isdir(root_dir):
            continue
        for dirpath, _dirnames, filenames in os.walk(root_dir):
            for fname in filenames:
                if os.path.splitext(fname)[1].lower() not in exts:
                    continue
                fpath = os.path.join(dirpath, fname)
                try:
                    with open(fpath, "rb") as fh:
                        magic = fh.read(len(OOXML_MAGIC))
                except OSError:
                    continue
                if magic == OOXML_MAGIC:
                    hits.append(fpath)
    return hits


def scan_plaintext_leaks(config: RecoveryConfig) -> list[str]:
    """Regression assertion: %TEMP% + controlled/service profile backup dirs
    (LO backup/AutoRecovery location) must hold no plaintext office files."""
    return find_plaintext_office_files(
        (config.temp_dir, *config.profile_scan_dirs),
        extra_extensions=(".bak",),
    )
