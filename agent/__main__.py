"""CipherBox Agent composition root (plan todo 12-16 wiring; handoff gap #2).

Resident program: ``python -m agent``.  Startup order is plan-mandated
(todo 26): crash-recovery FIRST, then key ensure, then the watcher thread,
then the controlled-open named-pipe server — before any controlled open or
watcher encryption can run.

Controlled opens carry the todo-17 interceptor link: each session spawns a
link worker under LibreOffice's python (see :mod:`agent.session_link`) that
registers the forced-encrypt interceptor BEFORE the document loads.  The
worker fetches the current master key per forced save and reports interceptor
audits over the link pipe (``LINK_PIPE_NAME``); the key handler applies the
todo-11 rule (online refresh, cache fallback), the audit handler flows into
the resident :class:`AuditReporter`.

Components are the existing verified modules, wired here with their injected
callbacks; this file owns NO crypto/UNO/session logic of its own:

* :func:`build_runtime` — the composition seam; tests substitute fakes by
  constructing :class:`Runtime` directly.
* :func:`run_resident` — the ordered startup, then the pipe accept loop.
* :func:`once_startup` — ``--once`` mode (recovery + key ensure, then exit).

Nothing secret is ever printed: only counts, paths, and state.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import json
import os
import signal
import sys
import threading
from dataclasses import dataclass
from typing import Callable

from agent import make_console_prints_safe
from agent.audit import AuditReporter
from agent.cleanup import RecoveryConfig, RecoveryReport, run_recovery
from agent.config import AgentConfig, ConfigError, LoadedConfig, load_config
from agent.container import CbxContainer, ContainerError
from agent.controlled import LaunchError, launch_soffice, wait_document_close
from agent.encryptor import Encryptor
from agent.ipc import LINK_PIPE_NAME, PIPE_NAME, OpenPipeServer
from agent.key_manager import CachedKey, KeyManager, KeyManagerError
from agent.opener import CBX_SUFFIX, ControlledOpener, SessionStore, SingleInstanceMutex
from agent.session_link import LinkHandle, LinkSpec, queue_dir_for, spawn
from agent.uno_driver import UnoDriver
from agent.watcher import ProtectedFolderWatcher

AGENT_MUTEX_NAME = "Local\\CipherBoxAgentResident"
LINK_QUEUE_FILE = "link-audit.jsonl"


def default_recovery(rt: Runtime) -> RecoveryReport:
    """Wire RecoveryConfig to the composed agent (paths, audit, key, driver)."""
    cfg = rt.config
    volume_root = os.path.dirname(cfg.temp_root.rstrip("\\/")) or "."
    return run_recovery(RecoveryConfig(
        tmp_root=cfg.temp_root,
        sessions_dir=cfg.session_dir,
        quarantine_dir=os.path.join(volume_root, ".cipherbox-quarantine"),
        appdata_dir=os.path.dirname(cfg.keycache) or os.path.expandvars(r"%APPDATA%\CipherBox"),
        audit_reporter=rt.audit.report,
        key_manager=rt.key_manager,
        re_encrypt=lambda tmp_path, cbx_path, password:
            rt.uno_driver.encrypt_to_cbx(tmp_path, cbx_path, password),
    ))


@dataclass(frozen=True, slots=True)
class Runtime:
    """Fully composed agent; tests build this directly with recording fakes."""

    config: AgentConfig
    key_manager: KeyManager
    audit: AuditReporter
    uno_driver: UnoDriver
    watcher: ProtectedFolderWatcher | None
    pipe_server: OpenPipeServer
    recovery_runner: Callable[["Runtime"], RecoveryReport] = default_recovery
    link_pipe_server: OpenPipeServer | None = None  # key/audit for the link worker


# ---------------------------------------------------------------------------
# link-worker channel handlers (todo 17 ①: per-save key fetch + audit route)
# ---------------------------------------------------------------------------

def make_key_handler(key_manager: KeyManager) -> Callable[[dict], dict]:
    """Current master key for the interceptor's per-save fetch.

    Applies the todo-11 rule: online refresh first (server unreachable ->
    DPAPI cache fallback inside ``ensure_keys``), then the resident current
    key.  Failures raise; the pipe boundary turns them into
    ``{"ok": false}`` and the worker fail-closes the save.
    """

    def handle_key(_request: dict) -> dict:
        key_manager.ensure_keys(online=True)
        current = key_manager.current_key()
        return {"ok": True, "key": current.key, "version": current.version}

    return handle_key


def make_audit_handler(audit: AuditReporter) -> Callable[[dict], dict]:
    """Interceptor audit event -> resident AuditReporter (server/queue).

    Every link audit is echoed on the agent console: forced saves / plaintext
    exports are rare and security-relevant, and without this line a refused
    save is invisible to the operator.
    """

    def handle_audit(request: dict) -> dict:
        action = request.get("action")
        file_hash = request.get("file_hash")
        ok = request.get("ok")
        key_version = request.get("key_version")
        if not isinstance(action, str) or not action:
            return {"ok": False, "error": "audit event requires a non-empty action"}
        if not isinstance(file_hash, str) or not isinstance(ok, bool):
            return {"ok": False, "error": "audit event requires file_hash:str + ok:bool"}
        if key_version is not None and not isinstance(key_version, int):
            return {"ok": False, "error": "key_version must be int or null"}
        audit.report(action, file_hash, key_version, ok)
        prefix = f" {file_hash[:48]}" if file_hash else ""
        print(f"[agent] link audit: {action} ok={ok}{prefix}")
        return {"ok": True}

    return handle_audit


def replay_link_audit_queue(rt: Runtime) -> int:
    """Replay the volume-side fallback queue the link worker wrote while the
    agent was unreachable (todo 17 ①).  ``AuditReporter.report`` queues on
    server failure itself, so replaying the file then deleting it cannot lose
    events.  Returns the replayed count."""
    queue_dir = queue_dir_for(rt.config.temp_root)
    path = os.path.join(queue_dir, LINK_QUEUE_FILE)
    if not os.path.isfile(path):
        return 0
    count = 0
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            rt.audit.report(
                str(event.get("action") or ""),
                str(event.get("file_hash") or ""),
                event.get("key_version"),
                bool(event.get("ok", True)))
            count += 1
    try:
        os.remove(path)
    except OSError:
        pass
    return count


def make_interceptor_attacher(config: AgentConfig) -> Callable[[str, str], LinkHandle]:
    """Build the opener's ``attach_interceptor`` callback (one per session).

    Spawns the link worker (LibreOffice python), gates on its hard ordering
    — ``await_loaded`` returns only after interception is confirmed active
    and the document is loaded — and surfaces any :class:`LinkError` to the
    opener, which then aborts the session fail-closed.
    """
    spec_queue_dir = queue_dir_for(config.temp_root)

    def attach(pipe_name: str, doc_path: str) -> LinkHandle:
        print(f"[agent] link: registering interceptor for {os.path.basename(doc_path)}")
        handle = spawn(LinkSpec(
            soffice_pipe=pipe_name,
            doc_path=doc_path,
            agent_pipe=LINK_PIPE_NAME,
            queue_dir=spec_queue_dir))
        try:
            frames = handle.await_loaded()
        except Exception as exc:
            # The worker's error otherwise lands only in the launcher's
            # double-click cmd window, which closes before anyone can read
            # it.  Surface it on the persistent agent console; the opener
            # then aborts the session fail-closed as before.
            print(f"[agent] link FAILED: {exc}")
            raise
        print(f"[agent] link: interception active on {frames} frame(s), document loaded")
        return handle

    return attach


@dataclass(frozen=True, slots=True)
class OpenDeps:
    """The four composed services one controlled-open session needs."""

    config: AgentConfig
    key_manager: KeyManager
    uno_driver: UnoDriver
    audit: AuditReporter


def make_open_handler(deps: OpenDeps) -> Callable[[str], dict]:
    """One accepted open request -> controlled-open session (opener's flow)."""

    def handle_open(cbx_path: str) -> dict:
        target = os.path.abspath(cbx_path)
        if not target.lower().endswith(CBX_SUFFIX):
            return {"ok": False, "error": f"not a .cbx file: {target}"}
        if not os.path.isfile(target):
            return {"ok": False, "error": f"file not found: {target}"}
        try:
            with SingleInstanceMutex() as mutex:
                if not mutex.acquired():
                    return {"ok": False, "error": "busy: another controlled session is active"}
                return _run_controlled_open(target, deps)
        except KeyManagerError as exc:
            return {"ok": False, "error": f"keys unavailable: {exc}"}
        except ContainerError as exc:
            return {"ok": False, "error": f"container error: {exc}"}
        except LaunchError as exc:
            return {"ok": False, "error": str(exc)}
        except Exception as exc:  # boundary: session failure -> JSON response
            return {"ok": False, "error": f"open failed: {exc}"}

    return handle_open


def _run_controlled_open(target: str, deps: OpenDeps) -> dict:
    key_set = deps.key_manager.ensure_keys(online=True)  # refresh before decrypt (todo 11)
    opener = ControlledOpener(
        container=CbxContainer.from_file(target),
        passwords=[cached.key for cached in key_set],  # current first, then older
        key_version=deps.key_manager.current_key().version,
        session_store=SessionStore(deps.config.session_dir),
        tmp_root=deps.config.temp_root,
        launch_soffice=launch_soffice,
        attach_interceptor=make_interceptor_attacher(deps.config),
        wait_document_close=wait_document_close,
        re_encrypt=lambda tmp_path, cbx_path, password:
            deps.uno_driver.encrypt_to_cbx(tmp_path, cbx_path, password),
        audit=deps.audit.report,
    )
    result = opener.open_controlled(target)
    print(f"[agent] open: {target} changed={result.changed} re_encrypted={result.re_encrypted}")
    return {"ok": True, "changed": result.changed, "re_encrypted": result.re_encrypted}


def build_runtime(loaded: LoadedConfig, *, with_watcher: bool, pipe_name: str = PIPE_NAME) -> Runtime:
    """Compose the verified modules into a runnable agent (no side effects)."""
    cfg, token = loaded.config, loaded.token
    key_manager = KeyManager(
        cfg.server_url, token, cache_file=cfg.keycache, ca_bundle=cfg.ca_bundle)
    audit = AuditReporter(
        server_url=cfg.server_url, token=token, queue_file=cfg.audit_queue,
        ca_bundle=cfg.ca_bundle)
    uno_driver = UnoDriver()

    watcher = None
    if with_watcher:
        def encrypt_func(plain_path: str, password: str) -> bytes:
            # Adapter: the driver already writes <plain>.cbx atomically; the
            # Encryptor pipeline re-writes it through its own .cbx.tmp rename.
            cbx = os.path.abspath(plain_path) + CBX_SUFFIX
            print(f"[agent] encrypting: {plain_path}")
            try:
                uno_driver.encrypt_to_cbx(plain_path, cbx, password)
            except Exception as exc:
                # Surface the failure on the console: the retry loop inside
                # Encryptor only lands the final error in the audit event,
                # and the server drops the detail text — without this print
                # the operator sees N silent "encrypting" lines and nothing else.
                print(f"[agent] encrypt FAILED: {exc}")
                raise
            with open(cbx, "rb") as fh:
                data = fh.read()
            print(f"[agent] encrypted: {cbx} ({len(data)} bytes)")
            return data

        encryptor = Encryptor(
            encrypt_func=encrypt_func,
            audit_reporter=audit.report,
            get_password=lambda: key_manager.current_key().key,
            get_key_version=lambda: key_manager.current_key().version,
        )
        watcher = ProtectedFolderWatcher(
            cfg.protected_dir, on_candidate=encryptor.encrypt_file)

    pipe_server = OpenPipeServer(
        make_open_handler(OpenDeps(
            config=cfg, key_manager=key_manager, uno_driver=uno_driver, audit=audit)),
        pipe_name)
    link_pipe_server = OpenPipeServer({
        "key": make_key_handler(key_manager),
        "audit": make_audit_handler(audit),
    }, LINK_PIPE_NAME)
    return Runtime(
        config=cfg, key_manager=key_manager, audit=audit, uno_driver=uno_driver,
        watcher=watcher, pipe_server=pipe_server, link_pipe_server=link_pipe_server)


def run_resident(rt: Runtime) -> None:
    """Ordered startup, then block in the pipe accept loop.

    Keys come BEFORE recovery: the orphan re-encrypt inside recovery needs
    the current key.  Recovery still precedes the watcher and any
    controlled-open request (plan todo 26 ordering constraint kept).
    """
    key_set = rt.key_manager.ensure_keys(online=True)  # 1. keys (online w/ cache fallback)
    print(f"[agent] keys: {len(key_set.versions)} version(s), current=v{key_set.current}")
    report = rt.recovery_runner(rt)  # 2. crash recovery: before watcher AND before pipe
    print("[agent] recovery:", _format_counts(report))
    dispatched = rt.audit.flush()  # 3. 联网后补报本地暂存审计（todo 15）
    if dispatched:
        print(f"[agent] audit: replayed {dispatched} queued event(s)")
    replayed = replay_link_audit_queue(rt)  # 3b. 卷内链接审计队列补报（todo 17①）
    if replayed:
        print(f"[agent] audit: replayed {replayed} link-queue event(s)")
    if rt.watcher is not None:  # 4. watcher thread + startup scan
        rt.watcher.start()
        print(f"[agent] watcher: started on {rt.config.protected_dir}")
    link_thread = None  # 4b. link pipe (key/audit for the link worker)
    if rt.link_pipe_server is not None:
        link_thread = threading.Thread(
            target=rt.link_pipe_server.serve_forever, name="cipherbox-link-pipe",
            daemon=True)
        link_thread.start()
        print(f"[agent] link pipe: listening on {rt.link_pipe_server.pipe_name}")
    try:
        print(f"[agent] pipe: listening on {rt.pipe_server.pipe_name}")  # 5. pipe server
        rt.pipe_server.serve_forever()
    finally:
        if rt.watcher is not None:
            rt.watcher.stop()
            print("[agent] watcher: stopped")
        if rt.link_pipe_server is not None:
            rt.link_pipe_server.stop()
            if link_thread is not None:
                link_thread.join(timeout=5.0)
            print("[agent] link pipe: closed")
        rt.pipe_server.close()
        print("[agent] pipe: closed")


def once_startup(rt: Runtime) -> tuple[RecoveryReport, str]:
    """--once mode: keys + recovery, then exit.  Never crashes offline."""
    try:
        key_set = rt.key_manager.ensure_keys(online=True)
        rt.audit.flush()  # 联网即补报本地暂存审计（todo 15）
        key_state = f"ok: {len(key_set.versions)} version(s), current=v{key_set.current}"
    except KeyManagerError as exc:
        key_state = f"unavailable: {exc}"  # offline and no DPAPI cache
    report = rt.recovery_runner(rt)
    return report, key_state


def serve_resident(rt: Runtime) -> int:
    """Run the agent until stop; drain watcher candidates; no orphan threads."""
    failures: list[BaseException] = []

    def _run() -> None:
        try:
            run_resident(rt)
        except BaseException as exc:  # thread boundary: captured and reported
            failures.append(exc)

    thread = threading.Thread(target=_run, name="cipherbox-agent", daemon=True)
    thread.start()
    _install_signal_handlers(rt.pipe_server.stop)
    try:
        while thread.is_alive():
            thread.join(timeout=1.0)  # bounded wake: lets signals run + drains watcher
            if rt.watcher is not None and not failures:
                try:
                    rt.watcher.process_pending()
                except Exception as exc:  # boundary: keep the resident loop alive
                    print(f"[agent] watcher cycle error: {exc}", file=sys.stderr)
    finally:
        rt.pipe_server.stop()
        thread.join(timeout=10.0)
    if thread.is_alive():
        print("[agent] ERROR: pipe thread did not stop within 10s", file=sys.stderr)
        return 3
    if failures:
        failure = failures[0]
        if isinstance(failure, KeyboardInterrupt):
            return 0
        print(f"[agent] ERROR: {failure}", file=sys.stderr)
        return 1
    return 0


def _install_signal_handlers(stop: Callable[[], None]) -> None:
    def _handle(signum, frame):
        stop()

    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is not None:
            with contextlib.suppress(ValueError, OSError):
                signal.signal(sig, _handle)


def _format_counts(report: RecoveryReport) -> str:
    return " ".join(f"{key}={value}" for key, value in dataclasses.asdict(report).items())


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="agent", description="CipherBox resident agent")
    parser.add_argument("--config", default="config/client.json",
                        help="client.json path (default: config/client.json)")
    parser.add_argument("--token-file", default="config/employee_token.dpapi",
                        help="DPAPI-protected employee token file")
    parser.add_argument("--once", action="store_true",
                        help="run recovery + key ensure, then exit (no watcher, no pipe)")
    parser.add_argument("--no-watcher", action="store_true",
                        help="do not start the protected-folder watcher")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    make_console_prints_safe()
    args = parse_args(argv)
    try:
        loaded = load_config(args.config, args.token_file)
    except ConfigError as exc:
        print(f"[agent] config error: {exc}", file=sys.stderr)
        return 2
    rt = build_runtime(loaded, with_watcher=not args.no_watcher and not args.once)
    if args.once:
        report, key_state = once_startup(rt)
        print("[once] recovery:", _format_counts(report))
        print("[once] keys:", key_state)
        return 0
    guard = SingleInstanceMutex(AGENT_MUTEX_NAME)  # held for process lifetime
    if not guard.acquired():
        print("[agent] another resident agent already owns the instance mutex",
              file=sys.stderr)
        return 1
    return serve_resident(rt)


if __name__ == "__main__":
    raise SystemExit(main())
