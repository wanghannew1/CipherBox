"""Link-worker orchestration tests with fake uno/force_encrypt (no soffice).

Locks in the hard ordering and the agent channel of
:mod:`agent.uno_link_worker` (todo 17 ① wiring):

* registration strictly BEFORE loadComponentFromURL (todo 14 "先注册、后加载");
* the session-temp guard is applied from the spec's doc directory;
* events: registered {frames} -> loaded -> closed {crashed}, and any
  pre-load failure emits {"ok": false} and never loads the document;
* the new-frame watcher registers interceptors on frames that appear
  mid-session and dies quietly when the bridge does;
* the password provider consults the agent link pipe per forced save and
  returns None (fail-closed) on any failure;
* audit reports flow to the agent pipe, with a volume JSONL fallback queue
  when the agent cannot be reached;
* main() validates the stdin spec and surfaces errors as {"ok": false}.

run() blocks until document close, so the driver starts it in a thread and
tests advance the lifecycle through the fake doc's close listeners.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

import pytest

from agent import uno_link_worker as worker_module
from agent.uno_link_worker import REQUIRED_SPEC_KEYS, LinkWorker, main

PIPE = "cipherbox-controlled-uuid-1"
DOC = r"S:\.cipherbox-tmp\uuid-1\a.docx"
AGENT_PIPE = r"\\.\pipe\cipherbox-link"


def make_spec(**overrides) -> dict:
    spec = {
        "soffice_pipe": PIPE,
        "doc_path": DOC,
        "agent_pipe": AGENT_PIPE,
        "queue_dir": r"S:\.cipherbox-tmp\audit-queue",  # queue tests pass a tmp_path dir
        "poll_seconds": 60.0,  # watcher idle unless a test rewrites it
    }
    spec.update(overrides)
    return spec


# ---------------------------------------------------------------------------
# fake uno / force_encrypt / doc
# ---------------------------------------------------------------------------

class FakeProp:
    def __init__(self) -> None:
        self.Name = ""
        self.Value = None


class FakeResolver:
    def __init__(self, fake: "FakeUno") -> None:
        self._fake = fake

    def resolve(self, url: str):
        if self._fake.connect_fails:
            raise RuntimeError("no connection")
        self._fake.resolved_urls.append(url)
        return self._fake.ctx


class FakeServiceManager:
    def __init__(self, fake: "FakeUno") -> None:
        self._fake = fake

    def createInstanceWithContext(self, name, ctx):
        if name == "com.sun.star.bridge.UnoUrlResolver":
            return FakeResolver(self._fake)
        assert name == "com.sun.star.frame.Desktop"
        return self._fake.desktop


class FakeCtx:
    def __init__(self, fake: "FakeUno") -> None:
        self.ServiceManager = FakeServiceManager(fake)


class FakeEnumeration:
    def __init__(self, items: list) -> None:
        self._items = list(items)
        self._index = 0

    def hasMoreElements(self) -> bool:
        return self._index < len(self._items)

    def nextElement(self):
        item = self._items[self._index]
        self._index += 1
        return item


class FakeFrames:
    def __init__(self, fake: "FakeUno") -> None:
        self._fake = fake

    def queryFrames(self, _flag: int) -> list:
        # real shape: XFrames.queryFrames -> sequence<XFrame> (spike P4;
        # there is NO createEnumeration on a real desktop's Frames)
        return list(self._fake.frames)


class FakeDesktop:
    def __init__(self, fake: "FakeUno") -> None:
        self._fake = fake
        self.load_calls: list[tuple[str, str, int, tuple]] = []

    def getFrames(self) -> FakeFrames:
        return FakeFrames(self._fake)

    def loadComponentFromURL(self, url, target, flags, properties):
        self.load_calls.append((url, target, flags, tuple(properties)))
        if self._fake.load_returns_none:
            return None
        return self._fake.doc


class FakeDoc:
    def __init__(self) -> None:
        self.url = "file:///s:/.cipherbox-tmp/uuid-1/a.docx"
        self.listeners: list = []
        self.dead = False

    def getURL(self) -> str:
        if self.dead:
            raise RuntimeError("bridge disposed")
        return self.url

    def addCloseListener(self, listener) -> None:
        self.listeners.append(listener)


class FakeUno:
    def __init__(self) -> None:
        self.ctx = FakeCtx(self)
        self.desktop = FakeDesktop(self)
        self.doc = FakeDoc()
        self.frames: list = []
        self.connect_fails = False
        self.load_returns_none = False
        self.resolved_urls: list[str] = []

    def getComponentContext(self):
        return self.ctx

    def createUnoStruct(self, name: str) -> FakeProp:
        assert name == "com.sun.star.beans.PropertyValue"
        return FakeProp()

    def systemPathToFileUrl(self, path: str) -> str:
        return "file:///" + str(path).replace("\\", "/").lstrip("/")

    def getConstantByName(self, name: str) -> int:
        assert name == "com.sun.star.frame.FrameSearchFlag.ALL"
        return 1  # value irrelevant to the fakes (queryFrames ignores it)


class FakeInterceptor:
    IMPL = "com.sun.star.comp.cipherbox.ForceEncryptInterceptorImpl"

    def __init__(self) -> None:
        self.guard: str | None = None
        self._slave: "FakeInterceptor | None" = None
        self.released = False

    def set_guard(self, directory: str) -> None:
        self.guard = directory

    def getImplementationName(self) -> str:
        return self.IMPL

    def getSlaveDispatchProvider(self):
        return self._slave

    def setSlaveDispatchProvider(self, slave) -> None:
        self._slave = slave

    def release(self) -> None:
        self.released = True


class FakeForceEncrypt:
    def __init__(self) -> None:
        self.registrations: list[tuple[object, object, object]] = []
        self.interceptors: list[FakeInterceptor] = []
        self.register_fails = False
        self._chain_heads: dict[int, FakeInterceptor] = {}  # id(frame) -> head

    def register_on_frame(self, frame, provider, audit_reporter):
        """LO chain semantics: the new interceptor's slave is the chain head
        it displaces (what the worker's implementation-name dedup probes)."""
        if self.register_fails:
            raise RuntimeError("register refused")
        interceptor = FakeInterceptor()
        previous = self._chain_heads.get(id(frame))
        if previous is not None:
            interceptor.setSlaveDispatchProvider(previous)
        self._chain_heads[id(frame)] = interceptor
        self.registrations.append((frame, provider, audit_reporter))
        self.interceptors.append(interceptor)
        return interceptor


@pytest.fixture()
def wired():
    uno = FakeUno()
    fe = FakeForceEncrypt()
    return uno, fe


# ---------------------------------------------------------------------------
# driver: run() in a thread, event polling, lifecycle triggers
# ---------------------------------------------------------------------------

def run_worker(spec, *, uno, fe, requests=None, connect_timeout=0.5):
    """Start LinkWorker.run in a daemon thread; return (emitted, worker, thread)."""
    emitted: list[dict] = []
    requester = requests if requests is not None else (
        lambda pipe, request, timeout_s=5.0: {"ok": True, "key": "k3", "version": 3})
    worker = LinkWorker(
        spec, uno_module=uno, force_encrypt_module=fe,
        requester=requester, sleep=lambda _s: time.sleep(0.01),
        connect_timeout_s=connect_timeout, emit=lambda p: emitted.append(p))
    thread = threading.Thread(target=worker.run, daemon=True)
    thread.start()
    return emitted, worker, thread


def wait_event(emitted: list[dict], name: str, timeout: float = 5.0) -> dict:
    """The event with ``event == name`` (or the fatal ok:false for 'error')."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for event in emitted:
            if event.get("event") == name:
                return event
            if name == "error" and event.get("ok") is False:
                return event
        time.sleep(0.005)
    raise AssertionError(f"event {name!r} never emitted; got {emitted}")


def close_doc(uno: FakeUno, *, crashed: bool = False, timeout: float = 5.0) -> None:
    """Fire the close path: notifyClosing (clean) or disposing (crashed).
    Waits for the worker thread to reach addCloseListener first (race: the
    'loaded' event precedes listener registration by a scheduling step)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and not uno.doc.listeners:
        time.sleep(0.005)
    assert uno.doc.listeners, "close listener never registered"
    listener = uno.doc.listeners[0]
    if crashed:
        listener.disposing(None)
    else:
        listener.notifyClosing(None)


# ---------------------------------------------------------------------------
# hard ordering + events
# ---------------------------------------------------------------------------

class TestHardOrdering:
    def test_registers_all_frames_before_load_then_clean_close(self, wired):
        uno, fe = wired
        uno.frames = [object(), object(), object()]
        emitted, _, thread = run_worker(make_spec(), uno=uno, fe=fe)

        wait_event(emitted, "loaded")
        assert len({id(f) for f, _, _ in fe.registrations}) == 3  # frames hit
        assert len(uno.desktop.load_calls) == 1  # ...BEFORE the single load
        url, target, flags, props = uno.desktop.load_calls[0]
        assert url == "file:///S:/.cipherbox-tmp/uuid-1/a.docx"
        assert target == "_blank" and flags == 0
        assert props[0].Name == "UpdateDocMode" and props[0].Value == 0

        close_doc(uno)
        thread.join(timeout=5)
        assert not thread.is_alive()
        assert [e["event"] for e in emitted] == ["registered", "loaded", "closed"]
        assert emitted[0]["frames"] == 3
        assert emitted[-1] == {"event": "closed", "crashed": False}

    def test_repeated_sweep_releases_duplicates_and_counts_zero(self, wired):
        """queryFrames hands out FRESH proxies per poll (live smoke P1), so
        proxy-identity dedup cannot work: sweep 2 re-registers and must drop
        each duplicate because its slave carries a token the worker holds."""
        uno, fe = wired
        uno.frames = [object(), object()]
        worker = LinkWorker(
            make_spec(), uno_module=uno, force_encrypt_module=fe,
            requester=lambda pipe, request, timeout_s=5.0: {"ok": True, "key": "k"})
        worker._desktop = uno.desktop  # skip connect/register phases
        assert worker._register_new_frames(uno, fe) == 2
        assert worker._register_new_frames(uno, fe) == 0
        assert len(worker._interceptors) == 2  # only the originals are kept
        assert len(fe.registrations) == 4  # LO saw the re-registrations
        assert all(ic.released for ic in fe.interceptors[2:])  # ...and dropped

    def test_guard_set_from_doc_directory(self, wired):
        uno, fe = wired
        uno.frames = [object()]
        emitted, _, thread = run_worker(make_spec(), uno=uno, fe=fe)
        wait_event(emitted, "loaded")
        assert fe.interceptors[0].guard == r"S:\.cipherbox-tmp\uuid-1"
        close_doc(uno)
        thread.join(timeout=5)

    def test_load_failure_emits_ok_false_and_never_loads(self, wired):
        uno, fe = wired
        uno.frames = [object()]
        uno.load_returns_none = True
        emitted, _, thread = run_worker(make_spec(), uno=uno, fe=fe)

        error = wait_event(emitted, "error")
        assert "None" in error["error"]
        assert all("loaded" != e.get("event") for e in emitted)
        thread.join(timeout=5)
        assert emitted[-1]["ok"] is False

    def test_no_frames_is_a_hard_failure(self, wired):
        uno, fe = wired
        emitted, _, thread = run_worker(make_spec(), uno=uno, fe=fe)
        assert "no frames" in wait_event(emitted, "error")["error"]
        thread.join(timeout=5)
        assert uno.desktop.load_calls == []

    def test_connect_failure_emits_ok_false(self, wired):
        uno, fe = wired
        uno.connect_fails = True
        emitted, _, thread = run_worker(make_spec(), uno=uno, fe=fe,
                                        connect_timeout=0.2)
        assert "unreachable" in wait_event(emitted, "error")["error"]
        thread.join(timeout=5)
        assert uno.desktop.load_calls == []


# ---------------------------------------------------------------------------
# new-frame watcher
# ---------------------------------------------------------------------------

class TestNewFrameWatcher:
    def test_late_frame_gets_registered(self, wired):
        uno, fe = wired
        uno.frames = [object()]
        emitted, worker, thread = run_worker(
            make_spec(poll_seconds=0.02), uno=uno, fe=fe)
        wait_event(emitted, "loaded")

        late = object()
        uno.frames.append(late)
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if any(frame is late for frame, _, _ in fe.registrations):
                break
            time.sleep(0.01)
        assert any(frame is late for frame, _, _ in fe.registrations)

        close_doc(uno)
        thread.join(timeout=5)

    def test_watcher_marks_crash_on_bridge_death(self, wired):
        """A dead bridge during a watcher sweep flips the crash flag (which
        the close wait reports as crashed=True)."""
        uno, fe = wired
        uno.frames = [object()]
        worker = LinkWorker(
            make_spec(poll_seconds=0.02), uno_module=uno,
            force_encrypt_module=fe,
            requester=lambda pipe, request, timeout_s=5.0: {"ok": True, "key": "k", "version": 1},
            sleep=lambda _s: time.sleep(0.01))
        worker._desktop = uno.desktop  # skip connect/register phases
        worker._register_new_frames(uno, fe)

        watcher = threading.Thread(target=worker._watch_frames, args=(uno, fe), daemon=True)
        watcher.start()
        uno.desktop.getFrames = lambda: (_ for _ in ()).throw(
            RuntimeError("bridge disposed"))
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if worker._crashed.is_set():
                break
            time.sleep(0.01)
        assert worker._crashed.is_set()
        watcher.join(timeout=5)
        assert not watcher.is_alive()


# ---------------------------------------------------------------------------
# close detection
# ---------------------------------------------------------------------------

class TestCloseDetection:
    def test_clean_close_via_listener(self, wired):
        uno, fe = wired
        uno.frames = [object()]
        emitted, _, thread = run_worker(make_spec(), uno=uno, fe=fe)
        wait_event(emitted, "loaded")
        close_doc(uno)  # waits for addCloseListener, then fires notifyClosing
        assert len(uno.doc.listeners) == 1
        thread.join(timeout=5)
        assert emitted[-1] == {"event": "closed", "crashed": False}

    def test_disposing_marks_crashed(self, wired):
        uno, fe = wired
        uno.frames = [object()]
        emitted, _, thread = run_worker(make_spec(), uno=uno, fe=fe)
        wait_event(emitted, "loaded")
        close_doc(uno, crashed=True)
        thread.join(timeout=5)
        assert emitted[-1] == {"event": "closed", "crashed": True}

    def test_bridge_death_without_listener_is_crashed(self, wired):
        uno, fe = wired
        uno.frames = [object()]

        def refuse(listener):
            raise RuntimeError("listener unsupported")

        uno.doc.addCloseListener = refuse
        emitted, _, thread = run_worker(make_spec(), uno=uno, fe=fe)
        wait_event(emitted, "loaded")

        uno.doc.dead = True  # the poll sees the doc gone...

        def dead_frames():
            raise RuntimeError("bridge disposed")

        uno.desktop.getFrames = dead_frames  # ...and the bridge is dead TOO
        thread.join(timeout=5)
        # the closed event carries a diagnostic `detail` alongside the verdict
        assert emitted[-1].get("event") == "closed"
        assert emitted[-1].get("crashed") is True
        assert "detail" in emitted[-1]

    def test_notify_closing_then_disposal_stays_clean(self, wired):
        """close(False) fires notifyClosing AND THEN disposing (the doc is
        disposed right after) — the disposal following a notified close must
        NOT flip the session to crashed (live smoke P6)."""
        uno, fe = wired
        uno.frames = [object()]
        emitted, _, thread = run_worker(make_spec(), uno=uno, fe=fe)
        wait_event(emitted, "loaded")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not uno.doc.listeners:
            time.sleep(0.01)
        assert uno.doc.listeners
        uno.doc.listeners[0].notifyClosing(None)
        uno.doc.listeners[0].disposing(None)  # disposal FOLLOWS the clean close
        thread.join(timeout=5)
        assert emitted[-1] == {"event": "closed", "crashed": False}

    def test_poll_race_close_is_clean_when_bridge_alive(self, wired):
        """Live smoke P6: close(False) can outrace notifyClosing -- the poll
        finds the doc disposed while the bridge is still alive.  That is a
        NORMAL close, not a crash (the desktop remains touchable)."""
        uno, fe = wired
        uno.frames = [object()]

        def refuse(listener):
            raise RuntimeError("listener unsupported")

        uno.doc.addCloseListener = refuse
        emitted, _, thread = run_worker(make_spec(), uno=uno, fe=fe)
        wait_event(emitted, "loaded")
        uno.doc.dead = True  # poll sees disposal; NO listener ever fires
        thread.join(timeout=5)
        assert emitted[-1].get("event") == "closed"
        assert emitted[-1].get("crashed") is False


# ---------------------------------------------------------------------------
# agent channel: key + audit
# ---------------------------------------------------------------------------

class TestKeyChannel:
    def test_provider_returns_key_from_agent(self, wired):
        uno, fe = wired
        uno.frames = [object()]
        requests: list[tuple[str, dict]] = []

        def requester(pipe, request, timeout_s=5.0):
            requests.append((pipe, request))
            return {"ok": True, "key": "current-key", "version": 3}

        emitted, _, _ = run_worker(make_spec(), uno=uno, fe=fe, requests=requester)
        wait_event(emitted, "loaded")
        _, provider, _ = fe.registrations[0]
        assert provider() == "current-key"
        assert requests[0][0] == AGENT_PIPE
        assert requests[0][1] == {"cmd": "key"}

    def test_provider_none_on_request_failure(self, wired):
        uno, fe = wired
        uno.frames = [object()]

        def requester(pipe, request, timeout_s=5.0):
            raise RuntimeError("agent gone")

        emitted, _, _ = run_worker(make_spec(), uno=uno, fe=fe, requests=requester)
        wait_event(emitted, "loaded")
        _, provider, _ = fe.registrations[0]
        assert provider() is None  # fail-closed: the save is refused

    def test_provider_none_on_bad_response(self, wired):
        uno, fe = wired
        uno.frames = [object()]
        emitted, _, _ = run_worker(make_spec(), uno=uno, fe=fe, requests=(
            lambda pipe, request, timeout_s=5.0: {"ok": False, "error": "denied"}))
        wait_event(emitted, "loaded")
        _, provider, _ = fe.registrations[0]
        assert provider() is None
        assert provider() is None  # empty key also refused


class TestAuditChannel:
    def test_audit_sent_to_agent(self, wired, tmp_path: Path):
        uno, fe = wired
        uno.frames = [object()]
        queue_dir = str(tmp_path / "audit-queue")
        sent: list[tuple[str, dict]] = []

        def requester(pipe, request, timeout_s=5.0):
            sent.append((pipe, request))
            return {"ok": True}

        emitted, _, _ = run_worker(
            make_spec(queue_dir=queue_dir), uno=uno, fe=fe, requests=requester)
        wait_event(emitted, "loaded")
        _, _, reporter = fe.registrations[0]
        reporter("export_plaintext", "ab" * 32, None, True)
        assert sent == [(AGENT_PIPE, {
            "cmd": "audit", "action": "export_plaintext",
            "file_hash": "ab" * 32, "key_version": None, "ok": True})]
        assert not os.path.exists(os.path.join(queue_dir, worker_module.QUEUE_FILE_NAME))

    def test_audit_falls_back_to_volume_queue(self, wired, tmp_path: Path):
        uno, fe = wired
        uno.frames = [object()]
        queue_dir = str(tmp_path / "audit-queue")

        def failing_requester(pipe, request, timeout_s=5.0):
            raise RuntimeError("pipe absent")

        emitted, _, _ = run_worker(make_spec(queue_dir=queue_dir), uno=uno, fe=fe,
                                   requests=failing_requester)
        wait_event(emitted, "loaded")
        _, _, reporter = fe.registrations[0]
        reporter("encrypt", "cd" * 32, 2, False)
        path = os.path.join(queue_dir, worker_module.QUEUE_FILE_NAME)
        with open(path, "r", encoding="utf-8") as fh:
            lines = [json.loads(line) for line in fh if line.strip()]
        assert lines == [{"action": "encrypt", "file_hash": "cd" * 32,
                          "key_version": 2, "ok": False}]


# ---------------------------------------------------------------------------
# main(): stdin spec validation
# ---------------------------------------------------------------------------

class TestMain:
    def test_valid_spec_reaches_worker(self, wired, capsys):
        uno, fe = wired
        captured: dict = {}

        class ScriptedWorker(LinkWorker):
            def run(self_inner):
                return 0

        def factory(spec):
            captured["spec"] = spec
            return ScriptedWorker(spec, uno_module=uno, force_encrypt_module=fe)

        rc = main(stdin=json.dumps(make_spec()).encode(), worker_class=factory)
        assert rc == 0
        assert captured["spec"]["soffice_pipe"] == PIPE
        assert captured["spec"]["agent_pipe"] == AGENT_PIPE

    def test_invalid_json_rejected(self, capsys):
        assert main(stdin=b"{not json") == 2
        response = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert response["ok"] is False and "JSON" in response["error"]

    def test_missing_keys_rejected(self, capsys):
        assert main(stdin=b'{"soffice_pipe": "x"}') == 2
        response = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert response["ok"] is False
        for key in REQUIRED_SPEC_KEYS:
            assert key in response["error"]
