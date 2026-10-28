"""Scratch probe (NOT committed): observe frame/process lifecycle of a controlled GUI.

Launches a controlled instance, polls components/PIDs at each step:
  after pipe ready, after settle, after doc load, after close(False).
Writes observations to stdout; cleans up its own processes.
"""
import os, subprocess, sys, time
sys.path.insert(0, r"C:\code\cipherbox\lo-encryption-demo\test")
import spike_open_loop as S

import uno


def comps(desktop):
    e = desktop.Components.createEnumeration()
    out = []
    while e.hasMoreElements():
        c = e.nextElement()
        try:
            url = c.getURL()
        except Exception:
            url = "<nourl>"
        out.append("%s(%s)" % (type(c).__name__, url))
    return out


def main():
    session_dir = os.path.join(S.TMP_ROOT, "probe-" + str(int(time.time())))
    os.makedirs(session_dir)
    pre = set(S.controlled_pids())
    launcher = S.launch_controlled(session_dir)
    try:
        t0 = time.time()
        ctx = S.wait_controlled_pipe(S.CONTROLLED_URL, timeout=45)
        print("pipe ready at %.1fs; pids=%s" % (time.time() - t0, sorted(set(S.controlled_pids()) - pre)))
        d = S.desktop_of(ctx)
        print("components at pipe-ready: %s" % comps(d))
        time.sleep(5)
        print("components after 5s settle: %s" % comps(d))
        print("pids after settle: %s" % sorted(set(S.controlled_pids()) - pre))

        # load the fixture-derived plaintext
        svc = S.connect(S.SERVICE_URL)
        tmp_path, _ = S._decrypt_to_session(svc, session_dir)
        model = d.loadComponentFromURL(uno.systemPathToFileUrl(tmp_path), "_blank", 0, ())
        print("doc loaded: %r" % (model,))
        time.sleep(1)
        print("components after load: %s" % comps(d))
        listener = S.DocCloseListener()
        model.addCloseListener(listener)
        print("closing...")
        try:
            model.close(False)
            print("close() returned cleanly")
        except Exception as exc:
            print("close() raised: %r" % (exc,))
        print("listener: closed=%s disposed=%s events=%s" % (listener.closed, listener.disposed, listener.events))
        time.sleep(3)
        alive = [p for p in (set(S.controlled_pids()) - pre) if S.pid_alive(p)]
        print("pids 3s after close: %s" % alive)
        try:
            print("components after close: %s" % comps(d))
        except Exception as exc:
            print("bridge dead after close: %r" % (exc,))
    finally:
        for pid in set(S.controlled_pids()) - pre:
            S.kill_pid(pid)
        if launcher.poll() is None:
            try:
                launcher.terminate()
            except Exception:
                pass
        for n in os.listdir(session_dir):
            try:
                os.remove(os.path.join(session_dir, n))
            except OSError:
                pass
        try:
            os.rmdir(session_dir)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
