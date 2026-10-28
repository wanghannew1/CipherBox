"""Scratch probe (NOT committed): observe single-instance handover details."""
import os, sys, time
sys.path.insert(0, r"C:\code\cipherbox\lo-encryption-demo\test")
import spike_open_loop as S
import uno


def comp_list(desktop):
    e = desktop.Components.createEnumeration()
    out = []
    while e.hasMoreElements():
        c = e.nextElement()
        try:
            url = c.getURL()
        except Exception as exc:
            url = "<err %s>" % type(exc).__name__
        out.append(url or "<empty-url>")
    return out


def main():
    session_dir = os.path.join(S.TMP_ROOT, "probeB-" + str(int(time.time())))
    os.makedirs(session_dir)
    pre = set(S.controlled_pids())
    first = S.launch_controlled(session_dir)
    try:
        ctx = S.wait_controlled_pipe(S.CONTROLLED_URL, timeout=45)
        d = S.desktop_of(ctx)
        print("instance#1 up; settle 5s")
        time.sleep(5)
        print("components before: %s" % comp_list(d))

        svc = S.connect(S.SERVICE_URL)
        tmp_path, _ = S._decrypt_to_session(svc, session_dir)
        print("handing doc to second launcher: %s" % tmp_path)
        second = S.launch_controlled(session_dir, extra_args=[tmp_path])
        for i in range(30):
            time.sleep(1)
            rc = second.poll()
            urls = comp_list(d)
            pids = sorted(set(S.controlled_pids()) - pre)
            print("t+%02ds second_rc=%s pids=%s comps=%s" % (i + 1, rc, pids, urls))
            if rc is not None and len(urls) > 1:
                break
        print("final second returncode: %s" % second.poll())
    finally:
        for pid in set(S.controlled_pids()) - pre:
            S.kill_pid(pid)
        if first.poll() is None:
            try:
                first.terminate()
            except Exception:
                pass
        S._rmtree(session_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
