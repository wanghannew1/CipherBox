"""CipherBox client Agent package (Windows)."""


def make_console_prints_safe() -> None:
    """Console prints must never kill a controlled session.

    Agent console lines carry file names (e.g. ``报告测试文档1 - 副本.docx``).
    When stdout/stderr is redirected (log file, pipe, non-Unicode console) the
    stream encoding can be a codepage that cannot represent them (live
    2026-11-18: cp1252 capture on a zh-CN OS raised UnicodeEncodeError from a
    plain print and fail-closed the whole open — the exception text of a
    WinError is in the OS language, so even error paths can carry non-ASCII).
    Keep the native encoding (no mojibake on real consoles) but replace
    unencodable characters instead of raising.
    """
    import sys

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(errors="replace")
        except Exception:  # noqa: BLE001 — console setup must never crash startup
            pass


def hide_directory(path: str) -> None:
    """Mark a directory +H (best-effort, idempotent).

    The agent's volume-side work areas (``.cipherbox-tmp`` /
    ``.cipherbox-quarantine`` / ``.cipherbox-profile``) reveal cipherbox
    usage to anyone browsing the volume; hiding them keeps Explorer's
    default view to documents only.  Windows-hidden affects visibility
    only — access by LO, recovery and the watcher is unchanged.  Failure
    to set the attribute is never fatal.
    """
    import ctypes

    try:
        kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
        attrs = kernel32.GetFileAttributesW(path)
        if attrs == -1:  # INVALID_FILE_ATTRIBUTES: gone / inaccessible
            return
        kernel32.SetFileAttributesW(path, attrs | 0x2)  # FILE_ATTRIBUTE_HIDDEN
    except Exception:  # noqa: BLE001 — cosmetic hardening must never crash
        pass
