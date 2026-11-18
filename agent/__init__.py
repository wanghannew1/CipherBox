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
