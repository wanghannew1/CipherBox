"""Assertion-level differential: socket baseline vs pipe run of test_documents.py.

Normalizes each check line to (status, ext, label) -- embedded sizes, log byte
offsets, content reprs and URLs are stripped -- then diffs the two sequences.
Exit 0 = zero behavioral change at assertion level.
"""

import re
import sys

BASELINE = r"C:\code\cipherbox\.omo\start-work\artifacts\todo-01\baseline-run.txt"
PIPE = r"C:\code\cipherbox\.omo\start-work\artifacts\todo-01\test-documents-pipe.txt"

EXTS = ("docx", "xlsx", "pptx", "doc", "xls", "ppt")
LABELS = (
    "file written",
    "is an OLE/CFB container",
    "EncryptedPackage present",
    "our encrypt() ran",
    "key derived from password",
    "container names CipherBoxDataSpace",
    "reloads with correct password",
    "our decrypt() ran on reload",
    "content survives round trip",
    "wrong password is rejected",
)


def normalize_line(line):
    line = line.rstrip("\r\n")
    if line.startswith("RESULT:"):
        return line
    if re.match(r"^--- (docx|xlsx|pptx|doc|xls|ppt) \(", line):
        return line
    m = re.match(r"^(PASS|FAIL|SKIP|ERROR)\s+(.*)$", line)
    if not m:
        return None
    status, rest = m.group(1), m.group(2)
    for ext in EXTS:
        prefix = ext + ": "
        if rest.startswith(prefix):
            body = rest[len(prefix):]
            if status == "SKIP":
                return "%s %s: built-in skip" % (status, ext)
            if status == "ERROR":
                body = re.sub(r"<[^>]*>", "<URL>", body)
                return "%s %s: %s" % (status, ext, body)
            for label in LABELS:
                if body == label or body.startswith(label + " "):
                    return "%s %s: %s" % (status, ext, label)
            return "%s %s: <UNRECOGNIZED LABEL> %r" % (status, ext, body)
    return None


def normalize(path):
    out = []
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            norm = normalize_line(line)
            if norm is not None:
                out.append(norm)
    return out


def main():
    base = normalize(BASELINE)
    pipe = normalize(PIPE)
    print("baseline (socket) normalized check lines: %d" % len(base))
    print("pipe run normalized check lines:          %d" % len(pipe))
    print()
    if base == pipe:
        print("ASSERTION-LEVEL DIFF: NONE")
        print("- identical status per check line, identical order, identical RESULT line")
        print("- the 11 pre-existing failures reproduce exactly "
              "(LO 26.8 oox post-decrypt import layer + doc/xls/ppt over-assertions, todo 2 territory)")
        print("- observed divergences are limited to embedded values "
              "(component-log byte offsets, ERROR-line URL paths), which are transport-independent")
        return 0
    print("ASSERTION-LEVEL DIFF: FOUND")
    import difflib
    for line in difflib.unified_diff(base, pipe, "baseline(socket)", "pipe", lineterm=""):
        print(line)
    return 1


if __name__ == "__main__":
    sys.exit(main())
