"""Pytest path setup for agent tests: repo root + lo-encryption-demo/src."""

import os
import sys

REPO_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
ENGINE_SRC = os.path.join(REPO_ROOT, "lo-encryption-demo", "src")

for _path in (REPO_ROOT, ENGINE_SRC):
    if _path not in sys.path:
        sys.path.insert(0, _path)
