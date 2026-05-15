#!/usr/bin/env python3
"""
htmem SessionStart hook — emit a one-line digest of existing htmem artifacts.

Read-only. Exits cleanly even on filesystems that are slow / empty.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def main() -> int:
    project = os.environ.get("CLAUDE_PROJECT_DIR")
    if not project:
        return 0
    root = Path(project).resolve()
    count = 0
    for p in root.rglob("*.html"):
        try:
            if p.is_symlink():
                continue
            if any(part in (".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build") for part in p.parts):
                continue
            head = p.read_bytes()[:4096]
            if b"htmem-manifest" in head:
                count += 1
        except OSError:
            continue
        if count > 1000:
            break
    if count:
        print(f"htmem: {count} artifact{'s' if count != 1 else ''} found under {root}. Use /htm-hub to browse.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
