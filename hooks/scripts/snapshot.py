#!/usr/bin/env python3
"""
htmem PostToolUse hook — snapshot the file just edited as an htmem memory.

Receives the Claude Code hook event JSON on stdin. Reads the affected file
path (if any), and if it lives under ${CLAUDE_PROJECT_DIR}, writes a small
htmem memory artifact under ${CLAUDE_PROJECT_DIR}/htmem/snapshots/.

Refuses to snapshot:
  - paths outside ${CLAUDE_PROJECT_DIR}
  - paths matching .gitignore patterns (best-effort: .git, node_modules, etc.)
  - paths > 10 MB

Exit codes:
  0 = ok (proceed)
  Anything else is treated as a soft failure by the harness; do not block.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

EXCLUDED = (".git/", "node_modules/", "__pycache__/", ".venv/", "venv/", "dist/", "build/", ".htmem-state/")


def main() -> int:
    project = os.environ.get("CLAUDE_PROJECT_DIR")
    plugin = os.environ.get("CLAUDE_PLUGIN_ROOT")
    if not project or not plugin:
        return 0  # silently skip
    try:
        event = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0
    tool_input = event.get("tool_input") or {}
    target = tool_input.get("file_path") or tool_input.get("path") or ""
    if not target:
        return 0
    target_p = Path(target).resolve()
    project_p = Path(project).resolve()
    try:
        rel = target_p.relative_to(project_p).as_posix()
    except ValueError:
        return 0
    if any(rel.startswith(x) for x in EXCLUDED):
        return 0
    if not target_p.is_file():
        return 0
    if target_p.stat().st_size > 10 * 1024 * 1024:
        return 0

    out_dir = project_p / "htmem" / "snapshots"
    out_dir.mkdir(parents=True, exist_ok=True)
    title = f"Snapshot: {rel}"
    new_memory = Path(plugin) / "scripts" / "new_memory.py"
    try:
        subprocess.run(
            [sys.executable, str(new_memory), "memory", title, "--author", "PostToolUse hook"],
            cwd=str(out_dir),
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
