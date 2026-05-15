#!/usr/bin/env python3
"""
htmem PreToolUse hook — refuse to overwrite a signed decision artifact.

If the pending Write/Edit targets an htmem `decision` artifact whose manifest
declares `"status": "accepted"`, exits 2 with a message asking the user to
bump version + supersede rather than edit in place.

Exit codes:
  0 = allow (default)
  2 = block; harness shows the message to the user/agent
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

MANIFEST_RE = re.compile(
    rb'<script\s+id="htmem-manifest"\s+type="application/json"\s*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL,
)


def main() -> int:
    project = os.environ.get("CLAUDE_PROJECT_DIR")
    if not project:
        return 0
    try:
        event = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0
    tool_input = event.get("tool_input") or {}
    target = tool_input.get("file_path") or tool_input.get("path") or ""
    if not target or not target.endswith(".html"):
        return 0
    p = Path(target)
    if not p.is_file():
        return 0
    try:
        raw = p.read_bytes()
    except OSError:
        return 0
    m = MANIFEST_RE.search(raw)
    if not m:
        return 0
    try:
        manifest = json.loads(m.group(1).decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return 0
    if manifest.get("type") != "decision":
        return 0
    if manifest.get("status") != "accepted":
        return 0
    msg = (
        "htmem gate: refusing to edit a decision with status=accepted in place.\n"
        f"  File: {target}\n"
        "  Bump version + create a superseding decision artifact instead.\n"
        "  To override: change the decision's status to 'superseded' first."
    )
    print(msg, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
