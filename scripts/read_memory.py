#!/usr/bin/env python3
"""
htmem read_memory — safe LLM-read pipeline for htmem artifacts.

Output is a JSON object suitable for direct ingestion by an LLM. All free-text
fields are wrapped in `<untrusted_content>` sentinels so that any
prompt-injection inside the file content is visibly bounded.

Pipeline:
  1. Read bytes (never as a prompt).
  2. Validate (anchor, sanitize, schema, unicode hygiene).
  3. If CRITICAL: return ok=false with errors and exit non-zero.
  4. Otherwise: wrap free-text fields in <untrusted_content>...</untrusted_content>
     and emit a structured object.

Zero external dependencies. Python 3.10+ stdlib only.

Usage:
  read_memory.py <path>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

from validate import validate_artifact  # type: ignore


SENTINEL_OPEN = "<untrusted_content>"
SENTINEL_CLOSE = "</untrusted_content>"


def _wrap(value):
    """Wrap a string (or each string inside a list/dict) with sentinels."""
    if isinstance(value, str):
        if SENTINEL_OPEN in value:
            # Adversary tried to forge a sentinel boundary — escape it.
            value = value.replace(SENTINEL_OPEN, "&lt;untrusted_content&gt;")
            value = value.replace(SENTINEL_CLOSE, "&lt;/untrusted_content&gt;")
        return f"{SENTINEL_OPEN}{value}{SENTINEL_CLOSE}"
    if isinstance(value, list):
        return [_wrap(v) for v in value]
    if isinstance(value, dict):
        return {k: _wrap(v) for k, v in value.items()}
    return value


FREE_TEXT_FIELDS = {
    # memory
    "summary", "body_text",
    # decision
    "decision", "rationale", "consequences",
    # thread
    "outcome", "next_action",
}


def safe_read(path: Path) -> dict:
    result = validate_artifact(path)
    findings = result["findings"]
    has_crit = any(x["severity"] == "CRITICAL" for x in findings)
    if has_crit:
        return {
            "ok": False,
            "path": str(path),
            "errors": [x["message"] for x in findings if x["severity"] == "CRITICAL"],
            "warnings": [x["message"] for x in findings if x["severity"] in ("HIGH", "MEDIUM", "LOW")],
        }
    manifest = result["manifest"] or {}
    # Selectively wrap free-text fields
    wrapped = dict(manifest)
    for k in list(wrapped.keys()):
        if k in FREE_TEXT_FIELDS and isinstance(wrapped[k], str):
            wrapped[k] = _wrap(wrapped[k])
    # Always wrap onboarding (it's free-form text by design)
    onboarding = result.get("onboarding") or ""
    return {
        "ok": True,
        "path": str(path),
        "anchor_verified": result["anchor_verified"],
        "type": result["type"],
        "title": manifest.get("title"),
        "version": manifest.get("version"),
        "manifest": wrapped,
        "onboarding": _wrap(onboarding),
        "warnings": [x["message"] for x in findings if x["severity"] in ("HIGH", "MEDIUM", "LOW")],
    }


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="read_memory.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("path", type=Path)
    args = p.parse_args(argv)
    if not args.path.is_file():
        print(json.dumps({"ok": False, "error": f"not a file: {args.path}"}))
        return 2
    result = safe_read(args.path)
    json.dump(result, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
