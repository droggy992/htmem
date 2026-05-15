#!/usr/bin/env python3
"""
htmem anchor — compute / verify / emit the SHA-256 anchor of an htmem artifact.

The anchor fingerprints the canonical content of the file. Two passages of the
file are zeroed before hashing so the anchor depends only on content:

  1. The `content` attribute of `<meta name="htmem-anchor" content="...">`.
  2. The literal placeholder token `{{HTMEM_ANCHOR}}` (during initial render).

Usage:
  anchor.py compute <path>          # print canonical sha256 (no file change)
  anchor.py verify  <path>          # exit 0 if anchor matches, 1 otherwise
  anchor.py emit    <path>          # compute and rewrite the file's anchor meta

Exit codes:
  0  ok
  1  mismatch / verify failed
  2  malformed input / I/O error

Zero external dependencies — Python 3.10+ stdlib only.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

# Canonical attribute order is name=, then content=. We accept both orders for
# robustness against hostile files; canonical form (what `emit` writes) is
# always `name="htmem-anchor" content="..."`.
ANCHOR_META_RE = re.compile(
    rb'(<meta\s+name="htmem-anchor"\s+content=")[^"]*(")',
    flags=re.IGNORECASE,
)
ANCHOR_META_RE_REV = re.compile(
    rb'<meta\s+content="[^"]*"\s+name="htmem-anchor"\s*/?\s*>',
    flags=re.IGNORECASE,
)
# Match `"anchor": "..."` inside any data island. JSON forbids backslash
# without a valid escape so `[^"\\]` is a sound capture for the value here.
ANCHOR_JSON_FIELD_RE = re.compile(
    rb'("anchor"\s*:\s*")(?:[^"\\]|\\.)*(")',
)
# Any literal sha256:<64 hex> substring is treated as an anchor reference and
# zeroed during canonicalization. This is how the body's visible anchor (e.g.
# `<code>sha256:abc…</code>`) becomes invariant to fill-in: creation hashes
# the file with placeholders removed; validation hashes the file with the real
# anchor strings removed; both produce identical canonical bytes.
ANCHOR_TEXT_RE = re.compile(rb'sha256:[a-f0-9]{64}')
ANCHOR_TOKEN = b"{{HTMEM_ANCHOR}}"


def canonical_bytes(raw: bytes) -> bytes:
    """Return the bytes used as input to the anchor hash.

    Normalizations applied so the hash depends only on content:
      1. `<meta name="htmem-anchor" content="...">` content is emptied
         (both attribute orders are accepted).
      2. Every literal `sha256:<64 hex>` substring is removed (this is how
         body-visible anchors become invariant to fill-in).
      3. The literal `{{HTMEM_ANCHOR}}` placeholder is removed.
      4. Any JSON `"anchor": "..."` field inside an inert data island
         is emptied.
    """
    zeroed = ANCHOR_META_RE.sub(rb'\1\2', raw)
    zeroed = ANCHOR_META_RE_REV.sub(b'<meta name="htmem-anchor" content="">', zeroed)
    zeroed = ANCHOR_TEXT_RE.sub(b"", zeroed)
    zeroed = zeroed.replace(ANCHOR_TOKEN, b"")
    zeroed = ANCHOR_JSON_FIELD_RE.sub(rb'\1\2', zeroed)
    return zeroed


def compute_anchor(raw: bytes) -> str:
    h = hashlib.sha256(canonical_bytes(raw)).hexdigest()
    return f"sha256:{h}"


def read_file_anchor(raw: bytes) -> str | None:
    m = ANCHOR_META_RE.search(raw)
    if not m:
        return None
    full = ANCHOR_META_RE.search(raw).group(0)
    inner = re.search(rb'content="([^"]*)"', full)
    return inner.group(1).decode("ascii", errors="replace") if inner else None


def cmd_compute(path: Path) -> int:
    raw = path.read_bytes()
    print(compute_anchor(raw))
    return 0


def cmd_verify(path: Path) -> int:
    raw = path.read_bytes()
    expected = read_file_anchor(raw)
    if expected is None:
        print("ERROR: no <meta name=\"htmem-anchor\" content=\"...\"> in file", file=sys.stderr)
        return 2
    actual = compute_anchor(raw)
    if expected == actual:
        print(f"OK {actual}")
        return 0
    print(f"MISMATCH expected={expected} actual={actual}", file=sys.stderr)
    return 1


def cmd_emit(path: Path) -> int:
    raw = path.read_bytes()
    new_anchor = compute_anchor(raw)
    if ANCHOR_META_RE.search(raw):
        new_raw = ANCHOR_META_RE.sub(
            lambda m: m.group(1) + new_anchor.encode("ascii") + m.group(2),
            raw,
        )
    else:
        print("ERROR: file has no <meta name=\"htmem-anchor\"> to write into. Add one and retry.", file=sys.stderr)
        return 2
    new_raw = new_raw.replace(ANCHOR_TOKEN, new_anchor.encode("ascii"))
    path.write_bytes(new_raw)
    (path.with_suffix(path.suffix + ".sha256")).write_text(new_anchor + "\n", encoding="ascii")
    print(f"WROTE {new_anchor}")
    return 0


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="anchor.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("compute", "verify", "emit"):
        sp = sub.add_parser(name)
        sp.add_argument("path", type=Path)
    args = p.parse_args(argv)
    if not args.path.is_file():
        print(f"ERROR: not a file: {args.path}", file=sys.stderr)
        return 2
    try:
        if args.cmd == "compute":
            return cmd_compute(args.path)
        if args.cmd == "verify":
            return cmd_verify(args.path)
        if args.cmd == "emit":
            return cmd_emit(args.path)
    except OSError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
