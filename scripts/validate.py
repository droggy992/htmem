#!/usr/bin/env python3
"""
htmem validate — full structural + schema validation of an htmem artifact.

Performs:
  1. Size + UTF-8 decode check
  2. Sanitization round-trip (drops disallowed markup, surfaces findings)
  3. Anchor verification
  4. Data island extraction
  5. JSON parse of each island
  6. JSON Schema validation of the manifest against the declared type schema
  7. LLM-onboarding completeness check
  8. Unicode hygiene check

Zero external dependencies. Python 3.10+ stdlib only.

Usage:
  validate.py <path>                # print findings, exit 0/1/2
  validate.py <path> --json         # JSON output
  validate.py <path> --strict       # exit 2 on any HIGH/CRITICAL finding
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow importing siblings when run from any cwd
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

from anchor import compute_anchor, read_file_anchor  # type: ignore
from sanitize import sanitize_bytes  # type: ignore
from schema_validator import validate as jsv_validate  # type: ignore

SCHEMAS_DIR = (_HERE.parent / "schemas").resolve()


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _finding(sev: str, code: str, msg: str) -> dict:
    return {"severity": sev, "code": code, "message": msg}


def _load_schema(htmem_type: str) -> dict:
    p = SCHEMAS_DIR / f"{htmem_type}.schema.json"
    if not p.is_file():
        raise FileNotFoundError(f"schema not found: {p}")
    return json.loads(p.read_text(encoding="utf-8"))


def validate_artifact(path: Path) -> dict:
    out: dict = {
        "path": str(path),
        "ok": True,
        "findings": [],
        "manifest": None,
        "onboarding": None,
        "type": None,
        "anchor_verified": False,
    }
    f = out["findings"]

    raw = path.read_bytes()
    if len(raw) > 10 * 1024 * 1024:
        f.append(_finding("CRITICAL", "V01", "file > 10 MB"))
        out["ok"] = False
        return out
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        f.append(_finding("CRITICAL", "V02", "file is not valid UTF-8"))
        out["ok"] = False
        return out

    # ----- Sanitize round-trip -----
    clean, sfindings, removed, islands = sanitize_bytes(raw)
    for sf in sfindings:
        if sf.startswith("dropped DANGEROUS tag") or "active <script" in sf or "<script src" in sf or "javascript:" in sf or "dropped <script> inside dropped subtree" in sf:
            f.append(_finding("CRITICAL", "V03", f"sanitizer dropped dangerous markup: {sf}"))
        elif sf.startswith("dropped inline handler") or sf.startswith("dropped inline style") or sf.startswith("dropped HTML comment") or sf.startswith("dropped <style> body"):
            f.append(_finding("HIGH", "V04", sf))
        else:
            f.append(_finding("MEDIUM", "V05", sf))
    if removed > 0:
        f.append(_finding("HIGH", "V06", f"removed {removed} unicode tag/zero-width/Cf chars"))

    # V18 — multiple or zero manifest scripts is a smuggling indicator.
    # Real htmem files have exactly one `<script id="htmem-manifest"`.
    manifest_count = raw.count(b'id="htmem-manifest"') + raw.count(b"id='htmem-manifest'")
    if manifest_count == 0:
        f.append(_finding("CRITICAL", "V18", "no <script id=\"htmem-manifest\"> present"))
        out["ok"] = False
    elif manifest_count > 1:
        f.append(_finding("CRITICAL", "V18", f"multiple <script id=\"htmem-manifest\"> present (count={manifest_count})"))
        out["ok"] = False

    # ----- Anchor verify -----
    expected = read_file_anchor(raw)
    if expected is None:
        f.append(_finding("CRITICAL", "V07", "missing <meta name=htmem-anchor>"))
        out["ok"] = False
    elif expected == "{{HTMEM_ANCHOR}}":
        # Template — anchor placeholder still in place
        f.append(_finding("LOW", "V08", "anchor placeholder still present — file is an unrendered template"))
    else:
        actual = compute_anchor(raw)
        if actual != expected:
            f.append(_finding("CRITICAL", "V09", f"anchor mismatch: file={expected} computed={actual}"))
            out["ok"] = False
        else:
            out["anchor_verified"] = True

    # ----- Data islands -----
    manifest_raw = islands.get("htmem-manifest", "").strip()
    onboarding_raw = islands.get("htmem-llm-onboarding", "").strip()
    if not manifest_raw:
        f.append(_finding("CRITICAL", "V10", "missing or empty <script id=htmem-manifest>"))
        out["ok"] = False
        return out
    # Per-island size cap (allocator-DoS guard) — 1 MB per island.
    for island_id, content in islands.items():
        if len(content.encode("utf-8", errors="replace")) > 1024 * 1024:
            f.append(_finding("CRITICAL", "V17", f"data island {island_id!r} > 1 MB"))
            out["ok"] = False
            return out
    if not onboarding_raw:
        f.append(_finding("HIGH", "V11", "missing or empty <script id=htmem-llm-onboarding>"))

    try:
        manifest = json.loads(manifest_raw)
    except json.JSONDecodeError as e:
        f.append(_finding("CRITICAL", "V12", f"manifest JSON parse error: {e}"))
        out["ok"] = False
        return out

    # Treat template placeholders as a soft pass (file is a template, not a real artifact)
    if any(isinstance(v, str) and v.startswith("{{HTMEM_") for v in manifest.values() if not isinstance(v, (list, dict))):
        f.append(_finding("LOW", "V13", "manifest contains template placeholders — file is unrendered"))
        out["manifest"] = manifest
        return out

    out["manifest"] = manifest
    out["onboarding"] = onboarding_raw

    htmem_type = manifest.get("type")
    out["type"] = htmem_type
    if htmem_type not in {"memory", "decision", "thread"}:
        f.append(_finding("CRITICAL", "V14", f"unknown manifest.type: {htmem_type!r}"))
        out["ok"] = False
        return out

    # ----- Schema validation -----
    try:
        schema = _load_schema(htmem_type)
    except FileNotFoundError as e:
        f.append(_finding("CRITICAL", "V15", str(e)))
        out["ok"] = False
        return out

    errs = jsv_validate(manifest, schema)
    for e in errs:
        f.append(_finding("HIGH", "V16", f"manifest schema: {e}"))

    # Recompute overall ok
    if any(x["severity"] == "CRITICAL" for x in f):
        out["ok"] = False

    return out


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="validate.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("path", type=Path)
    p.add_argument("--json", action="store_true")
    p.add_argument("--strict", action="store_true", help="exit 2 if any HIGH or CRITICAL finding")
    args = p.parse_args(argv)
    if not args.path.is_file():
        print(f"ERROR: not a file: {args.path}", file=sys.stderr)
        return 2

    result = validate_artifact(args.path)
    findings = result["findings"]
    findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 9))

    if args.json:
        json.dump(result, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    else:
        print(f"path: {result['path']}")
        print(f"type: {result['type']}")
        print(f"anchor verified: {result['anchor_verified']}")
        print(f"findings: {len(findings)}")
        for x in findings:
            print(f"  {x['severity']:8} {x['code']}: {x['message']}")

    has_crit = any(x["severity"] == "CRITICAL" for x in findings)
    has_high = any(x["severity"] == "HIGH" for x in findings)
    if has_crit:
        return 2
    if args.strict and has_high:
        return 2
    if has_high:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
