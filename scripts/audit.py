#!/usr/bin/env python3
"""
htmem audit — 20-check deep audit of one artifact or a folder of them.

Severities: CRITICAL (block), HIGH (review), MEDIUM (report), LOW (report).
Exit codes: 0 (clean / MEDIUM+LOW only), 1 (HIGH), 2 (CRITICAL).

Zero external dependencies. Python 3.10+ stdlib only.

Usage:
  audit.py <path-or-folder>
  audit.py <path-or-folder> --format=markdown
  audit.py <path-or-folder> --format=json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from html.parser import HTMLParser
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

from validate import validate_artifact  # type: ignore


CREDENTIAL_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "A17", "AWS access key id"),
    (re.compile(r"sk-[A-Za-z0-9]{32,}"), "A17", "OpenAI-style secret key"),
    (re.compile(r"sk-ant-[A-Za-z0-9\-_]{32,}"), "A17", "Anthropic-style API key"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "A17", "GitHub PAT"),
    (re.compile(r"gho_[A-Za-z0-9]{36}"), "A17", "GitHub OAuth token"),
    (re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}"), "A17", "Slack token"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "A17", "PEM private key"),
    (re.compile(r"password\s*[:=]\s*[\"']?\w{6,}", re.IGNORECASE), "A17", "literal password assignment"),
    (re.compile(r"bearer\s+[A-Za-z0-9._\-]{20,}", re.IGNORECASE), "A17", "Bearer token"),
]

INSTRUCTION_LIKE = re.compile(
    r"\b(ignore (?:all )?previous|disregard|system\s*:|you are now|you must|act as|execute the following|override|forget (?:all )?(?:previous|prior)|jailbreak)\b",
    re.IGNORECASE,
)


class _MetaScanner(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.tags: list[tuple[str, dict]] = []
        self.comments: list[str] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag.lower(), {k.lower(): (v or "") for k, v in attrs}))

    def handle_startendtag(self, tag, attrs):
        self.tags.append((tag.lower(), {k.lower(): (v or "") for k, v in attrs}))

    def handle_comment(self, data):
        self.comments.append(data)


def _scan_unicode(text: str) -> list[str]:
    issues = []
    for c in text:
        cp = ord(c)
        if 0xE0000 <= cp <= 0xE007F:
            issues.append(f"tag-block char U+{cp:05X}")
        if unicodedata.category(c) == "Cf":
            issues.append(f"format char U+{cp:05X}")
    return issues


def audit_file(path: Path) -> dict:
    raw = path.read_bytes()
    text = raw.decode("utf-8", errors="replace")
    findings: list[dict] = []

    def add(sev, code, msg):
        findings.append({"severity": sev, "code": code, "message": msg})

    # Run the validator first — captures anchor + sanitize + schema findings
    vresult = validate_artifact(path)
    for f in vresult["findings"]:
        # Map validator codes to audit codes (V01..V16 → A0x mapping)
        if f["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            findings.append(f)

    scanner = _MetaScanner()
    scanner.feed(text)

    # A02 — script types
    for tag, attrs in scanner.tags:
        if tag == "script":
            t = attrs.get("type", "").lower()
            if t not in ("application/json", "application/ld+json", "text/plain"):
                add("CRITICAL", "A02", f"active <script type={t!r}> present")
            if "src" in attrs:
                add("CRITICAL", "A02", "<script src=...> present")

    # A03 — forbidden tags (full dangerous set per docs/format-spec.md)
    forbidden = {"iframe", "object", "embed", "frame", "frameset", "applet", "base", "noframes", "noembed"}
    for tag, _ in scanner.tags:
        if tag in forbidden:
            add("CRITICAL", "A03", f"forbidden tag <{tag}>")

    # A04 — on*= attrs
    for tag, attrs in scanner.tags:
        for k in attrs.keys():
            if k.startswith("on"):
                add("CRITICAL", "A04", f"inline handler {k}= on <{tag}>")

    # A05 — inline style attrs + style element contents
    for tag, attrs in scanner.tags:
        if "style" in attrs and tag != "html":
            add("HIGH", "A05", f"inline style on <{tag}>")
    style_count = sum(1 for tag, _ in scanner.tags if tag == "style")
    if style_count > 1:
        add("HIGH", "A05", f"{style_count} <style> elements; htmem allows exactly one in <head>")
    # Scan style element CONTENTS for dangerous tokens
    style_block_re = re.compile(r"<style\b[^>]*>(.*?)</style>", re.IGNORECASE | re.DOTALL)
    dangerous_css = ("url(", "@import", "expression(", "-moz-binding", "behavior:", "<!--", "javascript:")
    for m in style_block_re.finditer(text):
        body = m.group(1).lower()
        for token in dangerous_css:
            if token in body:
                add("HIGH", "A05", f"<style> contains dangerous token {token!r}")

    # A06 — external resources (we allow <a href> but flag any src= or url() pointing outside data:/relative)
    for tag, attrs in scanner.tags:
        for k in ("src", "data", "poster", "longdesc", "background"):
            v = attrs.get(k, "")
            if v and not (v.startswith(("./", "/", "data:")) or v == "" or v.startswith("#")):
                if v.lower().startswith(("http://", "https://", "//")):
                    add("HIGH", "A06", f"external {k}={v[:60]!r} on <{tag}>")

    # A07 — instruction-like phrases in comments. Standard descriptive
    # comments are tolerated (LOW severity); instruction-shaped comments are
    # promoted to CRITICAL.
    for c in scanner.comments:
        if INSTRUCTION_LIKE.search(c):
            add("CRITICAL", "A07", f"instruction-like phrase inside comment: {c[:80]!r}")
        else:
            add("LOW", "A07", f"HTML comment present: {c[:80]!r}")

    # A08 — <meta> outside allow-list
    allowed_meta = {"viewport", "color-scheme", "description", "generator", "htmem-version", "htmem-type", "htmem-id", "htmem-anchor", "robots", "theme-color"}
    for tag, attrs in scanner.tags:
        if tag == "meta":
            name = attrs.get("name", "").lower()
            if name and name not in allowed_meta:
                add("HIGH", "A08", f"<meta name={name!r}> outside allow-list")

    # A13 — Unicode smuggling
    issues = _scan_unicode(text)
    if issues:
        for it in issues[:5]:
            add("CRITICAL", "A13", f"unicode smuggling: {it}")
        if len(issues) > 5:
            add("CRITICAL", "A13", f"... {len(issues) - 5} more unicode issues")

    # A17 — credentials
    for pat, code, what in CREDENTIAL_PATTERNS:
        for m in pat.finditer(text):
            add("CRITICAL", code, f"possible credential ({what}): {m.group(0)[:8]}…")

    # Verdict
    has_crit = any(f["severity"] == "CRITICAL" for f in findings)
    has_high = any(f["severity"] == "HIGH" for f in findings)
    if has_crit:
        verdict = "FAIL"
    elif has_high:
        verdict = "PASS_WITH_WARNINGS"
    else:
        verdict = "PASS"

    return {
        "path": str(path),
        "verdict": verdict,
        "counts": {
            "CRITICAL": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "HIGH": sum(1 for f in findings if f["severity"] == "HIGH"),
            "MEDIUM": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "LOW": sum(1 for f in findings if f["severity"] == "LOW"),
        },
        "findings": findings,
    }


def _walk(target: Path) -> list[Path]:
    """Walk a path returning htmem-shaped HTML files.

    Discovery test reads up to 1 MB (htmem hard cap is 10 MB, but the
    `htmem-manifest` data island is reliably within the first MB). Files
    larger than 10 MB are refused upstream.
    """
    if target.is_file():
        return [target] if target.suffix.lower() == ".html" else []
    out: list[Path] = []
    for p in target.rglob("*.html"):
        try:
            if p.is_symlink():
                continue
            with p.open("rb") as f:
                head = f.read(1024 * 1024)
            if b"htmem-manifest" in head:
                out.append(p)
        except OSError:
            continue
        if len(out) > 10000:  # soft DoS cap on hostile workspaces
            break
    return out


def render_markdown(results: list[dict]) -> str:
    lines: list[str] = ["# htmem audit report", ""]
    total = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in results:
        for k, v in r["counts"].items():
            total[k] += v
    overall = "FAIL" if total["CRITICAL"] else "PASS_WITH_WARNINGS" if total["HIGH"] else "PASS"
    lines += [
        f"**Files scanned:** {len(results)}",
        f"**Overall verdict:** {overall}",
        "",
        "## Totals",
        f"- CRITICAL: {total['CRITICAL']}",
        f"- HIGH: {total['HIGH']}",
        f"- MEDIUM: {total['MEDIUM']}",
        f"- LOW: {total['LOW']}",
        "",
        "## Per-file",
        "| File | Verdict | C | H | M | L |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        c = r["counts"]
        lines.append(f"| `{r['path']}` | {r['verdict']} | {c['CRITICAL']} | {c['HIGH']} | {c['MEDIUM']} | {c['LOW']} |")
    lines.append("")
    lines.append("## Findings")
    for r in results:
        if r["findings"]:
            lines.append(f"### `{r['path']}`")
            for f in r["findings"]:
                lines.append(f"- **{f['severity']}** `{f['code']}` — {f['message']}")
            lines.append("")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="audit.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("path", type=Path)
    p.add_argument("--format", choices=("text", "markdown", "json"), default="text")
    args = p.parse_args(argv)
    targets = _walk(args.path)
    if not targets:
        print(f"no htmem artifacts under {args.path}", file=sys.stderr)
        return 2
    results = [audit_file(t) for t in targets]

    if args.format == "json":
        json.dump(results, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    elif args.format == "markdown":
        print(render_markdown(results))
    else:
        for r in results:
            print(f"{r['verdict']:25} {r['path']}")
            for f in r["findings"]:
                print(f"  {f['severity']:8} {f['code']}: {f['message']}")

    has_crit = any(r["counts"]["CRITICAL"] > 0 for r in results)
    has_high = any(r["counts"]["HIGH"] > 0 for r in results)
    if has_crit:
        return 2
    if has_high:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
