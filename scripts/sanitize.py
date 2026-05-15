#!/usr/bin/env python3
"""
htmem sanitize — strict allow-list HTML sanitizer for the LLM-read pipeline.

Default-deny. Only tags and attributes on the allow-list are preserved. Inline
event handlers, javascript: URIs, external resources, CSS-only exfiltration
vectors, Unicode tag-block / zero-width characters, and any <script> not of an
inert data-island type are dropped.

This is *not* a general-purpose sanitizer. It is tuned for the htmem format and
errs on the side of stripping. Round-trip a hostile file through this script
before passing its content to an LLM.

Zero external dependencies. Python 3.10+ stdlib only.

Usage:
  sanitize.py <path>                    # write sanitized HTML to stdout
  sanitize.py <path> --json             # emit a JSON record with sanitized text
                                        # plus extracted data islands
  sanitize.py <path> --strict-fail      # exit 2 if anything was stripped
"""
from __future__ import annotations

import argparse
import html
import json
import re
import sys
import unicodedata
from html.parser import HTMLParser
from io import StringIO
from pathlib import Path

# ---------- Allow-lists ----------------------------------------------------

VOID_TAGS = frozenset({
    "area", "base", "br", "col", "embed", "hr", "img",
    "input", "link", "meta", "param", "source", "track", "wbr",
})

ALLOWED_TAGS = frozenset({
    "html", "head", "body", "title", "meta",
    "header", "main", "footer", "section", "article", "aside", "nav",
    "h1", "h2", "h3", "h4", "h5", "h6",
    "p", "a", "ul", "ol", "li", "dl", "dt", "dd",
    "blockquote", "q", "cite", "abbr",
    "code", "pre", "kbd", "samp", "var",
    "em", "strong", "i", "b", "small", "mark", "del", "ins",
    "span", "div",
    "table", "thead", "tbody", "tfoot", "tr", "th", "td", "caption",
    "time", "hr", "br",
    "figure", "figcaption",
    "details", "summary",
    "style",   # CSS allowed in <head>, body uses are scrubbed by content rule below
    "script",  # only inert types kept; rest dropped
})

ALLOWED_ATTRS_COMMON = frozenset({
    "id", "class", "lang", "dir", "tabindex", "role", "title",
})

ALLOWED_ARIA_PREFIXES = ("aria-",)
ALLOWED_DATA_PREFIXES = ("data-htmem-",)

ALLOWED_ATTRS_BY_TAG: dict[str, frozenset[str]] = {
    "a": frozenset({"href", "rel", "hreflang"}),
    "time": frozenset({"datetime"}),
    "th": frozenset({"scope", "colspan", "rowspan", "headers", "abbr"}),
    "td": frozenset({"colspan", "rowspan", "headers"}),
    "meta": frozenset({"charset", "name", "content", "http-equiv"}),
    "html": frozenset({"data-htmem-type"}),
    "label": frozenset({"for"}),
    "script": frozenset({"type"}),
    "details": frozenset({"open"}),
}

ALLOWED_META_NAMES = frozenset({
    "viewport", "color-scheme", "description", "generator",
    "htmem-version", "htmem-type", "htmem-id", "htmem-anchor",
    "robots", "theme-color",
})

ALLOWED_META_HTTP_EQUIV = frozenset({"content-type"})  # only used in <head>; never CSP via meta (real header required)

INERT_SCRIPT_TYPES = frozenset({
    "application/json",
    "application/ld+json",
    "text/plain",
})

# ---------- URL safety ------------------------------------------------------

_URL_BANNED_SCHEMES = ("javascript:", "data:text/html", "data:application/javascript", "vbscript:", "file:")


def _is_safe_url(value: str) -> bool:
    v = value.strip().lower()
    if any(v.startswith(s) for s in _URL_BANNED_SCHEMES):
        return False
    # block CR/LF smuggling
    if "\r" in v or "\n" in v:
        return False
    return True


# ---------- Unicode hygiene -------------------------------------------------

_TAG_BLOCK_RE = re.compile(r"[\U000E0000-\U000E007F]")
_ZERO_WIDTH_RE = re.compile(r"[​-‏‪-‮⁠-⁯﻿]")


def _scrub_unicode(s: str) -> tuple[str, int]:
    """Return (clean_string, removed_count)."""
    before = len(s)
    s = unicodedata.normalize("NFKC", s)
    s = _TAG_BLOCK_RE.sub("", s)
    s = _ZERO_WIDTH_RE.sub("", s)
    # Strip Cf (format) category remaining
    s = "".join(c for c in s if unicodedata.category(c) != "Cf")
    return s, before - len(s)


# ---------- Sanitizer parser ------------------------------------------------

class Sanitizer(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.out = StringIO()
        self.tag_stack: list[str] = []
        self.drop_depth = 0  # >0 means we're inside a dropped subtree
        self.findings: list[str] = []
        self.removed_chars = 0
        self.data_islands: dict[str, str] = {}
        self._current_script_id: str | None = None
        self._current_script_kept: bool = False
        # If any DANGEROUS_TAG appears anywhere in the document, the file is
        # not a valid htmem artifact — refuse to expose ANY captured data
        # island even if it was structurally a sibling of the dangerous tag.
        self.seen_dangerous: bool = False

    # ---------- helpers ----------
    def _emit(self, s: str) -> None:
        if self.drop_depth == 0:
            self.out.write(s)

    def _finding(self, msg: str) -> None:
        if msg not in self.findings:
            self.findings.append(msg)

    def _filter_attrs(self, tag: str, attrs: list[tuple[str, str | None]]) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        allowed_for_tag = ALLOWED_ATTRS_BY_TAG.get(tag, frozenset())
        for k, v in attrs:
            k_lc = k.lower()
            if v is None:
                v = ""
            # Reject every on*= attribute, full stop
            if k_lc.startswith("on"):
                self._finding(f"dropped inline handler {k_lc} on <{tag}>")
                continue
            # Reject style=
            if k_lc == "style":
                self._finding(f"dropped inline style on <{tag}>")
                continue
            # Allowed only if in one of the lists
            allowed = (
                k_lc in ALLOWED_ATTRS_COMMON
                or k_lc in allowed_for_tag
                or any(k_lc.startswith(p) for p in ALLOWED_ARIA_PREFIXES)
                or any(k_lc.startswith(p) for p in ALLOWED_DATA_PREFIXES)
            )
            if not allowed:
                self._finding(f"dropped attr {k_lc} on <{tag}>")
                continue
            # URL attrs
            if k_lc == "href":
                if not _is_safe_url(v):
                    self._finding(f"dropped unsafe href on <{tag}>: {v[:40]!r}")
                    continue
            # meta content rule
            if tag == "meta" and k_lc == "name":
                if v.lower() not in ALLOWED_META_NAMES:
                    # tag itself will be dropped — record finding
                    self._finding(f"dropped <meta name={v!r}>")
            scrubbed_v, removed = _scrub_unicode(v)
            self.removed_chars += removed
            out.append((k_lc, scrubbed_v))
        return out

    # ---------- handlers ----------
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._handle_open(tag, attrs, is_void=False)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._handle_open(tag, attrs, is_void=True)

    DANGEROUS_TAGS = frozenset({
        "iframe", "object", "applet", "embed", "frame", "frameset", "base",
        "noframes", "noembed",
    })

    def _handle_open(self, tag: str, attrs: list[tuple[str, str | None]], is_void: bool) -> None:
        tag_lc = tag.lower()
        if tag_lc not in ALLOWED_TAGS:
            # Tag classification — dangerous tags get a specific finding
            # prefix so validate.py can promote them to CRITICAL.
            if tag_lc in self.DANGEROUS_TAGS:
                self._finding(f"dropped DANGEROUS tag <{tag_lc}>")
                self.seen_dangerous = True
            else:
                self._finding(f"dropped <{tag_lc}> subtree")
            # Void disallowed tags have no end tag — do not push a drop-depth
            # frame (otherwise everything after them is silently swallowed).
            if is_void or tag_lc in VOID_TAGS:
                return
            self.drop_depth += 1
            self.tag_stack.append(("__DROP__", tag_lc))
            return
        # Special-case <meta>: require allow-listed name or http-equiv
        if tag_lc == "meta":
            d = {k.lower(): (v or "") for k, v in attrs}
            name_ok = d.get("name", "").lower() in ALLOWED_META_NAMES
            http_ok = d.get("http-equiv", "").lower() in ALLOWED_META_HTTP_EQUIV
            charset_ok = "charset" in d
            if not (name_ok or http_ok or charset_ok):
                self._finding(f"dropped <meta {dict(d)!s}>")
                return
        # Special-case <script>: only keep inert data-island types
        if tag_lc == "script":
            # CRITICAL: never capture a script that lives inside a dropped
            # subtree — that's how a forged manifest under <applet>/<object>/
            # <embed>/<base> could otherwise smuggle past the read pipeline.
            if self.drop_depth > 0:
                self._finding("dropped <script> inside dropped subtree")
                self.drop_depth += 1
                self.tag_stack.append(("__DROP__", tag_lc))
                return
            d = {k.lower(): (v or "") for k, v in attrs}
            type_attr = d.get("type", "").lower()
            if type_attr not in INERT_SCRIPT_TYPES:
                self._finding(f"dropped active <script type={type_attr!r}>")
                self.drop_depth += 1
                self.tag_stack.append(("__DROP__", tag_lc))
                return
            # Reject script with src attribute
            if "src" in d:
                self._finding("dropped <script src=...>")
                self.drop_depth += 1
                self.tag_stack.append(("__DROP__", tag_lc))
                return
            self._current_script_id = d.get("id", "")
            self._current_script_kept = True

        filtered = self._filter_attrs(tag_lc, attrs)
        attr_str = "".join(f' {k}="{html.escape(v, quote=True)}"' for k, v in filtered)
        is_void_effective = is_void or tag_lc in VOID_TAGS
        slash = " /" if is_void_effective else ""
        self._emit(f"<{tag_lc}{attr_str}{slash}>")
        if not is_void_effective:
            self.tag_stack.append(("KEEP", tag_lc))

    def handle_endtag(self, tag: str) -> None:
        tag_lc = tag.lower()
        if not self.tag_stack:
            return
        last_kind, last_tag = self.tag_stack[-1]
        if last_kind == "__DROP__" and last_tag == tag_lc:
            self.drop_depth -= 1
            self.tag_stack.pop()
            return
        if last_kind == "KEEP" and last_tag == tag_lc:
            self.tag_stack.pop()
            if tag_lc == "script" and self._current_script_kept:
                self._current_script_id = None
                self._current_script_kept = False
            self._emit(f"</{tag_lc}>")
            return
        # Mismatch — drop silently
        self._finding(f"unbalanced close </{tag_lc}>")

    def handle_data(self, data: str) -> None:
        scrubbed, removed = _scrub_unicode(data)
        self.removed_chars += removed
        # G05: inside <style> body, refuse dangerous CSS tokens (drop the
        # whole text node, do not emit, do not store).
        if self.tag_stack and self.tag_stack[-1] == ("KEEP", "style"):
            low = scrubbed.lower()
            for tok in ("url(", "@import", "expression(", "-moz-binding", "behavior:", "javascript:", "<!--"):
                if tok in low:
                    self._finding(f"dropped <style> body — contained {tok!r}")
                    return
        # G01 belt-and-braces: only capture data islands when not in a dropped
        # subtree (the _handle_open gate already refuses, but stay defensive).
        if (
            self._current_script_kept
            and self._current_script_id is not None
            and self.drop_depth == 0
        ):
            self.data_islands[self._current_script_id] = self.data_islands.get(self._current_script_id, "") + scrubbed
        self._emit(html.escape(scrubbed, quote=False))

    def handle_comment(self, data: str) -> None:
        # Always drop comments — they are a known IPI vector (CamoLeak).
        self._finding("dropped HTML comment")

    def handle_decl(self, decl: str) -> None:
        if decl.lower().startswith("doctype"):
            self._emit(f"<!{decl}>")
        else:
            self._finding(f"dropped declaration <!{decl}>")

    def handle_pi(self, data: str) -> None:
        self._finding(f"dropped processing instruction <?{data[:30]}?>")


# ---------- CLI -------------------------------------------------------------

def sanitize_bytes(raw: bytes) -> tuple[str, list[str], int, dict[str, str]]:
    text = raw.decode("utf-8", errors="replace")
    s = Sanitizer()
    s.feed(text)
    s.close()
    # Belt-and-braces: if any dangerous tag was seen, refuse to expose the
    # captured data islands. The document is malformed for htmem purposes
    # and a "valid" island next to an <embed> or <base> is a smuggling vector.
    islands = {} if s.seen_dangerous else s.data_islands
    return s.out.getvalue(), s.findings, s.removed_chars, islands


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="sanitize.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("path", type=Path)
    p.add_argument("--json", action="store_true", help="emit JSON record")
    p.add_argument("--strict-fail", action="store_true", help="exit 2 if any finding")
    args = p.parse_args(argv)
    if not args.path.is_file():
        print(f"ERROR: not a file: {args.path}", file=sys.stderr)
        return 2
    raw = args.path.read_bytes()
    if len(raw) > 10 * 1024 * 1024:
        print("ERROR: file > 10 MB; refusing to sanitize", file=sys.stderr)
        return 2
    clean, findings, removed, islands = sanitize_bytes(raw)
    if args.json:
        json.dump(
            {
                "path": str(args.path),
                "ok": True,
                "findings": findings,
                "unicode_chars_removed": removed,
                "sanitized_html": clean,
                "data_islands": islands,
            },
            sys.stdout,
            ensure_ascii=False,
        )
        sys.stdout.write("\n")
    else:
        sys.stdout.write(clean)
    if args.strict_fail and findings:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
