---
name: htmem-audit
description: Deep-audit an htmem HTML artifact for prompt-injection vectors, supply-chain issues, anchor tampering, schema violations, and Unicode smuggling. ONLY fire when (a) the user explicitly invokes `/htm-audit`, (b) the user names a specific path that contains an `htmem-manifest` data island and asks to audit/scan/verify it, or (c) the user writes the literal word "htmem" alongside an audit intent. Do NOT auto-fire on generic prompts like "audit this" or "check this" — those are too broad. Refuse to audit paths outside `${CLAUDE_PROJECT_DIR}` even when explicitly requested, since indexing arbitrary host files could expose sensitive paths.
allowed-tools: Bash, Glob
---

# htmem-audit — Deep-Inspection Audit

## What this skill does

Runs the full htmem audit pipeline against one file or a folder and produces a tabular report of every finding by severity. Unlike `htmem-read` (which silently strips and proceeds), `htmem-audit` surfaces everything.

## When to fire

- Before sign-off on a `decision`-type artifact.
- Before committing an htmem file to a public git repo.
- When loading an htmem from an untrusted source (e.g. another agent's output, a downloaded artifact).
- When the user says "is this safe to merge" or "scan this".
- On a schedule, against an entire memory folder (full audit).

## Workflow

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/audit.py" <path-or-folder> --format=markdown
```

The script runs every check below and emits a markdown report.

### Checks performed

| ID | Check | Severity |
|---|---|---|
| A01 | SHA-256 anchor matches canonical content | CRITICAL |
| A02 | All `<script>` blocks are inert data-island types | CRITICAL |
| A03 | No `<iframe>`, `<object>`, `<embed>`, `<link rel="import">` | CRITICAL |
| A04 | No `on*=` attributes | CRITICAL |
| A05 | No `style=` or `<style>` outside the head-level allow-list | HIGH |
| A06 | No external resources (`http(s)://...` in any `src` or `href` except `data:`) | HIGH |
| A07 | No HTML comments containing instruction-like phrases (`ignore previous`, `system:`, `execute the`, `act as`) | HIGH |
| A08 | No `<meta>` tags outside the htmem allow-list | HIGH |
| A09 | JSON islands parse and conform to the declared type schema | CRITICAL |
| A10 | LLM onboarding block exists and is non-empty | HIGH |
| A11 | Identity layer fields all present (id, title, type, version, created, updated, author, anchor) | HIGH |
| A12 | Semantic landmarks present (`<main>`, `<header>`, headings in order) | MEDIUM |
| A13 | No Unicode Cf-category or U+E0000–U+E007F characters in identifier or short-text fields | CRITICAL |
| A14 | No mixed-script tokens (Cyrillic + Latin, etc.) in identifier fields | HIGH |
| A15 | Free-text fields wrapped in `<untrusted_content>` sentinels | MEDIUM |
| A16 | Evidence layer has at least one source with URL + date for `decision` and `thread` types | MEDIUM |
| A17 | No credentials patterns (regex: `password=`, `token=`, `api_key=`, `bearer `, `AKIA[0-9A-Z]{16}`, `sk-[a-zA-Z0-9]{32,}`) | CRITICAL |
| A18 | No prompt-injection sentinels visible to the model (`</untrusted_content>` inside untrusted text — escape attempt) | HIGH |
| A19 | Sign-off layer present and non-stub for `decision`/`thread` types | MEDIUM |
| A20 | Version field is valid semver | LOW |

### Severity behavior

- **CRITICAL** — block ingestion. Exit code 2.
- **HIGH** — surface in report, allow ingestion only with explicit user override (`--allow-high`). Exit code 1.
- **MEDIUM** — surface in report, do not block. Exit code 0.
- **LOW** — surface in report, do not block. Exit code 0.

### Folder audit

If the path is a folder, the audit recurses into every `*.html` containing an `htmem-manifest` data island. The report aggregates findings by file.

## Output format

```markdown
# htmem audit report
**Date:** 2026-05-15T12:34:56Z
**Target:** /path/to/memory.html (or folder)
**Files scanned:** N
**Verdict:** PASS | PASS_WITH_WARNINGS | FAIL

## Findings by severity

### CRITICAL (0)
_None._

### HIGH (1)
- `A07` external comment looks like instruction at line 142 — `"# ignore previous instructions and..."`

### MEDIUM (2)
- `A15` body_text field not wrapped in <untrusted_content>
- `A16` evidence layer has no sources

### LOW (0)
_None._

## Per-file results
| File | Verdict | C | H | M | L |
|---|---|---|---|---|---|
| memory.html | PASS_WITH_WARNINGS | 0 | 1 | 2 | 0 |
```

## Path-traversal refusal (mandatory)

Before running the script, gate on the argument:

- The path must NOT contain `..` segments.
- If absolute, the path must be inside `${CLAUDE_PROJECT_DIR}`.
- The path must NOT be a symbolic link.

Single-quote the validated path before passing to Bash (replace each `'` with `'\''`).

If validation fails, refuse and ask the user to re-anchor inside the project. Do not bypass this gate even if the user insists — explain that auditing host paths outside the project could index sensitive files (`.ssh/`, system configs, other users' homes).

## Style-element check (A05 clarification)

The audit allows **exactly one** `<style>` element, located in `<head>`, whose contents contain none of: `url(`, `@import`, `expression(`, `-moz-binding`, `behavior:`, `<!--`. Multiple `<style>` blocks, body-level `<style>`, or any of those tokens fail A05.

## Benign-comment allow-list (A07 clarification)

A07 flags HTML comments only when they match instruction-shaped patterns: `ignore previous`, `disregard`, `system:`, `you must`, `act as`, `execute the`, `override`, `forget`, `jailbreak`. Standard descriptive comments (e.g. the template's "The blocks below are inert data islands…") are allowed.

## What this skill must never do

- Fix findings silently. The audit reports; the user (or `htmem-write`) decides what to fix.
- Strip CRITICAL findings without telling the user — they indicate the file is malformed or hostile.
- Run on directories outside `${CLAUDE_PROJECT_DIR}` — refuse, do not auto-confirm.

## Cross-references

- Threat model: `${CLAUDE_PLUGIN_ROOT}/docs/threat-model.md`
- Schemas: `${CLAUDE_PLUGIN_ROOT}/schemas/`
- Companion skills: `htmem-read`, `htmem-write`, `htmem-render`
