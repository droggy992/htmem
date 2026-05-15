# Changelog

All notable changes to `htmem` are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-05-15

### Fixed
- `commands/htm-new.md` frontmatter — the `description` field contained literal `|` pipe characters in an unquoted YAML scalar, which Claude Code's plugin loader rejected. The command silently failed to register as `htmem:htm-new`, so `/htmem:htm-new` returned "Unknown command" while every other command loaded. Description is now single-quoted and uses `or` instead of pipes. (Reported by first install attempt.)

### Docs
- README, AGENTS.md, and the landing page (docs/index.html) now show the namespaced form `/htmem:htm-new`, `/htmem:htm-read`, `/htmem:htm-render`, `/htmem:htm-audit`, `/htmem:htm-hub` — matching how Claude Code actually exposes plugin slash commands. The un-prefixed form `/htm-new` is not a thing.

## [0.1.0] - 2026-05-15

Initial public release.

### Added
- Plugin manifest (`.claude-plugin/plugin.json`) and single-plugin marketplace (`.claude-plugin/marketplace.json`).
- Four skills: `htmem-write`, `htmem-read`, `htmem-render`, `htmem-audit`. All with narrow auto-trigger descriptions and project-boundary path validation.
- Five slash commands: `/htm-new`, `/htm-read`, `/htm-render`, `/htm-audit`, `/htm-hub`. Each has an explicit `$ARGUMENTS` quoting + shell-metachar refusal block.
- Three canonical HTML templates (`memory`, `decision`, `thread`) with semantic landmarks, modern CSS (`@layer`, `light-dark()`, `clamp()`), and inert data islands.
- Five JSON Schemas (`memory`, `decision`, `thread`, `identity`, `llm-onboarding`) with `$defs.safeText` rejecting BMP zero-width / RTL-override / format / BOM chars.
- Python security boundary (zero PyPI deps, stdlib only, Python 3.10+):
  - `scripts/anchor.py` — SHA-256 anchor compute / verify / emit. Canonicalizes `<meta name="htmem-anchor">` content, both attribute orders, literal `sha256:<64hex>` substrings, `{{HTMEM_ANCHOR}}` placeholders, and JSON `"anchor"` fields.
  - `scripts/sanitize.py` — strict allow-list HTML sanitizer with void-element handling, attribute filter, Unicode NFKC + Cf strip + tag-block U+E0000-U+E007F strip, URL-scheme allow-list, drop-comment policy.
  - `scripts/schema_validator.py` — minimal JSON Schema validator (`type`, `required`, `additionalProperties`, `enum`, `const`, `pattern`, `minLength`, `maxLength`, `minItems`, `maxItems`, `items`, `properties`, `format`, `oneOf`, `allOf`, `not`, `$ref` local only).
  - `scripts/validate.py` — orchestrator combining sanitize + anchor + schema with per-island 1 MB size cap.
  - `scripts/read_memory.py` — safe LLM-read pipeline; wraps free-text fields in `<untrusted_content>` sentinels and escapes adversarial sentinel-boundary attempts.
  - `scripts/audit.py` — 20-check deep audit including a `<style>`-element-content scan, instruction-like comment detection, credential pattern detection (AWS, OpenAI, Anthropic, GitHub, Slack, PEM, generic bearer).
  - `scripts/new_memory.py` — template scaffold + automatic anchor emission.
  - `scripts/render_server.py` — CSP-hardened localhost render server. 127.0.0.1 bind, random high port, 128-bit token-in-URL, Host header allow-list, X-Forwarded-Host rejection, idle timeout (15 min), iframe-sandboxed view route, symlink refusal, methods other than GET forbidden, no CORS.
- MCP stdio server (`mcp/server.py` + `.mcp.json`) exposing `htmem_read`, `htmem_audit`, `htmem_list` tools and `htmem://<path>` resources. Project-root sandbox + symlink refusal.
- Opt-in hooks (`hooks/hooks.json` is empty by default) with three vetted recipes documented in `hooks/README.md`: PostToolUse snapshot, SessionStart digest, PreToolUse signed-decision gate.
- CI: gitleaks, CodeQL, Semgrep (OWASP Top 10 + python + security-audit), trufflehog history scan, JSON syntax + SKILL.md frontmatter checks, end-to-end smoke (`new_memory` → `validate` → `audit` → `read_memory`).
- `.gitleaks.toml` with htmem-specific allow-list for anchor strings.
- Dependabot (github-actions ecosystem, weekly).
- `CODEOWNERS` protecting `.claude-plugin/`, `hooks/`, `.github/`, sanitizer + render server + anchor, `mcp/`, `SECURITY.md`, `LICENSE`.
- `SECURITY.md` with 72-hour ack / 30-day fix SLA and an explicit in-scope / out-of-scope list.
- `CONTRIBUTING.md` with the local check recipe and no-new-runtime-deps rule.

### Cross-agent onboarding
- `AGENTS.md` at repo root: ~180-line universal onboarding doc readable by any LLM (Claude Code, ChatGPT, Cursor, Cline, Continue, Roo, Aider) that enters the repo. Explains the three operations, hard rules, artifact types, and a one-shot example workflow.
- `/htm-help` slash command — prints the onboarding into the current Claude Code session, no side effects.
- MCP server exposes `htmem://help/agents` as a resource, returning `AGENTS.md` content. Lets any MCP-aware client preload onboarding without traversing the filesystem.

### UX
- `htmem-write` skill auto-chains into `htmem-render` at the end of its workflow. After an artifact is written and validates clean, the CSP-hardened localhost render server opens it in the user's default browser inside a sandboxed iframe. Opt-out by saying "don't open" / "skip render" / "no browser" or passing `--no-open` to `/htm-new`. Never falls back to `file://`.
- Public landing page at <https://droggy992.github.io/htmem/> served via GitHub Pages from `/docs` on `main`. Mirrors README structure with an inline-SVG dual-pipeline diagram, install steps, security defenses table, and roadmap.

### Security
- Loop 1 audit (skeleton: skills, commands, schemas, templates) completed and remediated before this release.
- Loop 2 audit (Python boundary, MCP, hooks) completed and remediated before this release.
- Loop 3 audit (full-tree pre-commit leak scan + cold-eye review) completed before tagging.
