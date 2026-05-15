# htmem threat model

This document enumerates the threats `htmem` defends against, the defenses in place, and what is intentionally out of scope. It is updated whenever a Loop 1 / Loop 2 / Loop 3 audit lands a fix in `main`.

## Adversary model

| Adversary | Capabilities | In scope |
|---|---|---|
| **A1 — hostile artifact author** | Writes an htmem-shaped HTML file and commits it to a repo the user reads. | yes |
| **A2 — repo-fork prompt injector** | Edits an htmem artifact in a downstream fork to insert instruction-shaped content (visible body, comment, or data island). | yes |
| **A3 — local LAN attacker** | Same Wi-Fi as the user; tries to reach the htmem render server. | yes |
| **A4 — malicious npm/pip dep** | Tries to be added as a dependency to htmem to compromise installs. | yes (mitigated by zero-deps policy) |
| **A5 — supply-chain on git** | Compromises `droggy992/htmem` `main` HEAD and inserts a backdoor. | yes (mitigated by tag pinning + signed releases) |
| **A6 — co-tenant on host** | Reads the user's process memory or filesystem. | OUT of scope — local OS isolation is the OS's job |
| **A7 — physical access** | Has the unlocked machine. | OUT of scope |

## Threats and defenses

### T01 — Indirect prompt injection via free-text fields (A1, A2)

The next LLM that reads `summary`, `body`, `decision`, `rationale`, `turns.text`, `onboarding`, or `evidence.quote` could be coerced by instruction-shaped content there.

**Defenses (layered):**

1. Schema-level rejection of zero-width / RTL-override / BOM / format chars (`schemas/*.schema.json` `$defs.safeText`).
2. Sanitizer drops every Unicode `Cf` category char and every tag-block char U+E0000–U+E007F (`scripts/sanitize.py` `_scrub_unicode`).
3. Every free-text field is wrapped by `read_memory.py` in `<untrusted_content>...</untrusted_content>` sentinels before reaching the LLM.
4. `read_memory.py` escapes adversarial attempts to forge sentinel boundaries (`<untrusted_content>` inside the value becomes `&lt;untrusted_content&gt;`).
5. The `htmem-llm-onboarding` data island in templates is **pre-wrapped** with sentinels at scaffold time so even a writer that forgot to wrap is contained.

### T02 — Indirect prompt injection via HTML structure (A1, A2)

Comments, hidden `<meta>` tags, hidden `<div>` styled `display:none`, or instruction-shaped attribute values.

**Defenses:**

1. `scripts/sanitize.py` drops every HTML comment unconditionally (CamoLeak / CVE-2025-59145 lesson).
2. `<meta name="...">` is restricted to a 10-name allow-list. Anything else is dropped.
3. Inline `style=` is dropped.
4. `scripts/audit.py` A07 flags any comment containing `ignore previous`, `disregard`, `system:`, `you must`, `act as`, `execute the`, `override`, `forget`, `jailbreak` at CRITICAL.

### T03 — Local XSS via rendered HTML (A1, A2)

Inline `<script>`, `on*=`, `javascript:` URI, SVG `<animate onbegin>`, `<iframe srcdoc>`, etc.

**Defenses:**

1. Sanitizer drops every `<script>` not of an inert type (`application/json`, `application/ld+json`, `text/plain`).
2. Sanitizer drops every `<iframe>`, `<object>`, `<embed>`, `<frame>`, `<frameset>`, `<applet>`, `<base>`.
3. Sanitizer drops every `on*=` attribute.
4. URL-scheme allow-list rejects `javascript:`, `data:text/html`, `data:application/javascript`, `vbscript:`, `file:`.
5. Render server enforces strict CSP (`default-src 'self'; object-src 'none'; frame-ancestors 'self'; require-trusted-types-for 'script'`).
6. Each artifact is shown inside `<iframe sandbox>` **without** `allow-scripts` — defense-in-depth even if step 1 ever missed something.
7. File rendering via `file://` is forbidden by skill rules; only the localhost render server is supported.

### T04 — CSS-based exfiltration (A1, A2)

`background: url(...)`, `@import`, `content: attr(...)`, `@font-face` to attacker origin — the M365 Copilot Mermaid-via-CSS vector.

**Defenses:**

1. Sanitizer drops inline `style=` attrs.
2. `audit.py` A05 scans `<style>` element contents for `url(`, `@import`, `expression(`, `-moz-binding`, `behavior:`, `<!--`, `javascript:`.
3. Render server's CSP `connect-src 'self'` and `img-src 'self' data:` block off-origin requests.

### T05 — Anchor tampering (A1, A2)

Attacker edits an artifact but keeps the visible anchor unchanged.

**Defenses:**

1. `scripts/anchor.py` canonicalizes by zeroing the meta's `content`, all `sha256:<64hex>` substrings, all `{{HTMEM_ANCHOR}}` placeholders, and all JSON `"anchor"` fields.
2. The canonical input is deterministic across creation and validation — the smoke test in CI proves this.
3. `validate.py` V09 surfaces anchor mismatch at CRITICAL.
4. `read_memory.py` returns `ok=false` and refuses to expose content when the anchor mismatches.

### T06 — Unicode smuggling (A1, A2)

Adversary embeds U+E0000–U+E007F tag-block chars, U+200B–U+200F zero-width, U+202E RTL override, mixed-script tokens, or NFKC-equivalent lookalikes.

**Defenses:**

1. `_scrub_unicode` in `sanitize.py` runs NFKC normalize, drops `Cf` category, drops tag-block range, drops zero-width range.
2. Schema-level `$defs.safeText` with `not.pattern` rejects BMP-encodable variants at validate time (`schemas/*.schema.json`).
3. `audit.py` A13 surfaces any surviving instances at CRITICAL.

### T07 — Render-server escape (A3)

Local attacker reaches `127.0.0.1:<port>` from a hostile page (DNS rebinding), or escapes the iframe sandbox.

**Defenses:**

1. Bind `127.0.0.1` only — `0.0.0.0` is impossible to configure.
2. Random high port (49152–65535) per process.
3. 128-bit URL token (`secrets.token_urlsafe(32)`), compared with `secrets.compare_digest`.
4. `Host` header allow-list (`127.0.0.1:<port>`, `localhost:<port>`, `[::1]:<port>`).
5. `X-Forwarded-Host` rejected — defends against rebinding-via-proxy.
6. `Origin` header rejected — no cross-origin access.
7. Only `GET` accepted; every other method 405s.
8. State file (`render-server.json`) is mode 0o600.
9. Idle timeout (default 15 min) — server exits, token becomes invalid.

### T08 — Render-server path traversal (A3, A1)

`/raw/../../../etc/passwd?t=token`.

**Defenses:**

1. `_resolve_safe` rejects `..`, absolute paths, paths outside the served root, symlinks, non-`.html` files.
2. The served root is resolved at server start; never modifiable per-request.
3. Sanitizer runs even on disk content before serving (defense-in-depth for trees mounted from external sources).

### T09 — MCP server path traversal (A1)

A connected MCP client requests `htmem://../../etc/passwd`.

**Defenses:**

1. `_safe_resolve` in `mcp/server.py` rejects `..`, absolute paths, symlinks, non-`.html` files, paths outside `HTMEM_PROJECT_DIR`.
2. The MCP server is stdio-only — no network socket.
3. All resource reads go through `safe_read` (the same pipeline as `read_memory.py`).

### T10 — Hook abuse (A5)

A compromised plugin update adds a malicious hook that auto-runs Bash.

**Defenses:**

1. `hooks/hooks.json` is empty by default — opt-in only.
2. Three vetted recipes in `hooks/README.md`; nothing else ships pre-wired.
3. `CODEOWNERS` protects `hooks/` — every change requires explicit maintainer review.
4. CI's `validate-plugin` job parses the JSON syntax of `hooks/hooks.json` so a malformed hook block fails the build.
5. The CI smoke test runs WITH NO HOOKS — proves the core flow works without them.

### T11 — Supply-chain compromise (A5)

Attacker compromises maintainer credentials and pushes a tampered tag.

**Defenses (current in 0.1.0 + planned in v0.2 / v0.3):**

1. README instructs users to pin install by tag (`@v0.1.0`), never by `main` (in 0.1.0).
2. `.github/CODEOWNERS` requires owner sign-off on every change to `hooks/`, `.claude-plugin/`, `.github/`, `scripts/sanitize.py`, `scripts/render_server.py`, `scripts/anchor.py`, `mcp/`, `SECURITY.md`, `LICENSE` (in 0.1.0).
3. Sigstore cosign signing on release tags (planned v0.3).
4. GitHub `attest-build-provenance` on every release (planned v0.3).
5. Branch protection on `main` requiring 2-maintainer review (deferred until the project has a second maintainer; tracked under v0.3 roadmap).

### T12 — Dependency compromise (A4)

Adversary publishes a malicious version of a transitive dep.

**Defense:**

Zero PyPI runtime dependencies. The plugin runs on Python 3.10+ stdlib only. CI Dependabot watches `github-actions` and that's all there is to watch.

## What is intentionally NOT defended

* **Adversary with shell access on your machine** — see A6/A7. OS isolation is the OS's job.
* **Brute-force on the URL token** by an attacker who already has localhost access — 128 bits at random + 15-minute lifetime makes online brute infeasible; offline brute requires capturing the URL.
* **Steganography in artifact images** — `htmem` artifacts have no images. If a future template adds `<img src="data:...">`, this section will be revisited.
* **Side channels via cache timing** — out of scope.
* **Quantum-future signature breakage** — `sha256` anchors are pre-quantum-safe-enough for the foreseeable artifact lifetime.

## How to extend this model

A new threat goes into the `## Threats and defenses` section with: id, adversary tag, brief description, current defense list, status. A defense gone obsolete moves to a `## Deprecated defenses` appendix with a date. Audit loops cross-reference these IDs in their reports.
