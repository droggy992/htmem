# htmem design rationale

Why the format, the pipeline, and the constraints look the way they do. Read this when you wonder "why didn't they just X."

## Why single-file HTML

* **Self-contained = no dangling references.** A memory artifact's only meaning lives inside its bytes. Move it to a USB drive, email it, fork the repo — it still renders, still parses, still verifies its anchor.
* **HTML5 is the most-supported document format on Earth.** Every browser renders it; every LLM tokenizer handles it; every accessibility tool understands semantic landmarks; every search engine indexes it.
* **Inert data islands are a real spec feature.** `<script type="application/json">`, `<script type="application/ld+json">`, `<script type="text/plain">` are by the HTML spec NOT executed. We don't invent a side channel; we use the one the platform already gave us.
* **Markdown is too flat for memory.** Multi-section decisions, sign-off ledgers, multi-turn threads — these all want hierarchy, tables, and named regions. Markdown collapses them; HTML preserves them.

## Why Apache-2.0 (vs MIT)

Loop 1 audit guidance: htmem ships sanitizers, anchor cryptography, and an MCP server. These are surfaces patent-trolls would love to assert on. Apache-2.0's explicit patent grant + retaliation clause is the right default. MIT is shorter but lacks both.

FOSSA's 2025 analysis showed Apache-2.0 leading new project starts in security-adjacent categories for exactly this reason.

## Why zero PyPI dependencies

* The plugin runs locally. Any wheel we add is a trust delegation. Wheels can be backdoored (xz, ua-parser, event-stream, the entire 2025 cohort of typosquats).
* Python 3.10+ stdlib has everything `htmem` needs: `hashlib`, `re`, `html.parser`, `http.server`, `json`, `secrets`, `socket`, `urllib`, `pathlib`, `argparse`, `dataclasses`, `unicodedata`.
* The MCP server is stdio JSON-RPC; we built it on raw `sys.stdin`/`stdout` rather than the `mcp` PyPI package. The protocol is simple enough that 200 lines suffice, and the trust win is huge.
* Tradeoff accepted: we re-implemented a tiny JSON Schema validator and a tiny HTML sanitizer instead of using `jsonschema` / `nh3` / `DOMPurify`. They are smaller and more strict than the upstream — but they cover *less*. The format spec is correspondingly narrower so this is an acceptable trade.

## Why default-deny sanitizer

DOMPurify and `nh3` use allow-lists but their defaults are tuned for general web content (allows `<svg>`, allows many `data:` URIs, allows custom elements). `htmem`'s sanitizer allows ~50 tags and ~25 attributes — only what the canonical templates emit. Anything beyond that is dropped.

The cost: a future template that wants `<svg>` for an inline diagram has to extend the allow-list explicitly. We accept that cost; the alternative is one more thing for a CVE to exploit.

## Why one `<style>` block (not separate stylesheet files)

* External stylesheets are an external dependency. We forbid those.
* Inline `style=` attributes are a CSS-exfiltration vector. We forbid those too.
* The only middle ground is a single `<style>` in `<head>`. The audit pipeline scans that block's contents for `url()`, `@import`, `expression()` — narrow and check-able.

## Why `<untrusted_content>` sentinels

OWASP LLM01:2025 mitigation #6: "Separate trusted from untrusted content with explicit boundaries the model can see."

We pick `<untrusted_content>` (not XML-shaped, not Markdown-shaped) because it visually anchors the boundary to a model that's already pre-trained on lots of HTML. Adversarial attempts to forge the close tag are escaped to `&lt;/untrusted_content&gt;` in `read_memory.py`.

## Why dual-pipeline (LLM-read vs human-render)

The same bytes, two consumers, two threat models. Trying to make one pipeline serve both is the source of CamoLeak, CVE-2026-22813, CVE-2026-22792 — sanitizers tuned for "LLM read" get bypassed in the browser, sanitizers tuned for "browser render" leak prompt-injection to the model.

`htmem` keeps them physically separate: `read_memory.py` produces a JSON object the LLM consumes; `render_server.py` produces a sandboxed iframe the human sees. Neither can be confused for the other.

## Why anchor canonicalization removes literal `sha256:<64hex>` substrings

Two design options:
* **(A)** Anchor appears only in `<meta>` — body renders without it. Visible-anchor users can't read the hash without view-source.
* **(B)** Anchor appears in both `<meta>` and visible body — but body copies must be invariant during canonicalization, otherwise creation hash ≠ validation hash.

We pick (B) for usability. The trick: zero ANY literal `sha256:<64hex>` substring during canonicalization. Both at creation time (when the body has `{{HTMEM_ANCHOR}}` placeholders) and at validation time (when the body has the real hash), the canonical form is identical: body-anchor positions are empty.

Tradeoff: a user-written evidence quote that happens to contain a literal `sha256:<64hex>` substring is excluded from the anchor. We accept this — such substrings are rare in prose, and the risk (tamper to a quote without invalidating the file) is small.

## Why hooks default to OFF

Hooks run unsandboxed at the harness's trust level. The 2025-26 cohort of plugin CVEs is dominated by hooks (PromptArmor analysis, VentureBeat 2025 incident). We ship the recipes documented but the wiring inert. Opt-in is a two-step gesture: read the recipe, paste it. Both steps matter.

## Why the MCP server is stdio-only

Most MCP server CVEs in 2025-26 came from network-bound servers (TCP, HTTP, SSE) that under-authenticated requests. stdio is captured by the parent process; there is no socket to misuse. The tradeoff is that you can't easily share an htmem MCP server between two agents on the same machine — each agent spawns its own. We accept that cost.

## Why no telemetry

* `htmem` doesn't phone home. There is no opt-in analytics, no error reporter, no version-check ping.
* Tradeoff: we don't know who uses it. GitHub stars and explicit issues are the only signal. That's a feature; if we wanted more, we'd ship a dashboard, which is itself a data-exfiltration vector.

## Why narrow SKILL.md descriptions

* Loop 1 audit caught the original descriptions firing on phrases like "remember this" or "save this" — far too broad. A coerced model on a hostile session could trigger htmem-write to land an attacker-controlled artifact on disk.
* v0.1.0 descriptions only fire on explicit `/htm-*` invocation or the literal word "htmem". Less convenient — and that's the point.

## Why CODEOWNERS protects the boundary

Sanitizer, render server, MCP server, anchor — these are the load-bearing security surfaces. Any change there must be reviewed by `@droggy992`. Documentation, examples, and templates are open to community PRs.

## Why we ship audits as recurring CI

`gitleaks`, `CodeQL`, `Semgrep`, `trufflehog` all run on PR + on a weekly cron. Plus our own `audit.py` is part of the smoke test. Defense in depth: each tool catches a different class of bug, and the weekly cron catches new CVE rules added to upstream rule sets.

## Why 0.1.0 ships without sigstore signing

We want the first version to land cleanly and accumulate adopters first. Sigstore + provenance attestation is planned for 0.3.0 when the format spec stabilizes. README explicitly instructs users to pin install by tag, which is the cheap version of the same protection.
