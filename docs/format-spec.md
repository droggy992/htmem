# htmem format spec (v0.1)

This document is the canonical reference for the on-disk shape of an htmem artifact. Authors of new templates, alternative implementations, or compatible consumers MUST follow this spec.

## File extension and encoding

* Extension: `.html`
* Encoding: UTF-8 (BOM optional but discouraged).
* Maximum file size: 10 MiB. Implementations MUST refuse larger files.
* Maximum data-island size: 1 MiB per `<script>` block. Implementations MUST refuse larger islands.

## Document shape

An htmem file is an HTML5 document. The required structure (in document order):

```text
1. <!DOCTYPE html>
2. <html lang="..." data-htmem-type="memory|decision|thread">
3.   <head>
4.     <meta charset="UTF-8">
5.     <meta name="viewport" content="...">
6.     <meta name="color-scheme" content="light dark">
7.     <meta name="generator" content="htmem <version> (<homepage>)">
8.     <meta name="htmem-version" content="0.1">
9.     <meta name="htmem-type" content="memory|decision|thread">
10.    <meta name="htmem-id" content="<id>">
11.    <meta name="htmem-anchor" content="sha256:<64 hex>">
12.    <title>...</title>
13.    <style>... single inline stylesheet, no @import, no url(), no expression() ...</style>
14.  </head>
15.  <body>
16.    <a class="skip-link" href="#main">Skip to content</a>
17.    <div class="container">
18.      <header class="hero"> ... identity layer + summary ... </header>
19.      <main id="main" tabindex="-1"> ... type-specific content sections ... </main>
20.      <footer class="anchor-footer" role="contentinfo"> ... anchor verification snippet ... </footer>
21.    </div>
22.    <script id="htmem-manifest"       type="application/json">    { ... } </script>
23.    <script id="htmem-jsonld"         type="application/ld+json"> { ... } </script>
24.    <script id="htmem-llm-onboarding" type="text/plain">          <untrusted_content> ... </untrusted_content> </script>
25.    <script id="htmem-evidence-ledger" type="application/json">   [ ... ]  (memory/decision only) </script>
26.  </body>
27. </html>
```

Every `<script>` MUST use one of the three inert types listed above. No `<script src="...">`, no `<script type="module">`, no `<script type="text/javascript">`.

## Identity layer

Required `<meta>` tags (order is canonical but not enforced):

| Name | Required | Notes |
|---|---|---|
| `htmem-version` | yes | The format version. Currently `0.1`. |
| `htmem-type` | yes | One of `memory`, `decision`, `thread`. |
| `htmem-id` | yes | 8–64 chars matching `[a-zA-Z0-9_-]+`. |
| `htmem-anchor` | yes | `sha256:<64 lowercase hex>`. May be empty until first anchor emission. |

The `<meta>` `name` allow-list is exactly: `viewport`, `color-scheme`, `description`, `generator`, `htmem-version`, `htmem-type`, `htmem-id`, `htmem-anchor`, `robots`, `theme-color`. Any other `<meta name="...">` is rejected by the sanitizer.

## Data islands

### `htmem-manifest` (required)

JSON conforming to the type-specific schema in `schemas/`. The manifest is the canonical structured payload — humans read the visible HTML, machines read the manifest.

Critical fields shared across all types:

```json
{
  "htmem_version": "0.1",
  "id": "<stable id>",
  "type": "memory|decision|thread",
  "title": "<human title, max 240 chars>",
  "version": "<semver>",
  "created": "<ISO 8601 UTC>",
  "updated": "<ISO 8601 UTC>",
  "author": "<who wrote it>",
  "summary": "<one-sentence summary, max 480 chars>"
}
```

Type-specific fields are documented in:

* `schemas/memory.schema.json`
* `schemas/decision.schema.json`
* `schemas/thread.schema.json`

### `htmem-jsonld` (optional but recommended)

JSON-LD with `@context: https://schema.org` and `@type: CreativeWork`. Improves agent and search-engine retrieval.

### `htmem-llm-onboarding` (required)

Plain-text block wrapped in `<untrusted_content>...</untrusted_content>` sentinels. Five named fields, line-separated `key: value`:

```text
what_is_this: <one sentence>
when_to_use: <one sentence>
first_action: <one sentence>
never_do: <one sentence>
source_of_truth: <path or URL>
```

The sentinel wrapping is mandatory because the onboarding field is the textual hint the next agent reads — adversaries can place instruction-shaped strings here; the sentinel makes the data/instruction boundary visible.

### `htmem-evidence-ledger` (optional, memory + decision only)

Array of evidence objects matching `evidence` in the manifest. Redundant with the manifest's `evidence` field; included for clients that want to load only the ledger.

## Anchor canonicalization

The anchor is `sha256:<hex>` of the canonical bytes of the file. To produce canonical bytes:

1. Replace the `content` attribute of `<meta name="htmem-anchor" content="...">` with the empty string. Both attribute orders (`name=` first or `content=` first) are accepted.
2. Remove every literal `sha256:<64 lowercase hex>` substring from the bytes. This makes the visible body's anchor invariant to fill-in (creation removes placeholders; validation removes the real anchor text; both produce identical canonical bytes).
3. Remove every literal `{{HTMEM_ANCHOR}}` placeholder token.
4. Replace the value of any JSON `"anchor": "..."` field inside an inert data island with the empty string.

Then compute SHA-256 over the result and prefix with `sha256:`.

Implementations MUST be byte-for-byte reproducible across platforms — Python `hashlib.sha256(canonical_bytes).hexdigest()` is the reference.

## Content rules

| Rule | Status |
|---|---|
| Exactly one `<style>` element, in `<head>`, with no `url()`, `@import`, `expression(`, `-moz-binding`, `behavior:`, or `<!--`. | required |
| No `<iframe>`, `<object>`, `<embed>`, `<frame>`, `<frameset>`, `<applet>`, `<base>`. | required |
| No `on*=` attributes. | required |
| No inline `style=` attributes. | required |
| No HTML comments outside the head-level `<!DOCTYPE>` declaration. Sanitizers MUST drop all comments. | required |
| Semantic landmarks (`<main>`, `<header>`, `<footer>`, headings in order h1 → h6 without skipping). | required |
| Accessibility tree must be clean — every interactive control has a name; every image has alt; tables have `<th scope>`. | required |
| Unicode tag-block (U+E0000–U+E007F), zero-width (U+200B–U+200F), RTL-override (U+202A–U+202E), other format (U+2060–U+206F, U+FEFF, U+FFF9–U+FFFB) MUST be stripped before persistence and rejected at schema validation. | required |
| External CDN resources. | forbidden |
| Tracking pixels / analytics. | forbidden |
| Server-side includes / templating directives. | forbidden after render |

## Type-specific shapes

### `memory`

Free-form persistent state. Sections (visible HTML): Content, Evidence, Related. Manifest fields beyond the shared core: `tags[]`, `evidence[]`, `related[]`.

### `decision`

Architecture decision record with sign-off. Sections: Decision, Rationale, Alternatives, Consequences, Evidence, Signatures. Manifest fields: `status` (`draft`/`proposed`/`accepted`/`rejected`/`superseded`), `decision`, `rationale`, `alternatives_considered[]`, `consequences`, `signatures[]`, `evidence[]`.

### `thread`

Multi-turn agent-to-agent record. Sections: Turns, Outcome, Next action. Manifest fields: `status` (`open`/`handed_off`/`closed`/`stalled`), `participants[]`, `turns[]`, `outcome`, `next_action`.

## Versioning

The format itself is versioned via `htmem-version` (currently `0.1`). Breaking changes increment the minor (until 1.0). Each artifact also carries its own content `version` (semver). Editing artifact content without bumping the content `version` and re-anchoring is flagged by `/htm-audit`.

## Conformance

A producer is **conformant** if its output passes `scripts/audit.py` on a fresh clone of the reference implementation with no findings of severity HIGH or CRITICAL.

A consumer is **conformant** if it routes all artifact content through a pipeline equivalent to `scripts/read_memory.py` before exposing any text to an LLM.
