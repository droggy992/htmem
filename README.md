# htmem

> **HTML is the new Markdown for LLM I/O. `htmem` makes it canonical, signed, and safe.**

**Landing page:** <https://droggy992.github.io/htmem/> · **Source:** <https://github.com/droggy992/htmem>

`htmem` is a [Claude Code](https://docs.claude.com/en/docs/claude-code) plugin (and MCP server) that teaches AI agents to write and read **single-file HTML** as their persistent memory and inter-agent communication format. Each artifact is human-renderable, LLM-ingestible, schema-validated, anchor-fingerprinted against tampering, and routed through a strict sanitizer before any LLM ever sees its content.

* **One file per memory.** Self-contained — no external CSS, no external scripts, no CDN.
* **Dual pipeline.** LLM-read view runs through a default-deny sanitizer + JSON Schema validator + `<untrusted_content>` sentinel wrapper. Human-render view is served by a CSP-hardened localhost server inside an iframe sandbox.
* **Anchor-signed.** Every artifact carries a SHA-256 anchor of its canonical content. Editing without bumping `version` and re-anchoring is flagged by `/htm-audit`.
* **Zero runtime dependencies.** Stdlib-only Python. No npm, no pip wheels, no CDN. Read every line of code before installing.
* **Hooks off by default.** No PostToolUse / SessionStart / PreToolUse hooks fire until you opt in by reading the recipe in `hooks/README.md` and pasting it into `hooks/hooks.json` yourself.
* **MCP cross-agent.** Bundled stdio MCP server exposes htmem artifacts as `htmem://...` resources for ChatGPT desktop, Cursor, Cline, Continue, and any other MCP-aware agent.

## Install

```shell
/plugin marketplace add droggy992/htmem@v0.1.0
/plugin install htmem@htmem-plugins --scope user
```

Always install by tag (`@v0.1.0`), not from bare `main`. The plugin code runs on your machine; you should be able to read every line you're trusting.

## 60-second tour

```text
# Create a canonical decision artifact
> /htm-new decision "Switch our caching layer from Redis to in-memory LRU"

# Open it in a sandboxed browser view
> /htm-render htmem/decision-switch-our-caching-layer-2026-05-15.html

# Audit before commit
> /htm-audit htmem/

# In a future session, ask Claude what was decided
> what's in htmem/decision-switch-our-caching-layer-2026-05-15.html
# (auto-routes to /htm-read; runs sanitizer + anchor verify + schema check)
```

## Why HTML, why now

The "HTML is the new Markdown" thesis crystallized in May 2026 after Thariq Shihipar's *Unreasonable Effectiveness of HTML* and Simon Willison's [permalink endorsement](https://simonwillison.net/2026/May/8/unreasonable-effectiveness-of-html/). The defensible reading isn't "HTML beats Markdown everywhere" — it's **bifurcated by direction**:

| Direction | Best format | Why |
|---|---|---|
| Agent → human (outputs, decisions, artifacts) | **HTML** | Diagrams, tables, hierarchy, links, interactivity — Markdown flattens all of it. |
| Agent → agent (context, retrieval, RAG) | **HTML with structured data islands** | [HtmlRAG](https://arxiv.org/abs/2411.02959) shows HTML beats plain-text on six QA benchmarks because heading + table structure survives. |
| System → agent (tables, configs) | **Markdown-KV or YAML** | [Improving Agents 2025](https://www.improvingagents.com/blog/best-input-data-format-for-llms/) benchmarks show MD-KV at 60.7 % vs HTML at 53.6 % on tabular tasks. |

`htmem` is built for the first two. For the third (config files, table input), keep using Markdown.

## What ships in v0.1.0

| Component | Purpose | Lines |
|---|---|---|
| 4 skills | `htmem-write`, `htmem-read`, `htmem-render`, `htmem-audit` — narrow auto-trigger only on explicit `/htm-*` or literal "htmem" mentions. | ~300 each |
| 5 slash commands | `/htm-new`, `/htm-read`, `/htm-render`, `/htm-audit`, `/htm-hub` — each with explicit `$ARGUMENTS` quoting and shell-metachar refusal. | ~30 each |
| 3 HTML templates | `memory.html`, `decision.html`, `thread.html` — semantic landmarks, `@layer` CSS, `light-dark()` tokens, no JS, no external resources. | ~250 each |
| 5 JSON Schemas | `memory`, `decision`, `thread`, `identity`, `llm-onboarding` — bounded `maxLength` / `maxItems` + `not`-based zero-width rejection. | ~80 each |
| Python boundary | `anchor.py`, `sanitize.py`, `schema_validator.py`, `validate.py`, `read_memory.py`, `audit.py`, `new_memory.py`, `render_server.py` — zero deps. | ~150–500 each |
| MCP server | `mcp/server.py` — stdio JSON-RPC for `htmem_read` / `htmem_audit` / `htmem_list` + `htmem://...` resources. | ~200 |
| Opt-in hooks | Three vetted recipes (snapshot / digest / signed-gate). `hooks/hooks.json` empty by default. | — |
| CI | gitleaks · CodeQL · Semgrep · trufflehog · plugin-validate · end-to-end smoke. | — |

## Architecture (two pipelines)

```text
                            ┌───────────────────────────────────┐
                            │            htmem file              │
                            │  (single self-contained .html)     │
                            └───────────────┬───────────────────┘
                                            │
              ┌─────────────────────────────┴───────────────────────────┐
              │                                                         │
              ▼                                                         ▼
   ┌────────────────────┐                                  ┌───────────────────────┐
   │  LLM-read pipeline │                                  │ Human-render pipeline │
   │  (read_memory.py)  │                                  │  (render_server.py)   │
   ├────────────────────┤                                  ├───────────────────────┤
   │ 1. sanitize        │                                  │ 1. bind 127.0.0.1     │
   │    (default-deny   │                                  │ 2. random high port   │
   │    HTML allow-list)│                                  │ 3. 128-bit token URL  │
   │ 2. NFKC + strip Cf │                                  │ 4. strict CSP headers │
   │    + tag-block     │                                  │ 5. iframe sandbox     │
   │ 3. anchor verify   │                                  │ 6. host header check  │
   │ 4. schema validate │                                  │ 7. 15-min idle exit   │
   │ 5. sentinel wrap   │                                  │ 8. symlink refusal    │
   │    <untrusted_     │                                  │ 9. methods != GET     │
   │     content>...    │                                  │    refused            │
   │ 6. emit JSON       │                                  │                       │
   └────────────┬───────┘                                  └────────────┬──────────┘
                ▼                                                       ▼
        agent / Claude / MCP client                              user's browser
```

## Security stance

This plugin's threat model lives in [`docs/threat-model.md`](docs/threat-model.md). The short version:

* **Indirect prompt injection (IPI) is the headline threat.** A memory file an attacker writes today is read by your agent next week — and IPI in the wild grew 32 % YoY (Google Threat Intel Nov 2025 → Feb 2026). `htmem` wraps every free-text field in `<untrusted_content>` sentinels, strips Unicode tag-block + zero-width, drops every HTML comment, and refuses external CSS/JS/iframes/objects.
* **CVE-2026-22813** (OpenCode XSS via LLM markdown→DOM) and **CVE-2025-59145** ("CamoLeak", Copilot Chat CSP bypass via hidden HTML comments) are the precedent. The defenses above are direct responses.
* **MCP servers were the #1 attack surface in 2025-26 CVEs.** `htmem`'s MCP server is stdio-only, never opens a network socket, refuses paths outside `${HTMEM_PROJECT_DIR}`, and refuses symlinks.
* **Hooks run unsandboxed at harness trust level.** `htmem` ships hooks **disabled by default.** Opt-in requires reading [`hooks/README.md`](hooks/README.md) and pasting recipes yourself.

If you find a vulnerability, follow [`SECURITY.md`](SECURITY.md). 72-hour ack, 30-day fix SLA for HIGH/CRITICAL.

## Roadmap

| Version | Theme | Status |
|---|---|---|
| 0.1.0 | Skills + commands + templates + MCP + opt-in hooks + CI | shipped |
| 0.2.0 | Anthropic + OpenAI [MCP Apps Extension](https://inkeep.com/blog/anthropic-openai-mcp-apps-extension) compatibility — htmem artifacts as `ui://` resources renderable in Claude desktop and ChatGPT side-pane | planned |
| 0.3.0 | Cosign signed releases + provenance attestation + automated security advisories | planned |
| 0.4.0 | Local sqlite full-text index over htmem artifacts (no embedding model required) | planned |
| 0.5.0 | First-party browser-agent integration (Stagehand / browser-use accessibility-tree extraction of htmem artifacts) | exploratory |

Suggest a feature: [open an issue](https://github.com/droggy992/htmem/issues).

## Examples

See [`examples/`](examples/) for fully-rendered artifacts:

* [`examples/01-simple-memory.html`](examples/01-simple-memory.html) — minimum-viable memory artifact.
* [`examples/02-decision-doc.html`](examples/02-decision-doc.html) — architecture decision record with sign-off ledger.
* [`examples/03-comms-thread.html`](examples/03-comms-thread.html) — multi-agent handoff record.

Run `/htm-hub examples` after installing the plugin to view all three in the hardened render server.

## Related work and prior art

* **Authoring-context-html** (Anthropic skill, 2026) — htmem's intellectual ancestor; we narrow the design to "files-as-memory" rather than dashboards.
* **interactive-doc** (community skill, 2026) — feedback-required interactive HTML docs; htmem borrows the data-island pattern.
* **HtmlRAG** (Tan et al., Renmin U. + Baichuan, arXiv 2411.02959) — empirical evidence that HTML beats plain-text for RAG.
* **MCP Apps Extension** (Anthropic + OpenAI, Nov 2025) — the standard htmem will align with in v0.2.
* **Thariq Shihipar** — *Unreasonable Effectiveness of HTML* (May 2026); see [Simon Willison's writeup](https://simonwillison.net/2026/May/8/unreasonable-effectiveness-of-html/).

## License

[Apache-2.0](LICENSE) — explicit patent grant, retaliation clause, provenance-friendly. Forks are welcome; please re-anchor the examples and rotate `CODEOWNERS` before publishing yours.

---

If this plugin saves you the cost of designing your own memory format, hit ⭐ on [github.com/droggy992/htmem](https://github.com/droggy992/htmem). It's the only signal the maintainer reads.
