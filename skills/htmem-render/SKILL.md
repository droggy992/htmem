---
name: htmem-render
description: Open an htmem HTML memory artifact (or a folder of them as a hub) in the user's browser via a CSP-hardened localhost render server with sandboxed iframes. ONLY fire when (a) the user explicitly invokes `/htm-render` or `/htm-hub`, (b) the user names a specific path that contains an `htmem-manifest` data island and asks to view it, or (c) the user writes the literal word "htmem" alongside a render intent. Do NOT auto-fire on generic verbs ("show me", "open", "preview") — those are too broad. NEVER instruct the user to open the file via `file://` — that bypasses CSP and exposes the browser to XSS / CSS exfiltration / DNS rebinding vectors against sibling files. Always route through the render server, which binds to 127.0.0.1, picks a random high port, requires a 128-bit token in the URL, and sandboxes each artifact inside an iframe with `sandbox` attribute and no `allow-scripts`.
allowed-tools: Bash, Glob
---

# htmem-render — CSP-Hardened Localhost Render Server

## What this skill does

Starts (or reuses) the htmem render server on `127.0.0.1` at a random high port, then opens the user's default browser to the chosen artifact. Every artifact is served with strict CSP headers and embedded inside a `<iframe sandbox>` so even if an artifact contained inline scripts, they would not execute.

## Why not file://

Opening an HTML file with `file://` bypasses every CSP defense:

- `<meta http-equiv="Content-Security-Policy">` cannot set `frame-ancestors`, `sandbox`, or `report-uri` (MDN).
- Chromium under `file://` allows fetching sibling files in the same directory.
- DNS-rebinding attacks can reach `127.0.0.1` from a separately-opened malicious page.
- CVE-2026-22813 (OpenCode) and CVE-2026-22792 (5ire) are the recent in-the-wild precedent.

The render server fixes all of this by serving real HTTP with real headers.

## Workflow

### 0. Validate the path (mandatory)

Refuse if the user-supplied path:
- Contains `..` segments.
- Is absolute and outside `${CLAUDE_PROJECT_DIR}`.
- Is a symbolic link.
- Refers to a folder when single-file mode was requested, or vice versa.

Single-quote the validated path before passing to Bash (replace `'` → `'\''`).

### 1. Check whether the server is already running

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/render_server.py" --status
```

Returns one of: `RUNNING <port> <token>` or `STOPPED`.

### 2. Start the server if needed

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/render_server.py" --serve "$PWD"
```

This:

- Binds `127.0.0.1` on a random port in range 49152–65535.
- Picks a 128-bit token, embeds it in the URL: `http://127.0.0.1:<port>/?t=<token>`.
- Sets HTTP headers on every response:
  - `Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-<rand>'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'; require-trusted-types-for 'script'; connect-src 'self'; img-src 'self' data:`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: no-referrer`
  - `Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=()`
  - `Cross-Origin-Opener-Policy: same-origin`
  - `Cross-Origin-Embedder-Policy: require-corp`
- Enforces `Host` header is `127.0.0.1:<port>` or `localhost:<port>` (DNS-rebinding mitigation).
- Refuses CORS — `Access-Control-Allow-Origin` is never sent.
- Exits after 15 minutes of idleness, or on Ctrl-C, or on session end.
- Logs every request to `${CLAUDE_PLUGIN_DATA}/render-server.log` so the user can audit.

Each artifact is delivered inside a wrapper HTML page that uses:

```html
<iframe sandbox src="/raw/<path>?t=<token>"></iframe>
```

The `sandbox` attribute with no `allow-scripts` means inline `<script>` in the artifact will not run, even though we already strip them in the artifact validation step. Defense in depth.

### 3. Open the browser

```bash
"${CLAUDE_PLUGIN_ROOT}/scripts/render_server.py" --open <path>
```

This sends an HTTP request to the server saying "open this path" — the server then triggers the user's default browser via `webbrowser.open()`. The user never sees the raw `file://` URL.

### 4. Report

Reply with the localhost URL (with token redacted) and a one-line note:

```text
Rendered at http://127.0.0.1:<port>/?t=<redacted>
Server logs:  ${CLAUDE_PLUGIN_DATA}/render-server.log
Idle timeout: 15 min · Ctrl-C to stop early
```

## Hub mode (multiple artifacts)

The hub is a built-in route of the render server, not a separate command. To open it:

```bash
# Start the server (if not already running)
"${CLAUDE_PLUGIN_ROOT}/scripts/render_server.py" --serve "$PWD"

# Hub URL is then:  http://127.0.0.1:<port>/hub?t=<token>
# Get current port + token from --status:
"${CLAUDE_PLUGIN_ROOT}/scripts/render_server.py" --status
```

The `/hub` route serves an index page that lists every `*.html` in the served root containing an `htmem-manifest` data island, grouped by type (memory / decision / thread). The hub page is itself served with the same hardened headers — no CDN, no external resources, no Tailwind, no React.

## What this skill must never do

- Open the file via `file://` (see above).
- Bind to `0.0.0.0` or any non-loopback interface.
- Disable CSP for "convenience".
- Persist the token to disk in plaintext.
- Auto-open the browser without the user-visible token URL.
- Accept inbound connections from other origins (CORS is off).

## When to fall back

If the user is on a host without Python 3.10+ (the render server depends on `http.server` + `urllib`), or the random port range is blocked, report the failure and offer to scaffold a minimal alternative the user can run manually — but **never** suggest `file://`.

## Cross-references

- Sibling: `htmem-write`, `htmem-read`, `htmem-audit`
- Threat model: `${CLAUDE_PLUGIN_ROOT}/docs/threat-model.md`
- Reference: render server source at `${CLAUDE_PLUGIN_ROOT}/scripts/render_server.py`
