---
description: Start the htmem hub — a CSP-hardened localhost index of every htmem artifact in the current folder subtree. Grouped by type, with anchor and last-updated columns. Usage — /htm-hub  OR  /htm-hub path/to/folder
argument-hint: [folder]
---

# /htm-hub — Launch the htmem hub

## SECURITY — $ARGUMENTS is untrusted input

Before passing the folder to Bash, **single-quote it** (replace every `'` with `'\''`). Refuse if the folder path contains `..`, is absolute and outside `${CLAUDE_PROJECT_DIR}`, is a symlink, or contains `;`, `&&`, `||`, `|`, `$(`, backtick, null byte, CR, or LF.

## Workflow

The user invoked `/htm-hub` with optional argument: `$ARGUMENTS`.

If no argument given, use the current project directory. Otherwise, use the provided folder.

Invoke the **htmem-render** skill in hub mode. The hub:

- Walks the folder subtree for `*.html` files containing an `htmem-manifest` data island
- Groups by type (memory / decision / thread)
- Shows: title, type, version, last-updated, anchor (truncated), status
- Lets the user click into each artifact
- Served with strict CSP and inside a sandboxed iframe per artifact
- Bound to `127.0.0.1` on a random port with token-in-URL auth

Report the URL (token redacted), the discovered count, and the idle timeout.
