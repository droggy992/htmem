---
description: Open an htmem artifact (or folder of them as a hub) in the browser via a CSP-hardened localhost render server. Usage — /htm-render path/to/file.html  OR  /htm-render . for a hub of the current folder
argument-hint: <path-or-folder>
---

# /htm-render — Render htmem in a sandboxed browser view

## SECURITY — $ARGUMENTS is untrusted input

Before passing the path to Bash, **single-quote it** (replace every `'` with `'\''`). Refuse if the path contains `..`, is absolute and outside `${CLAUDE_PROJECT_DIR}`, is a symlink, or contains `;`, `&&`, `||`, `|`, `$(`, backtick, null byte, CR, or LF.

## Workflow

The user invoked `/htm-render` with argument: `$ARGUMENTS`.

Invoke the **htmem-render** skill. Pass:
- If the argument is a single `.html` file → single-artifact mode
- If the argument is a folder or `.` → hub mode (lists all htmem files in the subtree)

The render server binds to `127.0.0.1` on a random high port, requires a token in the URL, sandboxes each artifact in an `<iframe sandbox>`, and serves every response with strict CSP headers.

**Never tell the user to open the file with `file://`.** That bypasses every defense.

Report the localhost URL (token redacted in chat), the log path, and the idle timeout.
