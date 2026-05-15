---
description: 'Create a new htmem HTML memory, decision doc, or comms thread. Usage: /htmem:htm-new memory "Title"  or  /htmem:htm-new decision "Title"  or  /htmem:htm-new thread "Title"'
argument-hint: '<type: memory|decision|thread> "<title>"'
---

# /htm-new — Create a new htmem artifact

## SECURITY — $ARGUMENTS is untrusted input

Before passing any part of `$ARGUMENTS` to a Bash command, **single-quote it** (replace every `'` in the value with `'\''`). Never use `$ARGUMENTS` inside `eval`, `bash -c`, backticks, or `$(...)`. If the path argument contains any of `;`, `&&`, `||`, `|`, `$(`, backtick, `..`, null byte, CR, or LF, refuse and ask the user to re-enter a plain path.

## Workflow

The user invoked `/htm-new` with arguments: `$ARGUMENTS`.

Parse the arguments:
- First word: type (one of `memory`, `decision`, `thread`)
- Rest: title (may be quoted)

If parsing fails or type is missing, ask the user to retry with the correct form.

Then invoke the **htmem-write** skill (it has the full workflow). Pass:
- `type` = parsed type
- `title` = parsed title
- `path` = default `./htmem/<type>-<slug>-<YYYY-MM-DD>.html`

After the artifact is written and validated, **auto-open it in the browser** by chaining into the htmem-render skill — unless the user's prompt contains a phrase like "don't open", "no render", "skip browser", or the argument list contains `--no-open`. Auto-open uses the CSP-hardened localhost server and the iframe-sandboxed view; never fall back to `file://`.

Report this final shape:

```text
Created htmem artifact.
  File:   <path>
  Anchor: sha256:<first-16-chars>
  Opened: http://127.0.0.1:<port>/view/<rel>?t=<first12>…
```

If auto-open was skipped or failed, replace the `Opened:` line with `Render: /htm-render <path>`.
