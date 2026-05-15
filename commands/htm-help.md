---
description: Print the htmem onboarding for the current session — what htmem is, the three operations, the hard rules, where to look for more. Usage — /htm-help
argument-hint: (no arguments)
---

# /htm-help — print the htmem onboarding

The user invoked `/htm-help`. Read `${CLAUDE_PLUGIN_ROOT}/AGENTS.md` and reply with its content, lightly compressed where helpful, plus this footer:

```text
Full onboarding:  ${CLAUDE_PLUGIN_ROOT}/AGENTS.md
Format spec:      ${CLAUDE_PLUGIN_ROOT}/docs/format-spec.md
Threat model:     ${CLAUDE_PLUGIN_ROOT}/docs/threat-model.md
Public landing:   https://droggy992.github.io/htmem/
Source:           https://github.com/droggy992/htmem
```

Do **not** auto-invoke any other htmem skill from this command. `/htm-help` is read-only and produces no side effects.
