# htmem hooks — opt-in only

**Default state:** every event hook is disabled. `hooks/hooks.json` ships empty.

We ship hooks disabled because hook commands run **unsandboxed at the harness's trust level** — they can execute arbitrary shell, read your filesystem, and reach the network. A compromised hook is a one-line RCE. Plugin hooks were the #1 attack vector in the 2025-26 plugin CVE cohort (PromptArmor analysis, VentureBeat 2025).

## Opt-in process (always do this)

1. **Read the script.** Before enabling any hook, open the script file in `hooks/scripts/` and read every line.
2. **Read the event docs.** Skim the [Claude Code hooks reference](https://code.claude.com/docs/en/hooks) for the event you're wiring.
3. **Enable in `hooks/hooks.json`.** Paste only the entry for the event you want.
4. **Restart Claude Code** for hook changes to take effect.

## Vetted hook recipes

The recipes below are tested and minimal. Each runs a self-contained script that ships with the plugin and is reviewed in the audit pipeline.

### 1. PostToolUse snapshot — auto-write an htmem memory after Write/Edit

Snapshots the file you just edited into an htmem memory artifact under `htmem/snapshots/`. Useful for archival workflows.

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "python \"${CLAUDE_PLUGIN_ROOT}/hooks/scripts/snapshot.py\""
          }
        ]
      }
    ]
  }
}
```

**Tradeoffs:** writes a file on every successful Write/Edit (cheap, but disk grows). Refuses to snapshot files outside `${CLAUDE_PROJECT_DIR}` and skips files matching `.gitignore`.

### 2. SessionStart — preload existing htmem context

Lists the htmem artifacts in the project and prints a one-line digest so the new session knows what canonical memory exists. Read-only.

```json
{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python \"${CLAUDE_PLUGIN_ROOT}/hooks/scripts/list_artifacts.py\""
          }
        ]
      }
    ]
  }
}
```

**Tradeoffs:** read-only, exits within ~1s on typical projects. Skips folders > 5 GB.

### 3. PreToolUse audit gate — refuse writes that would overwrite a signed decision

Inspects the target path of a pending Write/Edit. If it's an htmem `decision` artifact with status `accepted`, refuses the write and asks the user to bump the version + supersede instead.

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "python \"${CLAUDE_PLUGIN_ROOT}/hooks/scripts/gate_signed_decision.py\""
          }
        ]
      }
    ]
  }
}
```

**Tradeoffs:** adds ~50 ms per Write/Edit. Exits with code 0 (allow) or 2 (block + reason).

## What this folder does NOT ship

- **Hooks that auto-approve permission requests.** Disallowed by design.
- **Hooks that pipe HTTP responses into a shell.** Disallowed by design.
- **`Bash`-matching hooks that run on every shell command.** Too broad; high blast radius.
- **`UserPromptSubmit` mutators.** They would silently rewrite user input — out of scope.

## Auditing hooks before enabling

Run `claude plugin details htmem` to see exactly which hooks the plugin currently contributes. If the output shows any hooks beyond what you opted in to, something is wrong — re-clone the plugin, run gitleaks against the tree, and file a report at https://github.com/droggy992/htmem/security/advisories.

## Removing all hooks

Replace `hooks/hooks.json` content with:

```json
{ "hooks": {} }
```

…and restart Claude Code.
