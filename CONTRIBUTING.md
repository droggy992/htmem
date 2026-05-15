# Contributing to htmem

Thanks for considering a contribution. `htmem` is a security-critical plugin (it writes files an agent will later read as instructions), so the bar for merges is higher than a typical OSS project.

## Before you open a PR

1. **Run the full local check.**
   ```bash
   python scripts/new_memory.py memory "PR smoke test" --out tmp/smoke.html
   python scripts/validate.py tmp/smoke.html
   python scripts/audit.py tmp/smoke.html
   python scripts/read_memory.py tmp/smoke.html >/dev/null
   ```
2. **Run gitleaks locally.**
   ```bash
   gitleaks detect --config .gitleaks.toml
   ```
3. **Re-anchor any example you changed.**
   ```bash
   python scripts/anchor.py emit examples/<file>.html
   ```

## What we accept

- Bug fixes with a regression test (add a fixture in `tests/` if you create that folder).
- Security hardening (broader sanitizer allow-list pruning, additional audit checks).
- New skills or commands that follow the trigger-discipline rules (see existing SKILL.md files — narrow descriptions only).
- Documentation that improves the format spec or threat model.

## What we reject

- New runtime dependencies. `htmem` is zero-deps by design.
- Broadening any SKILL `description` field beyond htmem-specific triggers.
- Hooks that ship enabled by default.
- Render-server changes that bind anything other than `127.0.0.1`.
- "Performance" rewrites that touch `scripts/sanitize.py` or `scripts/render_server.py` without a paired audit report.

## CODEOWNERS

Touching any of these paths requires `@droggy992` review:

- `.claude-plugin/`
- `hooks/`
- `.github/`
- `scripts/sanitize.py`, `scripts/render_server.py`, `scripts/anchor.py`
- `mcp/`
- `SECURITY.md`, `LICENSE`

## Security findings

Use the private advisory channel described in [`SECURITY.md`](SECURITY.md). Public PRs that fix a security bug should reference the advisory ID after the embargo lifts.

## DCO

Sign your commits (`git commit -s`). By signing you assert that your contribution complies with the [Developer Certificate of Origin](https://developercertificate.org/).

## License

Contributions are licensed under Apache-2.0 (same as the project). See [`LICENSE`](LICENSE).
