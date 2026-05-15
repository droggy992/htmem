# Security policy

`htmem` ships code that runs locally on a user's machine, manipulates HTML, and exposes an MCP server. Disclosure quality matters; please follow this policy.

## Supported versions

Only the latest **published tag** receives security fixes. `main` HEAD is unstable and is not a supported install target — never `/plugin marketplace add` against an unpinned `main`.

## Reporting a vulnerability

**Do not** open public issues for security findings.

1. Open a private advisory at <https://github.com/droggy992/htmem/security/advisories/new>. This goes to the maintainer and an embargo discussion is opened.
2. Or, email `ognjen.vucurevic@gmail.com` with subject `[htmem-security]`. PGP is not required; if you need encryption, request a key in the first message and one will be issued.

You will receive:

| Step | SLA |
| --- | --- |
| Acknowledgement of receipt | 72 hours |
| First triage decision (in scope / out of scope / need-more-info) | 7 days |
| Fix landed in `main` | 30 days for HIGH/CRITICAL, 60 days for MEDIUM |
| Public advisory + CVE (if applicable) | 90 days from receipt, or sooner if a fix is available |

## In-scope threats

- **Prompt injection that bypasses the LLM-read sanitizer.** Any input that survives `scripts/sanitize.py` + `scripts/read_memory.py` and lands as model-trusted instruction.
- **Anchor verification bypass.** Any way to tamper with an htmem artifact without `htm-audit` or `validate.py` detecting it.
- **Render-server escape.** Any way to bypass CSP, escape the iframe sandbox, reach a non-loopback address, or leak the URL token.
- **MCP-server escape.** Any way to read files outside `${HTMEM_PROJECT_DIR}`, traverse symlinks, or exfiltrate.
- **Hook trust violation.** Any default-on hook beyond what `hooks/hooks.json` declares, or any opt-in hook that does more than its `hooks/README.md` recipe claims.
- **Supply chain compromise.** Tampered tags, missing provenance, unsigned releases, or any dependency added without `CODEOWNERS` review.

## Out-of-scope

- Brute-forcing the URL token of an already-running render server from a co-tenant on the same host.
- Local privilege escalation beyond what the user account already grants.
- Findings against unpublished branches.
- Bug reports without a reproducer.

## What we will do

- Land a fix with a CHANGELOG entry crediting the reporter (unless you request anonymity).
- Publish a GitHub Security Advisory and request a CVE for CRITICAL findings.
- Sign the next release tag with sigstore cosign and emit a GitHub provenance attestation.

## What we will not do

- Pay bug bounties (the plugin is open-source and self-funded).
- Run a permanent embargo. Public advisories follow the 90-day window above.
- Accept "AI told me this is a vulnerability" reports without a reproducer.

## Hardening guide for maintainers

If you fork `htmem`, before publishing your fork:

- Replace the `author` and `owner` fields in `.claude-plugin/{plugin,marketplace}.json` with your own contact path.
- Rotate / remove any default account references in `.github/CODEOWNERS`.
- Re-anchor `examples/*.html` so `examples/*.html.sha256` matches your tree.
- Re-run `python scripts/audit.py .` after every meaningful change.
- Pin all GitHub Action versions by SHA, not by tag, before enabling `release.yml`.
