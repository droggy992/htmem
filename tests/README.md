# tests/

Regression tests for security-critical invariants. Every test here corresponds to a Loop-1, Loop-2, or Loop-3 audit finding that, if it ever regresses, would break the threat model documented in [`../docs/threat-model.md`](../docs/threat-model.md).

These tests are intentionally written without any test framework (no `pytest`, no `unittest`). They run with `python tests/<name>.py` and exit non-zero on failure. CI invokes them directly so a regression breaks the build.

## Current tests

| File | Defends |
| --- | --- |
| `test_forged_manifest_under_dropped_subtree.py` | Loop-2 finding **G01** (CRITICAL). Sanitizer must NOT capture `<script id="htmem-manifest">` content when that script lives inside (or as a sibling of) a dropped dangerous tag (`<iframe>`, `<object>`, `<applet>`, `<embed>`, `<frame>`, `<frameset>`, `<base>`). |
| `test_multi_manifest_smuggling.py` | Loop-2 follow-up. Validator must refuse files that contain zero or more than one `<script id="htmem-manifest">` element. Real htmem files have exactly one. |

## How to run all tests locally

```bash
for t in tests/test_*.py; do
  python "$t" || exit 1
done
```

CI wires this into `.github/workflows/ci.yml` so a regression on `main` breaks the build.
