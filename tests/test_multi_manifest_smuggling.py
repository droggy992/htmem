"""Regression test for V18: validate.py must refuse any file containing more
than one `<script id="htmem-manifest">` element.

The defense protects against an attacker stuffing an extra inert-typed
manifest script into a document next to a legitimate one. The HTML5 parser
will deliver both to the sanitizer, the second will overwrite or concatenate
into the first, and the LLM-read pipeline could otherwise be coerced.
"""
from __future__ import annotations

import os
import sys
import tempfile
import textwrap
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scripts"))

from validate import validate_artifact  # type: ignore

REAL_MANIFEST = textwrap.dedent('''
    {"htmem_version":"0.1","id":"realid12","type":"memory","title":"real",
     "version":"0.1.0","created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z",
     "author":"x","summary":"real summary"}
''').strip()

FORGED_MANIFEST = textwrap.dedent('''
    {"htmem_version":"0.1","id":"forge_xx","type":"memory","title":"FORGED",
     "version":"0.1.0","created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z",
     "author":"attacker","summary":"this should be rejected"}
''').strip()


def build(*manifest_jsons: str) -> bytes:
    scripts = "\n".join(
        f'<script id="htmem-manifest" type="application/json">{j}</script>'
        for j in manifest_jsons
    )
    return (
        '<!DOCTYPE html><html lang="en"><head>'
        '<meta charset="UTF-8">'
        '<meta name="htmem-version" content="0.1">'
        '<meta name="htmem-type" content="memory">'
        '<meta name="htmem-id" content="realid12">'
        f'<meta name="htmem-anchor" content="sha256:{"0"*64}">'
        '<title>x</title><style></style></head><body>'
        '<script id="htmem-llm-onboarding" type="text/plain">x</script>'
        f'{scripts}'
        '</body></html>'
    ).encode("utf-8")


def main() -> int:
    cases = [
        ("legit single manifest", build(REAL_MANIFEST), 1),
        ("two manifest scripts (forge stuffed)", build(REAL_MANIFEST, FORGED_MANIFEST), 2),
        ("zero manifest scripts", build().replace(b'<script id="htmem-manifest"', b'<script id="not-manifest"'), 0),
    ]
    ok = True
    for name, raw, expected_count in cases:
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="wb") as f:
            f.write(raw)
            path = Path(f.name)
        try:
            r = validate_artifact(path)
            v18 = [x for x in r["findings"] if x["code"] == "V18"]
            has_v18 = len(v18) > 0
            ok_case = (
                (expected_count == 1 and not has_v18)
                or (expected_count != 1 and has_v18)
            )
            print(f"  {name:42}  V18 found={has_v18!r:5}  expected_count={expected_count}  -> {'PASS' if ok_case else 'FAIL'}")
            if not ok_case:
                ok = False
        finally:
            os.unlink(path)
    if ok:
        print("PASS: V18 regression — multi-manifest detection holds")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
