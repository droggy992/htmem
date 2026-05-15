#!/usr/bin/env python3
"""
Minimal JSON Schema validator covering the subset used by htmem.

Supports: type, required, additionalProperties (bool), properties, items, enum,
const, pattern, minLength, maxLength, minItems, maxItems, format (date,
date-time, uri), oneOf (limited).

Zero external dependencies. Python 3.10+ stdlib only.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


class SchemaError(Exception):
    pass


_TYPE_CHECKS = {
    "string": lambda v: isinstance(v, str),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
    "array": lambda v: isinstance(v, list),
    "object": lambda v: isinstance(v, dict),
}


_FORMAT_CHECKS = {
    "date": lambda v: _check_date(v),
    "date-time": lambda v: _check_datetime(v),
    "uri": lambda v: _check_uri(v),
}


def _check_date(v: Any) -> bool:
    if not isinstance(v, str):
        return False
    try:
        datetime.strptime(v, "%Y-%m-%d")
        return True
    except ValueError:
        return False


def _check_datetime(v: Any) -> bool:
    if not isinstance(v, str):
        return False
    try:
        datetime.fromisoformat(v.replace("Z", "+00:00"))
        return True
    except (ValueError, TypeError):
        return False


def _check_uri(v: Any) -> bool:
    if not isinstance(v, str):
        return False
    try:
        parsed = urlparse(v)
        return bool(parsed.scheme) and parsed.scheme.lower() in {"http", "https", "mailto"}
    except ValueError:
        return False


def _check_type(value: Any, t: str | list[str]) -> bool:
    if isinstance(t, str):
        return _TYPE_CHECKS.get(t, lambda v: False)(value)
    if isinstance(t, list):
        return any(_check_type(value, x) for x in t)
    return False


def _resolve_ref(ref: str, root: dict[str, Any]) -> dict[str, Any] | None:
    if not ref.startswith("#/"):
        return None
    parts = ref[2:].split("/")
    node: Any = root
    for p in parts:
        if not isinstance(node, dict) or p not in node:
            return None
        node = node[p]
    return node if isinstance(node, dict) else None


def validate(value: Any, schema: dict[str, Any], path: str = "$", root: dict[str, Any] | None = None) -> list[str]:
    errors: list[str] = []
    if root is None:
        root = schema

    if "$ref" in schema:
        target = _resolve_ref(schema["$ref"], root)
        if target is None:
            errors.append(f"{path}: cannot resolve $ref {schema['$ref']!r}")
            return errors
        errors.extend(validate(value, target, path, root))
        return errors

    if "type" in schema and not _check_type(value, schema["type"]):
        errors.append(f"{path}: expected type {schema['type']!r}, got {type(value).__name__}")
        return errors

    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: must equal const {schema['const']!r}, got {value!r}")

    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: must be one of {schema['enum']!r}, got {value!r}")

    if isinstance(value, str):
        if "pattern" in schema:
            if not re.search(schema["pattern"], value):
                errors.append(f"{path}: does not match pattern {schema['pattern']!r}")
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{path}: shorter than minLength {schema['minLength']}")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{path}: longer than maxLength {schema['maxLength']}")
        if "format" in schema:
            fmt = schema["format"]
            check = _FORMAT_CHECKS.get(fmt)
            if check and not check(value):
                errors.append(f"{path}: not a valid {fmt}")

    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{path}: fewer than minItems {schema['minItems']}")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path}: more than maxItems {schema['maxItems']}")
        if "items" in schema:
            for i, item in enumerate(value):
                errors.extend(validate(item, schema["items"], f"{path}[{i}]", root))

    if isinstance(value, dict):
        props = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        required = schema.get("required", [])

        for k in required:
            if k not in value:
                errors.append(f"{path}.{k}: required property missing")

        for k, v in value.items():
            if k in props:
                errors.extend(validate(v, props[k], f"{path}.{k}", root))
            else:
                if additional is False:
                    errors.append(f"{path}.{k}: additional property not allowed")
                elif isinstance(additional, dict):
                    errors.extend(validate(v, additional, f"{path}.{k}", root))

    if "oneOf" in schema:
        matched = sum(1 for s in schema["oneOf"] if not validate(value, s, path, root))
        if matched != 1:
            errors.append(f"{path}: must match exactly one of oneOf (matched {matched})")

    if "allOf" in schema:
        for s in schema["allOf"]:
            errors.extend(validate(value, s, path, root))

    if "not" in schema:
        sub_errs = validate(value, schema["not"], path, root)
        if not sub_errs:
            errors.append(f"{path}: matched a 'not' schema (forbidden form)")

    return errors


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: schema_validator.py <schema.json> <instance.json>", file=sys.stderr)
        return 2
    schema_path, inst_path = Path(argv[0]), Path(argv[1])
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    instance = json.loads(inst_path.read_text(encoding="utf-8"))
    errs = validate(instance, schema)
    if not errs:
        print("OK")
        return 0
    for e in errs:
        print(e)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
