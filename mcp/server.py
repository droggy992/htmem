#!/usr/bin/env python3
"""
htmem MCP server — stdio JSON-RPC bridge exposing htmem artifacts as MCP
resources and a small set of MCP tools to read / audit them safely.

Why MCP: cross-agent reach. Any MCP-aware client (Claude Code, ChatGPT
desktop, Cursor, Cline, Continue) can consume htmem artifacts as first-class
resources without ad-hoc file reads. Critically, the server only exposes
content **after** running it through the same sanitizer + validator the
in-process pipeline uses, so prompt injection inside an artifact cannot reach
the client.

Implementation: stdlib-only stdio JSON-RPC matching the MCP 2025-06-18 spec
(initialize, resources/list, resources/read, tools/list, tools/call). No
PyPI deps — keeps the supply-chain attack surface at zero.

Sandbox:
  - Refuses any path outside HTMEM_PROJECT_DIR (or cwd if unset).
  - Refuses symlinks.
  - Caps per-island JSON size at 1 MB.
  - Wraps free-text fields in <untrusted_content> sentinels.

stdin / stdout protocol: one JSON-RPC message per line ("ndjson"). stderr is
free for diagnostic logging.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import traceback
from pathlib import Path

_HERE = Path(__file__).resolve().parent
SCRIPTS_DIR = (_HERE.parent / "scripts").resolve()
sys.path.insert(0, str(SCRIPTS_DIR))

from read_memory import safe_read  # type: ignore
from audit import audit_file as audit_one  # type: ignore


PROTOCOL_VERSION = "2025-06-18"


def _project_root() -> Path:
    env = os.environ.get("HTMEM_PROJECT_DIR")
    if env:
        return Path(env).resolve()
    return Path.cwd().resolve()


def _safe_resolve(rel: str) -> Path | None:
    """Resolve a project-relative path safely. Refuses .., symlinks, outside."""
    if not rel or "\x00" in rel:
        return None
    root = _project_root()
    candidate = (root / rel).resolve() if not Path(rel).is_absolute() else Path(rel).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    if candidate.is_symlink():
        return None
    if not candidate.is_file():
        return None
    if candidate.suffix.lower() != ".html":
        return None
    return candidate


def _list_artifacts() -> list[Path]:
    root = _project_root()
    out: list[Path] = []
    for p in root.rglob("*.html"):
        try:
            if p.is_symlink():
                continue
            with p.open("rb") as f:
                head = f.read(1024 * 1024)
            if b"htmem-manifest" in head:
                out.append(p)
        except OSError:
            continue
        if len(out) > 10000:
            break
    return sorted(out)


# ----- JSON-RPC dispatch -----

def _result(req_id, value):
    return {"jsonrpc": "2.0", "id": req_id, "result": value}


def _error(req_id, code, message):
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def handle_initialize(req_id, params):
    return _result(req_id, {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            "resources": {"listChanged": False, "subscribe": False},
            "tools": {"listChanged": False},
        },
        "serverInfo": {"name": "htmem", "version": "0.1.0"},
    })


def handle_resources_list(req_id, params):
    items = []
    # Universal onboarding resource — exposed to every MCP client so any
    # agent can learn how to use htmem without leaving its session.
    plugin_root = os.environ.get("HTMEM_PLUGIN_ROOT")
    if plugin_root:
        agents_md = Path(plugin_root) / "AGENTS.md"
        if agents_md.is_file():
            items.append({
                "uri": "htmem://help/agents",
                "name": "AGENTS.md — htmem onboarding for LLM agents",
                "description": "Read this first if you're an AI agent that just connected. Explains the three operations (write/read/audit), the hard rules, and the file layout.",
                "mimeType": "text/markdown",
            })
    root = _project_root()
    for p in _list_artifacts():
        rel = p.relative_to(root).as_posix()
        items.append({
            "uri": f"htmem://{rel}",
            "name": p.name,
            "description": f"htmem artifact at {rel}",
            "mimeType": "application/json",
        })
    return _result(req_id, {"resources": items})


def handle_resources_read(req_id, params):
    uri = (params or {}).get("uri", "")
    if not uri.startswith("htmem://"):
        return _error(req_id, -32602, f"unsupported uri scheme: {uri!r}")
    rel = uri[len("htmem://"):]
    # Special-case the universal onboarding resource.
    if rel == "help/agents":
        plugin_root = os.environ.get("HTMEM_PLUGIN_ROOT")
        if not plugin_root:
            return _error(req_id, -32603, "HTMEM_PLUGIN_ROOT not set; cannot serve onboarding")
        agents_md = Path(plugin_root) / "AGENTS.md"
        if not agents_md.is_file():
            return _error(req_id, -32603, "AGENTS.md not found in plugin root")
        return _result(req_id, {
            "contents": [{
                "uri": uri,
                "mimeType": "text/markdown",
                "text": agents_md.read_text(encoding="utf-8"),
            }]
        })
    target = _safe_resolve(rel)
    if not target:
        return _error(req_id, -32602, f"path resolution refused: {rel!r}")
    result = safe_read(target)
    return _result(req_id, {
        "contents": [{
            "uri": uri,
            "mimeType": "application/json",
            "text": json.dumps(result, ensure_ascii=False),
        }]
    })


def handle_tools_list(req_id, params):
    return _result(req_id, {"tools": [
        {
            "name": "htmem_read",
            "description": "Safely read an htmem artifact through the sanitizer + validator + sentinel-wrap pipeline. Path must be relative to the project root.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "required": ["path"],
                "properties": {
                    "path": {"type": "string", "description": "Project-relative path, must end in .html"}
                },
            },
        },
        {
            "name": "htmem_audit",
            "description": "Run the 20-check deep audit on an htmem artifact (or the project root for a full sweep).",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "path": {"type": "string", "description": "Project-relative path. Default: project root."},
                },
            },
        },
        {
            "name": "htmem_list",
            "description": "List all htmem artifacts under the project root.",
            "inputSchema": {"type": "object", "additionalProperties": False, "properties": {}},
        },
    ]})


def handle_tools_call(req_id, params):
    name = (params or {}).get("name", "")
    args = (params or {}).get("arguments") or {}
    if name == "htmem_list":
        root = _project_root()
        rels = [p.relative_to(root).as_posix() for p in _list_artifacts()]
        return _result(req_id, {"content": [{"type": "text", "text": json.dumps(rels, indent=2)}]})
    if name == "htmem_read":
        rel = args.get("path", "")
        target = _safe_resolve(rel)
        if not target:
            return _error(req_id, -32602, f"path resolution refused: {rel!r}")
        result = safe_read(target)
        return _result(req_id, {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False, indent=2)}]})
    if name == "htmem_audit":
        rel = args.get("path", "")
        if rel:
            target = _safe_resolve(rel)
            if not target:
                return _error(req_id, -32602, f"path resolution refused: {rel!r}")
            paths = [target]
        else:
            paths = _list_artifacts()
        results = [audit_one(p) for p in paths]
        return _result(req_id, {"content": [{"type": "text", "text": json.dumps(results, ensure_ascii=False, indent=2)}]})
    return _error(req_id, -32601, f"unknown tool: {name!r}")


HANDLERS = {
    "initialize": handle_initialize,
    "resources/list": handle_resources_list,
    "resources/read": handle_resources_read,
    "tools/list": handle_tools_list,
    "tools/call": handle_tools_call,
    "ping": lambda req_id, params: _result(req_id, {}),
    "notifications/initialized": lambda req_id, params: None,
}


def main() -> int:
    # Line-buffered stdio.
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError as e:
            sys.stderr.write(f"htmem-mcp: bad json: {e}\n")
            sys.stderr.flush()
            continue
        method = msg.get("method", "")
        req_id = msg.get("id")
        params = msg.get("params")
        if method in HANDLERS:
            try:
                resp = HANDLERS[method](req_id, params)
            except Exception as e:
                sys.stderr.write(f"htmem-mcp: handler {method} crashed: {e}\n{traceback.format_exc()}\n")
                sys.stderr.flush()
                resp = _error(req_id, -32603, f"internal error in {method}")
            # Notifications produce no response
            if resp is None:
                continue
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()
        else:
            if req_id is not None:
                sys.stdout.write(json.dumps(_error(req_id, -32601, f"unknown method: {method!r}"), ensure_ascii=False) + "\n")
                sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
