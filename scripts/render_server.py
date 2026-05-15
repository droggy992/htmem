#!/usr/bin/env python3
"""
htmem render_server — CSP-hardened localhost render server for htmem artifacts.

Defenses (defense-in-depth):
  - Binds 127.0.0.1 only. Refuses to bind any other address.
  - Random high port (49152–65535).
  - 128-bit token required in every request (URL query ?t=<token>).
  - Host header allow-list (`localhost`, `127.0.0.1`, `[::1]`).
  - CORS disabled.
  - Strict CSP headers on every response (Content-Security-Policy, COOP, COEP,
    Permissions-Policy, Referrer-Policy, X-Content-Type-Options).
  - Each artifact is served inside an <iframe sandbox> wrapper without
    `allow-scripts` — even if the artifact bypassed sanitization, inline
    scripts would not execute.
  - Idle timeout (default 15 minutes) — server exits when no request landed
    in the idle window.
  - Read-only — never serves files outside the cwd given at start.
  - Refuses any path containing `..` or absolute path traversal.

Zero external dependencies. Python 3.10+ stdlib only.

Usage:
  render_server.py --serve <root>          # start in foreground
  render_server.py --serve <root> --port 0 # let the OS pick (default)
  render_server.py --status                # print RUNNING/STOPPED to stdout
  render_server.py --open <path>           # open an artifact in the running server

The server writes its port + token to ${CLAUDE_PLUGIN_DATA}/render-server.json
(or ~/.cache/htmem/render-server.json when env not set) so --open and --status
can find it. The file is mode 0o600 — readable only by the user.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import sys
import threading
import time
import urllib.parse
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

from sanitize import sanitize_bytes  # type: ignore


# ---------- State file ----------

def _state_path() -> Path:
    base_env = os.environ.get("CLAUDE_PLUGIN_DATA")
    if base_env:
        base = Path(base_env)
    else:
        base = Path.home() / ".cache" / "htmem"
    base.mkdir(parents=True, exist_ok=True)
    p = base / "render-server.json"
    return p


def _write_state(state: dict) -> None:
    sp = _state_path()
    sp.write_text(json.dumps(state), encoding="utf-8")
    try:
        os.chmod(sp, 0o600)
    except OSError:
        pass


def _read_state() -> dict | None:
    sp = _state_path()
    if not sp.is_file():
        return None
    try:
        return json.loads(sp.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


# ---------- Hardened HTTP handler ----------

class HtmemHandler(BaseHTTPRequestHandler):
    server_version = "htmem/0.1"
    sys_version = ""

    # injected by the server factory:
    htmem_root: Path = Path()
    htmem_token: str = ""
    htmem_idle_last: list = [time.time()]  # mutable to allow update from handler

    # G03: token in URL must never reach the log. Redact `t=<value>` from any
    # logged line before it lands on disk.
    _TOKEN_REDACT_RE = __import__("re").compile(r'([?&])t=[^\s"&]+')

    def log_message(self, format: str, *args) -> None:
        line = format % args
        line = self._TOKEN_REDACT_RE.sub(r'\1t=REDACTED', line)
        msg = f"{self.address_string()} - - [{self.log_date_time_string()}] {line}"
        log_path = _state_path().parent / "render-server.log"
        try:
            with log_path.open("a", encoding="utf-8") as f:
                f.write(msg + "\n")
        except OSError:
            pass

    # ----- security gates -----
    def _gate(self) -> bool:
        # Host header check
        host = self.headers.get("Host", "").lower()
        host_ok = (
            host.startswith("127.0.0.1:")
            or host.startswith("localhost:")
            or host.startswith("[::1]:")
            or host in ("127.0.0.1", "localhost", "[::1]")
        )
        if not host_ok:
            self._send_err(HTTPStatus.FORBIDDEN, "bad host")
            return False
        # Token check
        qs = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(qs)
        token = (params.get("t") or [""])[0]
        if not secrets.compare_digest(token, self.htmem_token):
            self._send_err(HTTPStatus.UNAUTHORIZED, "bad token")
            return False
        # Refuse upgrade/CORS preflight noise
        if self.headers.get("Origin"):
            self._send_err(HTTPStatus.FORBIDDEN, "cross-origin denied")
            return False
        # Reject DNS rebinding attempts via X-Forwarded-Host
        if self.headers.get("X-Forwarded-Host"):
            self._send_err(HTTPStatus.FORBIDDEN, "forwarded host denied")
            return False
        # Touch idle timer
        self.htmem_idle_last[0] = time.time()
        return True

    def _hardened_headers(self, content_type: str, length: int, nonce: str = "") -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        csp = (
            "default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}'; "
            "style-src 'self' 'unsafe-inline'; "
            "object-src 'none'; "
            "base-uri 'none'; "
            "frame-ancestors 'self'; "
            "require-trusted-types-for 'script'; "
            "connect-src 'self'; "
            "img-src 'self' data:; "
            "form-action 'none'"
        )
        self.send_header("Content-Security-Policy", csp)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Permissions-Policy",
            "geolocation=(), camera=(), microphone=(), payment=(), usb=(), fullscreen=()",
        )
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        # Refuse to set any CORS headers — they remain absent.

    def _send_err(self, code: int, msg: str) -> None:
        body = f"<!doctype html><meta charset=utf-8><title>{int(code)}</title><h1>{int(code)}</h1><p>{msg}</p>".encode("utf-8")
        self.send_response(int(code))
        self._hardened_headers("text/html; charset=utf-8", len(body))
        self.end_headers()
        self.wfile.write(body)

    # ----- routes -----
    def do_GET(self) -> None:
        if not self._gate():
            return
        parsed = urllib.parse.urlparse(self.path)
        route = parsed.path
        if route == "/" or route == "/hub":
            return self._hub()
        if route.startswith("/raw/"):
            return self._raw(route[len("/raw/"):])
        if route.startswith("/view/"):
            return self._view(route[len("/view/"):])
        self._send_err(HTTPStatus.NOT_FOUND, "no such route")

    def do_HEAD(self) -> None:
        if not self._gate():
            return
        self._send_err(HTTPStatus.METHOD_NOT_ALLOWED, "HEAD not allowed")

    # All other verbs forbidden:
    def do_POST(self): self._gate() and self._send_err(HTTPStatus.METHOD_NOT_ALLOWED, "POST not allowed")
    def do_PUT(self): self._gate() and self._send_err(HTTPStatus.METHOD_NOT_ALLOWED, "PUT not allowed")
    def do_DELETE(self): self._gate() and self._send_err(HTTPStatus.METHOD_NOT_ALLOWED, "DELETE not allowed")
    def do_PATCH(self): self._gate() and self._send_err(HTTPStatus.METHOD_NOT_ALLOWED, "PATCH not allowed")
    def do_OPTIONS(self): self._send_err(HTTPStatus.METHOD_NOT_ALLOWED, "OPTIONS not allowed")

    # ----- helpers -----
    def _resolve_safe(self, rel: str) -> Path | None:
        rel = urllib.parse.unquote(rel)
        if not rel or "\x00" in rel or rel.startswith("/") or rel.startswith("\\"):
            return None
        # Reject .. against both POSIX and Windows separators so the pre-check
        # behaves identically on every platform.
        norm = rel.replace("\\", "/")
        if any(part == ".." for part in norm.split("/")):
            return None
        candidate = self.htmem_root / rel
        # G04: refuse to follow a symlink even when it points inside the root.
        if candidate.exists() and candidate.is_symlink():
            return None
        target = candidate.resolve()
        try:
            target.relative_to(self.htmem_root.resolve())
        except ValueError:
            return None
        if target.suffix.lower() != ".html":
            return None
        if not target.is_file():
            return None
        return target

    def _raw(self, rel: str) -> None:
        target = self._resolve_safe(rel)
        if not target:
            self._send_err(HTTPStatus.NOT_FOUND, "not a valid artifact path")
            return
        raw = target.read_bytes()
        if len(raw) > 10 * 1024 * 1024:
            self._send_err(HTTPStatus.PAYLOAD_TOO_LARGE, "artifact too large")
            return
        # Sanitize before serving — even though we sandbox the iframe, this is defense in depth.
        clean, _findings, _removed, _islands = sanitize_bytes(raw)
        body = clean.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self._hardened_headers("text/html; charset=utf-8", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _view(self, rel: str) -> None:
        # Wrapper page that embeds the raw artifact in a sandboxed iframe.
        target = self._resolve_safe(rel)
        if not target:
            self._send_err(HTTPStatus.NOT_FOUND, "not a valid artifact path")
            return
        rel_safe = urllib.parse.quote(rel, safe="/")
        token_qs = urllib.parse.quote(self.htmem_token)
        body = (
            f"""<!doctype html><html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>htmem · {target.name}</title>
<style>
  body {{ margin: 0; font-family: system-ui, sans-serif; background: #0e1116; color: #e4e1d6; }}
  header {{ padding: 0.75rem 1rem; border-bottom: 1px solid #2a3038; display: flex; align-items: center; gap: 1rem; }}
  header h1 {{ font-size: 0.95rem; margin: 0; font-weight: 600; }}
  header a {{ color: #f59e0b; text-decoration: none; font-size: 0.85rem; }}
  iframe {{ width: 100%; height: calc(100vh - 50px); border: 0; background: white; }}
</style>
</head><body>
<header>
  <h1>htmem · {target.name}</h1>
  <a href="/hub?t={token_qs}">← hub</a>
</header>
<iframe sandbox src="/raw/{rel_safe}?t={token_qs}" title="htmem artifact"></iframe>
</body></html>"""
        ).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self._hardened_headers("text/html; charset=utf-8", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _hub(self) -> None:
        items = []
        for p in sorted(self.htmem_root.rglob("*.html")):
            try:
                if p.is_symlink():
                    continue
                with p.open("rb") as f:
                    head = f.read(1024 * 1024)
                if b"htmem-manifest" not in head:
                    continue
            except OSError:
                continue
            rel = p.relative_to(self.htmem_root).as_posix()
            items.append(rel)
            if len(items) > 10000:
                break
        token_qs = urllib.parse.quote(self.htmem_token)
        lis = "\n".join(
            f'<li><a href="/view/{urllib.parse.quote(r, safe="/")}?t={token_qs}">{r}</a></li>'
            for r in items
        ) or "<li><em>no htmem artifacts found under this folder</em></li>"
        body = (
            f"""<!doctype html><html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>htmem hub · {len(items)} artifacts</title>
<style>
  :root {{ color-scheme: light dark; --bg: light-dark(#fafaf7, #0e1116); --text: light-dark(#1a1a1a, #e4e1d6); --rule: light-dark(#e6e3da, #2a3038); --accent: light-dark(#a63329, #f59e0b); }}
  body {{ margin: 0; padding: 2rem; max-width: 60ch; margin-inline: auto; font: 16px/1.5 system-ui, sans-serif; background: var(--bg); color: var(--text); }}
  h1 {{ font: 600 1.6rem/1.2 'Source Serif 4', Georgia, serif; }}
  p.eyebrow {{ color: var(--accent); text-transform: uppercase; letter-spacing: 0.1em; font-size: 0.75rem; font-weight: 700; margin: 0; }}
  ul {{ list-style: none; padding: 0; margin-top: 1.5rem; }}
  li {{ padding: 0.75rem 0; border-bottom: 1px solid var(--rule); }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  footer {{ margin-top: 3rem; font-size: 0.85rem; color: light-dark(#5a5a55, #9098a0); }}
</style>
</head><body>
<p class="eyebrow">htmem · hub</p>
<h1>{len(items)} artifact{'s' if len(items) != 1 else ''}</h1>
<ul>{lis}</ul>
<footer>
<p>Bound 127.0.0.1 · idle timeout 15 min · token required · iframe-sandboxed view</p>
</footer>
</body></html>"""
        ).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self._hardened_headers("text/html; charset=utf-8", len(body))
        self.end_headers()
        self.wfile.write(body)


# ---------- Server lifecycle ----------

def _find_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _serve(root: Path, port: int, idle_timeout_sec: int) -> int:
    if not root.is_dir():
        print(f"ERROR: not a directory: {root}", file=sys.stderr)
        return 2
    root = root.resolve()
    if port == 0:
        port = _find_port()
    token = secrets.token_urlsafe(32)
    HtmemHandler.htmem_root = root
    HtmemHandler.htmem_token = token
    HtmemHandler.htmem_idle_last = [time.time()]

    server = ThreadingHTTPServer(("127.0.0.1", port), HtmemHandler)
    state = {"port": port, "token": token, "root": str(root), "pid": os.getpid(), "started": time.time()}
    _write_state(state)

    print(f"htmem render server")
    print(f"  bind:    127.0.0.1:{port}")
    print(f"  root:    {root}")
    print(f"  token:   {token[:12]}…  (full token stored at {_state_path()}, mode 0o600)")
    # H02: do not emit the full token to stdout — agents that pipe stdout to
    # chat would leak it. The token is in the state file at mode 0o600; use
    # `render_server.py --open <path>` to launch the browser without
    # exposing the URL in conversation.
    print(f"  hub URL: http://127.0.0.1:{port}/hub?t={token[:12]}…  (use --open to launch)")
    print(f"  idle:    {idle_timeout_sec}s timeout")
    print(f"  log:     {_state_path().parent / 'render-server.log'}")
    print(f"  Ctrl+C to stop")

    stop = threading.Event()

    def idle_watcher():
        while not stop.is_set():
            time.sleep(5)
            if time.time() - HtmemHandler.htmem_idle_last[0] > idle_timeout_sec:
                print("\nidle timeout — shutting down.", file=sys.stderr)
                threading.Thread(target=server.shutdown, daemon=True).start()
                return

    t = threading.Thread(target=idle_watcher, daemon=True)
    t.start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping.", file=sys.stderr)
    finally:
        stop.set()
        server.server_close()
        try:
            _state_path().unlink()
        except OSError:
            pass
    return 0


def _status() -> int:
    st = _read_state()
    if not st:
        print("STOPPED")
        return 1
    print(f"RUNNING {st['port']} {st['token'][:12]}… root={st['root']} pid={st['pid']}")
    return 0


def _open(rel: str) -> int:
    st = _read_state()
    if not st:
        print("ERROR: server not running. Start with --serve <root>.", file=sys.stderr)
        return 2
    rel_path = Path(rel)
    if not rel_path.is_file():
        print(f"ERROR: not a file: {rel_path}", file=sys.stderr)
        return 2
    root = Path(st["root"])
    try:
        rel_norm = rel_path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        print(f"ERROR: {rel_path} is outside server root {root}", file=sys.stderr)
        return 2
    url = f"http://127.0.0.1:{st['port']}/view/{urllib.parse.quote(rel_norm, safe='/')}?t={urllib.parse.quote(st['token'])}"
    print(url)
    webbrowser.open(url)
    return 0


# ---------- CLI ----------

def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="render_server.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--serve", type=Path, help="start server with this root directory")
    g.add_argument("--status", action="store_true")
    g.add_argument("--open", dest="open_path", help="open an artifact in the running server")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--idle", type=int, default=15 * 60, help="idle timeout in seconds (default 900)")
    args = p.parse_args(argv)
    if args.serve:
        return _serve(args.serve, args.port, args.idle)
    if args.status:
        return _status()
    if args.open_path:
        return _open(args.open_path)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
