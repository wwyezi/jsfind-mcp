"""A scan must never take the whole MCP session down with it.

The server is asyncio-based: one loop answers every request. The extraction
passes (regex and Tree-sitter over whole bundles) used to run synchronously on
that loop, so a single large minified file froze ``tools/list`` along with
everything else — which is what "the tool list went empty until I restarted"
actually was. Extraction now runs on a worker thread and the loop stays free.

Three things a session must survive:

  1. tools/list while a big scan is running
  2. the caller cancelling that scan mid-flight
  3. a malformed message (the SDK drops it; the session must continue)

    python devtools/responsive_check.py [src]
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUFFIX = ".exe" if os.name == "nt" else ""
# "src" exercises the checkout instead of the frozen binary.
SERVER = ([sys.executable, "-m", "jsfind_mcp.server"] if len(sys.argv) > 1
          else [str(ROOT / "dist" / f"jsfind-mcp{SUFFIX}")])

#: ~6 MB, one line, the shape of a real minified bundle.
BUNDLE = (
    "var a=1;" +
    "".join(
        f'function f{i}(){{fetch("/api/v1/resource{i}/detail?token=abc{i}");'
        f'var x="AKIA{i}EXAMPLEKEY";return x;}}'
        for i in range(45000)
    )
).encode()

FAILURES: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILURES.append(label)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/":
            body = (b"<html><head><script src=/app.js></script></head>"
                    b"<body>hi</body></html>")
            content_type = "text/html"
        else:
            body = BUNDLE
            content_type = "application/javascript"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def log_message(self, *args) -> None:
        pass


def child_env() -> dict:
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONPATH"] = str(ROOT / "src")
    return env


class Session:
    """A stdio MCP client whose reads never block the checks."""

    def __init__(self, proc):
        self.proc = proc
        self.replies: dict = {}
        threading.Thread(target=self._drain, daemon=True).start()

    def _drain(self) -> None:
        for line in self.proc.stdout:
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "id" in message:
                self.replies[message["id"]] = message

    def send(self, request_id, method, params=None) -> None:
        self.proc.stdin.write(json.dumps({
            "jsonrpc": "2.0", "id": request_id, "method": method,
            "params": params or {},
        }) + "\n")
        self.proc.stdin.flush()

    def notify(self, method, params=None) -> None:
        self.proc.stdin.write(json.dumps({
            "jsonrpc": "2.0", "method": method, "params": params or {},
        }) + "\n")
        self.proc.stdin.flush()

    def wait(self, request_id, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if request_id in self.replies:
                return self.replies[request_id]
            time.sleep(0.05)
        return None


def tools_count(reply) -> int:
    if not reply:
        return 0
    return len((reply.get("result") or {}).get("tools") or [])


def main() -> int:
    site = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=site.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{site.server_address[1]}/"
    print(f"responsive check — {len(BUNDLE) / 1024 / 1024:.1f} MB bundle")

    proc = subprocess.Popen(
        [*SERVER, "--transport", "stdio", "--no-config"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True, env=child_env(), encoding="utf-8", errors="replace",
    )
    session = Session(proc)
    try:
        session.send(1, "initialize", {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "responsive", "version": "1"}})
        check("initialize answered", session.wait(1, 30) is not None)

        # Whatever the server registers is the expected count; the invariant is
        # that the count does not change mid-session.
        session.send(7, "tools/list")
        baseline = session.wait(7, 10.0)
        expected = tools_count(baseline)
        check("tool list is non-empty", expected > 0, str(expected))

        print("\n1. tools/list while a big scan runs")
        session.send(2, "tools/call", {
            "name": "jsfind_scan",
            "arguments": {"url": base, "save_js": False}})
        time.sleep(0.3)
        started = time.monotonic()
        session.send(3, "tools/list")
        reply = session.wait(3, 5.0)
        check("tools/list answered mid-scan", reply is not None,
              f"{time.monotonic() - started:.2f}s" if reply else "no reply in 5s")
        check("tool list is complete", tools_count(reply) == expected,
              str(tools_count(reply)))

        print("\n2. cancel that scan, then tools/list again")
        session.notify("notifications/cancelled",
                       {"requestId": 2, "reason": "responsive_check"})
        time.sleep(1.0)
        started = time.monotonic()
        session.send(4, "tools/list")
        reply = session.wait(4, 5.0)
        check("tools/list answered after cancel", reply is not None,
              f"{time.monotonic() - started:.2f}s" if reply else "no reply in 5s")
        check("tool list still complete", tools_count(reply) == expected,
              str(tools_count(reply)))

        print("\n3. a malformed message must not kill the session")
        # A lone surrogate cannot be parsed as JSON-RPC at all, so the SDK drops
        # the message before any tool sees it. What matters is that dropping it
        # leaves the session intact: a lost call is a lost call, a dead receive
        # loop is "the tools vanished".
        session.send(5, "tools/call", {
            "name": "jsfind_analyze_file",
            "arguments": {"files": [], "base_url": "http://x/\udcff\udcfe"}})
        time.sleep(1.0)
        started = time.monotonic()
        session.send(6, "tools/list")
        reply = session.wait(6, 5.0)
        check("session survived a malformed message", reply is not None,
              f"{time.monotonic() - started:.2f}s" if reply else "no reply in 5s")
        check("tool list is complete at the end", tools_count(reply) == expected,
              str(tools_count(reply)))
    finally:
        proc.kill()
        site.shutdown()

    print("\n" + ("ALL PASS" if not FAILURES
                  else f"{len(FAILURES)} FAILED: {FAILURES}"))
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
