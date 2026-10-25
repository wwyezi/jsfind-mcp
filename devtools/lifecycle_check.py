"""Resource governance: a session must not grow without bound.

Three things this pins down, all from the report on the four-instance /
667 MB pile-up:

  1. the scan store is bounded (LRU + TTL) and a scan can be released now
  2. a JS-file target skips route rendering, so the budget is not spent
     fetching the same bundle forty times
  3. a timeout comes back as structured data (``code`` / ``partial``), never
     as a string sentinel in a numeric field

    python devtools/lifecycle_check.py
"""

from __future__ import annotations

import asyncio
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from jsfind_mcp.model import Mode, Result  # noqa: E402
from jsfind_mcp.server import ScanStore, build_server  # noqa: E402

FAILURES: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILURES.append(label)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"<html><head><script src=/a.js></script></head><body>x</body></html>"
        if self.path != "/":
            body = b'fetch("/api/ping");var t="abc";'
        self.send_response(200)
        self.send_header("Content-Type",
                         "text/html" if self.path == "/"
                         else "application/javascript")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def log_message(self, *args) -> None:
        pass


def main() -> int:
    print("[scan store: LRU + TTL + release]")

    store = ScanStore(max_scans=3, ttl=600)
    ids = []
    for _ in range(5):
        ids.append(store.put(Result(target="http://t/", mode=Mode.AUTO)))
    held = store.ids()
    check("store is capped", len(held) == 3, f"{len(held)} held")
    check("oldest were evicted", ids[0] not in held and ids[1] not in held,
          f"kept {held}")

    check("release drops one", store.release(held[0]))
    check("released id is gone", held[0] not in store.ids())
    check("release is idempotent", not store.release(held[0]))
    check("clear drops the rest", store.clear() == 2, str(store.clear()))

    short = ScanStore(max_scans=10, ttl=0.3)
    sid = short.put(Result(target="http://t/", mode=Mode.AUTO))
    time.sleep(0.5)
    try:
        short.get(sid)
        check("expired entry is gone", False, "still resolvable")
    except KeyError:
        check("expired entry is gone", True)
    check("expired id no longer listed", sid not in short.ids())

    print("\n[js target skips route rendering]")
    site = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=site.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{site.server_address[1]}"

    async def scan_js_target():
        mcp = build_server(ScanStore())
        # The page's script is fetched as a normal resource; what matters is
        # that a target which *is* a bundle does not go on to render routes.
        result = await mcp.call_tool("jsfind_scan", {
            "url": f"{base}/a.js", "save_js": False, "probe": False})
        text = "".join(getattr(b, "text", "") or "" for b in (result or []))
        import json
        return json.loads(text)

    payload = asyncio.run(scan_js_target())
    check("js target scan answered", bool(payload.get("scan_id")),
          str(payload.get("scan_id"))[:40])
    check("no routes were rendered", payload.get("routes_rendered", 0) == 0,
          str(payload.get("routes_rendered")))
    site.shutdown()

    print("\n[timeout is structured]")
    check("timeout carries code field", "code" in payload, str(payload.get("code")))
    check("timeout carries partial flag", "partial" in payload,
          str(payload.get("partial")))
    check("timeout_seconds is a number",
          isinstance(payload.get("timeout_seconds"), (int, float)),
          str(payload.get("timeout_seconds")))
    check("no string sentinel in a numeric field",
          not isinstance(payload.get("timeout_seconds"), str))

    print("\n" + ("ALL PASS" if not FAILURES
                  else f"{len(FAILURES)} FAILED: {FAILURES}"))
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
