"""Verify proxy support end to end.

Runs a real forward proxy in-process and checks that traffic is actually routed
through it, rather than merely that the setting was accepted. Also covers the
three ways a proxy goes wrong quietly: a password leaking into the response, a
``no_proxy`` entry that does not take effect, and an exported HTTP_PROXY that
is ignored (or honoured when the operator asked for a provably direct run).

Run: python devtools/verify_proxy.py
"""
from __future__ import annotations

import asyncio
import http.client
import json
import os
import shutil
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from localsite import Handler as SiteHandler  # noqa: E402

from jsfind_mcp.server import ScanStore, build_server  # noqa: E402

FAILURES: list = []
SEEN: list = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILURES.append(label)


class ForwardProxy(BaseHTTPRequestHandler):
    """A working forward proxy for plain http:// targets.

    Records every absolute-form request line and forwards upstream. Recording
    is the point: it distinguishes "the proxy was configured" from "the proxy
    carried the traffic", which is the only distinction that matters here.
    """
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        SEEN.append(self.path)
        parsed = urlparse(self.path)
        if not parsed.netloc:
            self.send_error(400, "proxy expects absolute-form request line")
            return
        tail = parsed.path or "/"
        if parsed.query:
            tail += "?" + parsed.query
        upstream = http.client.HTTPConnection(parsed.netloc, timeout=10)
        try:
            upstream.request("GET", tail, headers={"Host": parsed.netloc})
            response = upstream.getresponse()
            body = response.read()
            self.send_response(response.status)
            self.send_header("Content-Type",
                             response.getheader("Content-Type", "text/html"))
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as exc:  # noqa: BLE001
            self.send_error(502, str(exc))
        finally:
            upstream.close()


async def run() -> None:
    site = ThreadingHTTPServer(("127.0.0.1", 0), SiteHandler)
    threading.Thread(target=site.serve_forever, daemon=True).start()
    target = f"http://127.0.0.1:{site.server_address[1]}/"

    proxy = ThreadingHTTPServer(("127.0.0.1", 0), ForwardProxy)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    proxy_url = f"http://127.0.0.1:{proxy.server_address[1]}"

    mcp = build_server(ScanStore())

    async def call(name: str, **arguments):
        result = await mcp.call_tool(name, arguments)
        if isinstance(result, dict):
            return result
        for block in result:
            text = block.get("text") if isinstance(block, dict) \
                else getattr(block, "text", None)
            if text:
                return json.loads(text)
        return {}

    scratch = tempfile.mkdtemp(prefix="jsfind-verify-proxy-")
    previous = os.getcwd()
    os.chdir(scratch)
    try:
        print("\n[1. a configured proxy actually carries the traffic]")
        SEEN.clear()
        scan = await call("jsfind_scan", url=target, js_dir="./out",
                          proxy=proxy_url, trust_env=False)
        check("scan completed", bool(scan.get("scan_id")),
              str(scan.get("error"))[:80])
        check("proxy received requests", len(SEEN) > 0, f"{len(SEEN)} requests")
        check("requests were absolute-form",
              all(s.startswith("http://") for s in SEEN), str(SEEN[:2]))
        check("content was collected through it", scan.get("resources", 0) > 0,
              str(scan.get("resources")))
        check("proxy reported back, redacted",
              scan.get("proxy") == proxy_url, str(scan.get("proxy")))

        print("\n[2. the proxy password never appears in the response]")
        auth = await call("jsfind_scan", url=target, js_dir="./out",
                          proxy="http://alice:s3cr3t@127.0.0.1:9",
                          trust_env=False)
        blob = json.dumps(auth, ensure_ascii=False)
        check("password absent", "s3cr3t" not in blob)
        check("username still reported", "alice" in blob, str(auth.get("proxy")))

        print("\n[3. no_proxy bypasses the named host]")
        SEEN.clear()
        await call("jsfind_scan", url=target, js_dir="./out", proxy=proxy_url,
                   no_proxy="127.0.0.1", trust_env=False)
        check("proxy saw nothing", len(SEEN) == 0, f"{len(SEEN)} requests")

        print("\n[4. trust_env decides whether an exported proxy counts]")
        SEEN.clear()
        os.environ["HTTP_PROXY"] = proxy_url
        os.environ["ALL_PROXY"] = proxy_url
        try:
            direct = await call("jsfind_scan", url=target, js_dir="./out",
                                trust_env=False)
            check("went direct despite env vars", len(SEEN) == 0,
                  f"{len(SEEN)} requests")
            check("scan still worked", bool(direct.get("scan_id")))
            SEEN.clear()
            await call("jsfind_scan", url=target, js_dir="./out", trust_env=True)
            check("trust_env=true used the env proxy", len(SEEN) > 0,
                  f"{len(SEEN)} requests")
        finally:
            os.environ.pop("HTTP_PROXY", None)
            os.environ.pop("ALL_PROXY", None)

        print("\n[5. a malformed proxy is one clear sentence]")
        bad = await call("jsfind_scan", url=target, proxy="htp://typo:3128")
        check("error, not a traceback", "error" in bad, str(bad)[:90])
        check("error names the problem", "htp" in str(bad.get("error", "")),
              str(bad.get("error"))[:70])

        print("\n[6. diagnostics exposes the proxy block, redacted]")
        diag = await call("jsfind_diagnostics")
        block = diag.get("proxy")
        check("block present", isinstance(block, dict), str(block)[:110])
        if isinstance(block, dict):
            check("no raw password key",
                  all("password" not in str(k).lower() for k in block))
    finally:
        os.chdir(previous)
        shutil.rmtree(scratch, ignore_errors=True)
        site.shutdown()
        proxy.shutdown()


asyncio.run(run())
print("\n" + ("ALL PASS" if not FAILURES
              else f"{len(FAILURES)} FAILED: {FAILURES}"))
sys.exit(1 if FAILURES else 0)
