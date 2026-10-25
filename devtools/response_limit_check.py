"""An oversized response must be capped in the HTTP client, not felt by the user.

A 20 MB JS response used to be buffered whole by ``client.get()``: no size cap,
no wall clock on the transfer (httpx's ``read`` timeout bounds the gap between
two reads, never the whole body). The scan pinned a fetch slot and hundreds of
MB of memory before any downstream check could run. The client now streams,
counts after decompression, keeps the first ``max_response_bytes`` of a
response in memory and hands everything past the cap to the sliding-window
extractor, whose regex passes see the whole transfer window by window — so a
20 MB bundle's back half still yields its interfaces without ever being held
whole.

    python devtools/response_limit_check.py
"""

from __future__ import annotations

import asyncio
import gzip
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from jsfind_mcp.chunking import PieceCutter  # noqa: E402
from jsfind_mcp.collect import Client  # noqa: E402
from jsfind_mcp.config import Config  # noqa: E402
from jsfind_mcp.server import ScanStore, build_server  # noqa: E402

FAILURES: list[str] = []

#: Unit-level cap: small so every scenario answers in seconds.
CAP = 5 * 1024 * 1024
#: A response bigger than the reported 20 MB hang.
BIG_SIZE = 21 * 1024 * 1024
#: Declared (and really sent) by the declared-oversize target.
DECLARED_SIZE = 25 * 1024 * 1024
#: Compressed tiny, ~12 MB after decompression — a small gzip bomb.
BOMB_RAW = 12 * 1024 * 1024
#: The e2e scan's cap (``"800kb"``); the seam endpoint straddles it.
E2E_CAP = 800 * 1024


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILURES.append(label)


def script_with(endpoints: list[tuple[int, str]], filler_size: int) -> bytes:
    """A JS body of ``filler_size`` bytes with endpoints planted at offsets.

    The filler is valid JavaScript on purpose: a real minified bundle parses,
    and the AST pass must cost what it costs on real input, not on garbage.
    Long string values, few statements — the shape of a real bundle, where
    parse time tracks tokens, not bytes.
    """
    unit = b'var s0="' + b"a" * 480 + b'";var s1="' + b"b" * 480 + b'";'
    chunks: list[bytes] = []
    pos = 0
    for offset, code in endpoints:
        if offset > pos:
            span = offset - pos
            chunks.append(unit * (span // len(unit)))
            pos += span - span % len(unit)
        chunk = code.encode()
        chunks.append(chunk)
        pos += len(chunk)
    rest = max(0, filler_size - pos)
    chunks.append(unit * (rest // len(unit)))
    return b"".join(chunks)


BIG = script_with(
    [(512 * 1024, "".join(
        f'function e{i}(){{fetch("/api/early{i}/detail?token=t{i}");}}'
        for i in range(6))),
     # Straddles the e2e cap: its head lands in the kept prefix cut
     # mid-token, its tail in the window — only the window's overlap keeps
     # the match whole.
     (E2E_CAP - 20, 'fetch("/api/seam0/detail?token=s0");'),
     (15 * 1024 * 1024, "".join(
        f'function d{i}(){{fetch("/api/deep{i}/detail?token=t{i}");}}'
        for i in range(6)))],
    BIG_SIZE)

BOMB = gzip.compress(b'fetch("/api/bomb");' * (BOMB_RAW // 20))


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        try:
            if self.path == "/":
                body = (b"<html><head><script src=/big.js></script>"
                        b"</head><body>hi</body></html>")
                self._plain(body, "text/html")
            elif self.path == "/big.js":
                self._plain(BIG, "application/javascript")
            elif self.path == "/cl.js":
                # Declares far more than the cap and really sends it: the
                # client must stop reading at the cap, keeping the prefix.
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript")
                self.send_header("Content-Length", str(DECLARED_SIZE))
                self.end_headers()
                block = b"y" * 65536
                for _ in range(DECLARED_SIZE // len(block)):
                    self.wfile.write(block)
            elif self.path == "/slow.js":
                # A dribbling server: each 64 KB chunk arrives well inside any
                # read-gap timeout, forever. Only the transfer wall clock ends
                # this.
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript")
                self.send_header("Content-Length", str(200 * 65536))
                self.end_headers()
                block = b"z" * 65536
                for _ in range(200):
                    self.wfile.write(block)
                    self.wfile.flush()
                    time.sleep(0.1)
            elif self.path == "/bomb.js":
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript")
                self.send_header("Content-Encoding", "gzip")
                self.send_header("Content-Length", str(len(BOMB)))
                self.end_headers()
                self.wfile.write(BOMB)
            elif self.path == "/normal.js":
                self._plain(b'fetch("/api/normal/ok");', "application/javascript")
            else:
                # A real 404 carries a length; without one an HTTP/1.1
                # keep-alive connection leaves the client waiting for a body
                # that never comes, which is what the probe timeouts defend
                # against in production — but this server should model the
                # well-behaved case.
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
        except OSError:
            # The client legitimately drops the connection mid-body when it
            # hits the cap; the handler thread just stops writing.
            self.close_connection = True

    def _plain(self, body: bytes, content_type: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        pass


def cutter_checks() -> None:
    print("[piece cutter: straddling matches stay whole]")
    marker = 'fetch("/api/straddle/detail")'
    body = "x" * (700000 - 10) + marker + "y" * 700000
    cutter = PieceCutter()
    pieces = cutter.feed(body) + cutter.flush()
    check("a match across the cut is seen whole",
          any(marker in piece for piece in pieces),
          f"{len(pieces)} pieces")
    check("pieces overlap rather than butt together",
          len(pieces) >= 2 and pieces[1].startswith("x" * 1000))


def unit_checks(base: str) -> None:
    print("\n[client streaming: caps, wall clock, consumer]")
    config = Config()
    config.request.max_response_bytes = CAP
    config.request.download_timeout = 2.0
    config.request.retry = 0

    consumed: list[int] = []

    async def consumer(data: bytes) -> None:
        consumed.append(len(data))

    async def run() -> dict:
        out: dict[str, object] = {}
        async with Client(config) as client:
            started = time.monotonic()
            out["big"] = await client.get(f"{base}/big.js", on_chunk=consumer)
            out["big_elapsed"] = time.monotonic() - started
            started = time.monotonic()
            out["cl"] = await client.get(f"{base}/cl.js")
            out["cl_elapsed"] = time.monotonic() - started
            started = time.monotonic()
            out["bomb"] = await client.get(f"{base}/bomb.js")
            out["bomb_elapsed"] = time.monotonic() - started
            started = time.monotonic()
            out["slow"] = await client.get(f"{base}/slow.js")
            out["slow_elapsed"] = time.monotonic() - started
            out["normal"] = await client.get(f"{base}/normal.js")
        return out

    got = asyncio.run(run())

    big = got["big"]
    check("20 MB response is truncated", big.truncated)
    check("kept exactly the cap", len(big.body) == CAP,
          f"{len(big.body)} bytes")
    check("declared size was recorded",
          big.declared_size == len(BIG), str(big.declared_size))
    check("streamed size records the whole transfer",
          big.streamed_size == len(BIG), str(big.streamed_size))
    check("consumer saw every byte past the cap",
          sum(consumed) == len(BIG), f"{sum(consumed)} of {len(BIG)}")
    check("overflow marked as analyzed", big.overflow_analyzed)
    check("truncated fetch was fast", got["big_elapsed"] < 10,
          f"{got['big_elapsed']:.2f}s for {BIG_SIZE / 1024 / 1024:.0f} MB response")
    check("truncated prefix still parses as ok", big.ok)

    cl = got["cl"]
    check("declared-oversize body keeps a capped prefix",
          cl.truncated and len(cl.body) == CAP,
          f"{len(cl.body)} of {DECLARED_SIZE} bytes read")
    check("declared size came from headers",
          cl.declared_size == DECLARED_SIZE, str(cl.declared_size))
    check("no consumer means no overflow claim",
          not cl.overflow_analyzed)
    check("oversize fetch was bounded", got["cl_elapsed"] < 5,
          f"{got['cl_elapsed']:.2f}s to cap a 25 MB body")

    bomb = got["bomb"]
    check("gzip bomb is capped after decompression", bomb.truncated,
          f"declared {bomb.declared_size} bytes, kept {len(bomb.body)}")
    check("bomb cap counted decoded bytes", len(bomb.body) == CAP)

    slow = got["slow"]
    check("dribbling transfer hits the wall clock",
          "download timeout" in slow.error, slow.error[:80])
    check("dribble ended promptly", got["slow_elapsed"] < 6,
          f"{got['slow_elapsed']:.2f}s against a 2s ceiling")

    normal = got["normal"]
    check("small response is untouched",
          not normal.truncated and len(normal.body) < 100)


def e2e_checks(base: str) -> None:
    print("\n[end-to-end scan over a capped bundle]")
    started = time.monotonic()

    async def scan() -> dict:
        mcp = build_server(ScanStore())
        result = await mcp.call_tool("jsfind_scan", {
            "url": f"{base}/", "save_js": False, "probe": False,
            # A string literal on purpose: the same loose parsing _seconds
            # established, exercised through the new parameter.
            "max_response_bytes": "800kb",
            # Full-window regex extraction over a 20 MB bundle is CPU work
            # measured in minutes; the default 90 s budget reports partial
            # results instead. Give the scan what the job needs.
            "timeout_seconds": 300})
        text = "".join(getattr(b, "text", "") or "" for b in (result or []))
        scan_payload = json.loads(text)
        listed = await mcp.call_tool("jsfind_endpoints", {
            "scan_id": scan_payload.get("scan_id"), "limit": 100})
        listed_text = "".join(getattr(b, "text", "") or "" for b in (listed or []))
        scan_payload["_rows"] = [r.get("url", "") for r in
                                 json.loads(listed_text).get("endpoints", [])]
        return scan_payload

    payload = asyncio.run(scan())
    elapsed = time.monotonic() - started
    codes = [i.get("code") for i in payload.get("issues") or []]
    joined = " ".join(payload.get("_rows") or [])

    check("scan finished under its own budget", payload.get("code") == "ok",
          f"{elapsed:.1f}s, code={payload.get('code')}")
    check("capped via loose parsing ('800kb')",
          any(c == "response_truncated" for c in codes), str(codes))
    check("endpoints from the kept prefix surfaced", "/api/early" in joined,
          joined[:120])
    check("endpoints past the cap surface via the window",
          "/api/deep" in joined, joined[:120])
    check("match straddling the cap stays whole", "/api/seam" in joined,
          joined[:120])
    check("hints mention the truncation",
          any("截断" in h for h in payload.get("hints") or []),
          str(payload.get("hints"))[:120])
    check("hints say the overflow was covered",
          any("滑动窗口" in h or "全量" in h for h in payload.get("hints") or []),
          str(payload.get("hints"))[:160])
    check("elapsed stays interactive", elapsed < 240, f"{elapsed:.1f}s")


def main() -> int:
    site = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=site.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{site.server_address[1]}"
    print(f"response limit check — {BIG_SIZE / 1024 / 1024:.0f} MB response, "
          f"unit cap {CAP / 1024 / 1024:.0f} MB")
    try:
        cutter_checks()
        unit_checks(base)
        e2e_checks(base)
    finally:
        site.shutdown()
    print("\n" + ("ALL PASS" if not FAILURES
                  else f"{len(FAILURES)} FAILED: {FAILURES}"))
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
