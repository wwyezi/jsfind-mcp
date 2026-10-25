"""The whole scan has to stop at its wall-clock budget, not run on.

Only the first queue drain used to be capped. Route rendering, spec probing and
endpoint probing then ran with no ceiling at all, so a target slowed a single
``jsfind_scan`` down to many minutes -- past what an MCP client waits before it
gives up, drops the stdio pipe and takes the server process (and every result
held in memory) down with it, with no error anywhere.

Two things are proven here: a scan stops inside its budget and still returns
partial results, and it says so instead of leaving "endpoints: 12" to be read as
"that is everything".

Run: python devtools/verify_budget.py
"""

from __future__ import annotations

import asyncio
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from jsfind_mcp.config import Config  # noqa: E402
from jsfind_mcp.scanner import Scanner, Target  # noqa: E402

#: Every request is answered slowly, so the budget is what decides when a scan
#: ends rather than how fast the target happens to be.
DELAY = 1.5
SCRIPTS = 60
BUDGET = 5.0
#: Room for whatever was already in flight when the deadline passed.
SLACK = 4.0

FAILURES: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILURES.append(label)


def fixture(scripts: int):
    """An SPA with many lazy scripts, every response deliberately slow."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            time.sleep(DELAY)
            if self.path == "/":
                tags = b"".join(f'<script src="/slow{i}.js"></script>'.encode()
                                for i in range(scripts))
                body = b"<html><head>" + tags + b"</head><body>x</body></html>"
                content_type = "text/html"
            else:
                body = b"fetch('/api/ping'); var version='1.0.0';"
                content_type = "application/javascript"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except OSError:
                pass  # the caller hung up: a cancelled request, not a failure

        def log_message(self, *args) -> None:
            pass

    return Handler


async def run() -> None:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), fixture(SCRIPTS))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}/"

    print(f"[budget {BUDGET:.0f}s against a slow target]")
    capped = Config()
    capped.request.target_timeout = BUDGET
    capped.request.timeout = 2.0
    started = time.monotonic()
    capped_result = await Scanner(capped).scan(Target(url=base))
    elapsed = time.monotonic() - started
    codes = [issue.code for issue in capped_result.issues]
    print(f"    elapsed={elapsed:.1f}s resources={capped_result.statistics.resources} "
          f"issues={codes}")
    check("stops inside the budget", elapsed <= BUDGET + SLACK, f"{elapsed:.1f}s")
    check("says why it stopped", "target_timeout" in codes, str(codes))
    check("still returns what it got", capped_result.statistics.resources >= 1,
          str(capped_result.statistics.resources))

    print("\n[0 means unlimited, and must not abort the first drain]")
    open_ended = Config()
    open_ended.request.target_timeout = 0
    open_ended.request.timeout = 2.0
    # Zero used to mean "wait_for(timeout=0)", which timed the first drain out
    # instantly and returned nothing at all.
    started = time.monotonic()
    full = await Scanner(open_ended).scan(Target(url=base))
    open_elapsed = time.monotonic() - started
    print(f"    elapsed={open_elapsed:.1f}s resources={full.statistics.resources}")
    check("no budget issue when unlimited",
          not any(i.code == "target_timeout" for i in full.issues),
          str([i.code for i in full.issues]))
    # Elapsed rather than counts: an unlimited scan of the same target simply
    # keeps going, which is the difference being asserted here.
    check("unlimited run goes on well past the capped one",
          open_elapsed > elapsed * 2, f"{open_elapsed:.1f}s vs {elapsed:.1f}s")

    httpd.shutdown()


def main() -> int:
    asyncio.run(run())
    print("\n" + ("ALL PASS" if not FAILURES
                  else f"{len(FAILURES)} FAILED: {FAILURES}"))
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
