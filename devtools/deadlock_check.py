"""An MCP client that never reads stderr must not be able to stop the server.

A scan logs every request through httpx and every tool call through FastMCP.
Under stdio those writes go to stderr, which is a pipe the client handed us and
is free to ignore. When the pipe fills, the server blocks inside a log write and
stops answering ``tools/list`` — which is exactly the reported symptom: the tool
list goes empty and only a restart brings it back.

Two runs of the same server against the same local fixture:

  A. stderr = PIPE, never read   what a non-draining client does
  B. stderr = DEVNULL            the same call with the pipe removed

A must answer like B. Both must answer.

    python devtools/deadlock_check.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from localsite import Handler  # noqa: E402

PYTHON = sys.executable
#: Generous: a scan of the fixture takes seconds; this is about deadlock, not
#: about speed.
WAIT = 30.0

FAILURES: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILURES.append(label)


def child_env() -> dict:
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONPATH"] = str(ROOT / "src")
    # Keep the test off the operator's real log.
    env["JSFIND_LOG"] = str(ROOT / ".deadlock-check.log")
    return env


def attempt(label: str, stderr_target, wait: float = WAIT) -> float:
    """One scan over stdio. Returns seconds until the scan reply, or ``wait``."""
    site = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=site.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{site.server_address[1]}/"

    proc = subprocess.Popen(
        [PYTHON, "-m", "jsfind_mcp.server", "--transport", "stdio",
         "--no-config"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr_target,
        text=True, env=child_env(), encoding="utf-8", errors="replace",
        cwd=str(ROOT),
    )
    started = time.monotonic()
    try:
        proc.stdin.write(json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "verify", "version": "1"}},
        }) + "\n")
        proc.stdin.flush()

        # Read stdout in a thread: a blocking readline here would hang the
        # harness too and hide which side is stuck.
        lines: list[str] = []

        def drain() -> None:
            for line in proc.stdout:
                lines.append(line)

        threading.Thread(target=drain, daemon=True).start()
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline and not lines:
            time.sleep(0.1)
        check(f"{label}: handshake answered", bool(lines))

        proc.stdin.write(json.dumps({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "jsfind_scan",
                       "arguments": {"url": base, "mode": "deep"}},
        }) + "\n")
        proc.stdin.flush()

        reply = ""
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline and not reply:
            for line in lines:
                try:
                    if json.loads(line).get("id") == 2:
                        reply = line
                        break
                except json.JSONDecodeError:
                    continue
            if not reply:
                time.sleep(0.2)
        elapsed = time.monotonic() - started
        check(f"{label}: scan answered", bool(reply),
              "deadlocked" if not reply else f"{elapsed:.1f}s")
        return elapsed
    finally:
        proc.kill()
        site.shutdown()


def main() -> int:
    print("stderr deadlock check\n")
    print("A. stderr = PIPE, never read  (what a non-draining client does)")
    slow = attempt("A", subprocess.PIPE)

    print("\nB. stderr = DEVNULL  (same call, pipe removed)")
    fast = attempt("B", subprocess.DEVNULL)

    # The point is not speed but parity: both runs must have answered at all.
    # A that answers is the fix; the ratio is reported as evidence, not judged.
    print(f"\n  (A {slow:.1f}s vs B {fast:.1f}s — both answering is what matters)")

    log = ROOT / ".deadlock-check.log"
    check("diagnostics went to the log file",
          log.is_file() and log.stat().st_size > 0, str(log))
    try:
        log.unlink()
    except OSError:
        pass

    print("\n" + ("ALL PASS" if not FAILURES
                  else f"{len(FAILURES)} FAILED: {FAILURES}"))
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
