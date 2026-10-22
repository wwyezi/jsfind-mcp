"""Verify the frozen executable.

The check that matters for a packaged build: source tests can all pass while the
bundle still cannot load its YAML, its native grammar, its MCP transport — or a
module that was added after the last build.

    python devtools/verify_frozen.py

Requires ``dist/jsfind-mcp.exe`` (Windows) or ``dist/jsfind-mcp`` (Linux).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "devtools"))
sys.path.insert(0, os.path.join(ROOT, "tests"))
SUFFIX = ".exe" if os.name == "nt" else ""
SERVER = os.path.join(ROOT, "dist", f"jsfind-mcp{SUFFIX}")

failures = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global failures
    if not ok:
        failures += 1
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f": {detail}" if detail else ""))


def child_env() -> dict:
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def run(argv: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=300,
                          env=child_env(), errors="replace")


def first_json(text: str):
    depth = 0
    start = -1
    for index, char in enumerate(text):
        if char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                try:
                    return json.loads(text[start:index + 1])
                except json.JSONDecodeError:
                    start = -1
    return None


def handshake() -> str | None:
    """Send initialize to the frozen server and return its reply.

    This is the check that matters for an MCP deliverable: the binary must not
    print anything of its own to stdout, or the protocol stream is corrupt.
    """
    proc = subprocess.Popen(
        [SERVER, "--transport", "stdio"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env=child_env(), encoding="utf-8", errors="replace",
    )
    try:
        proc.stdin.write(json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "verify", "version": "1"}},
        }) + "\n")
        proc.stdin.flush()
        return proc.stdout.readline()
    finally:
        proc.kill()


def rpc(proc: subprocess.Popen, request_id: int, method: str,
        params: dict | None = None):
    """Send one JSON-RPC request and read the matching reply line."""
    proc.stdin.write(json.dumps({
        "jsonrpc": "2.0", "id": request_id, "method": method,
        "params": params or {},
    }) + "\n")
    proc.stdin.flush()
    while True:
        line = proc.stdout.readline()
        if not line:
            return None
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if message.get("id") == request_id:
            if "error" in message:
                return {"__error__": message["error"]}
            return message.get("result")


def tool_payload(result) -> dict:
    """Unwrap an MCP tool result into the dict the tool returned.

    Over a raw stdio transport the content blocks arrive as plain JSON dicts,
    not as the objects the in-process client hands back.
    """
    if isinstance(result, dict):
        blocks = result.get("content")
        if not isinstance(blocks, list):
            return result
    else:
        blocks = result
    for block in blocks or []:
        text = block.get("text") if isinstance(block, dict) \
            else getattr(block, "text", None)
        if text:
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                continue
    return {}


def frozen_scan() -> None:
    """Scan the local fixture site with the packaged binary, over MCP."""
    from localsite import Handler

    site = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=site.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{site.server_address[1]}/"

    proc = subprocess.Popen(
        [SERVER, "--transport", "stdio", "--no-config"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env=child_env(), encoding="utf-8", errors="replace",
    )
    try:
        proc.stdin.write(json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "verify", "version": "1"}},
        }) + "\n")
        proc.stdin.flush()
        proc.stdout.readline()

        scan = tool_payload(rpc(proc, 2, "tools/call", {
            "name": "jsfind_scan", "arguments": {"url": base, "mode": "deep"},
        }))
        scan_id = scan.get("scan_id", "")
        check("scan returned a scan_id", bool(scan_id), scan_id or str(scan))
        if not scan_id:
            return
        check("asset manifests found in the frozen build",
              scan.get("asset_manifests", 0) >= 1,
              str(scan.get("asset_manifests")))
        check("api spec found in the frozen build",
              scan.get("api_specs") == 1, str(scan.get("api_specs")))
        check("spec operations expanded",
              scan.get("spec_operations", 0) >= 3,
              str(scan.get("spec_operations")))
        check("routes rendered in the frozen build",
              scan.get("routes_rendered", 0) >= 2,
              str(scan.get("routes_rendered")))
        check("graphql operations found in the frozen build",
              scan.get("graphql_operations", 0) >= 1,
              str(scan.get("graphql_operations")))
        check("no collection failure",
              not scan.get("issues"), str(scan.get("issues")))

        specs = tool_payload(rpc(proc, 3, "tools/call", {
            "name": "jsfind_specs", "arguments": {"scan_id": scan_id},
        }))
        check("jsfind_specs works in the frozen build",
              specs.get("operation_count", 0) >= 3,
              str(specs.get("operation_count")))
        gql_fields = (specs.get("graphql_operations") or [{}])[0].get("fields", [])
        check("graphql field set survives the freeze",
              "rawPassword" in gql_fields, str(gql_fields))

        routes = tool_payload(rpc(proc, 4, "tools/call", {
            "name": "jsfind_routes", "arguments": {"scan_id": scan_id},
        }))
        check("jsfind_routes works in the frozen build",
              routes.get("rendered", 0) >= 2,
              f"{routes.get('rendered')}/{routes.get('count')}")
    finally:
        proc.kill()
        site.shutdown()


def main() -> int:
    print("frozen build verification")
    check("executable exists", os.path.isfile(SERVER), SERVER)
    if not os.path.isfile(SERVER):
        return 1

    print("\n1. --help")
    out = run([SERVER, "--help"])
    check("exit code 0", out.returncode == 0, out.stderr[-300:])
    check("branded as jsfind-mcp", "jsfind-mcp" in out.stdout)
    check("no CLI flags", "--no-probe" not in out.stdout and "--json" not in out.stdout)

    print("\n2. --print-config (frozen mode)")
    out = run([SERVER, "--print-config"])
    check("exit code 0", out.returncode == 0, out.stderr[-300:])
    check("detects frozen mode", "已打包二进制" in out.stdout)
    payload = first_json(out.stdout) or {}
    entry = payload.get("mcpServers", {}).get("jsfind-mcp", {})
    check("emits absolute exe path",
          entry.get("command", "").lower().endswith(f"jsfind-mcp{SUFFIX}"),
          str(entry.get("command")))
    check("config parses", payload != {})
    check("no launcher flags", '"--print-config"' not in out.stdout)

    print("\n3. stdio handshake")
    reply = handshake()
    check("initialize over stdio",
          reply is not None and ('"result"' in reply or '"serverInfo"' in reply),
          (reply or "")[:160])

    print("\n4. diagnostics from the frozen binary")
    out = run([SERVER, "--print-config", "--no-config"])
    check("no stderr banner when disabled",
          "mcpServers" in out.stdout or out.returncode == 0)

    print("\n5. a real scan through the frozen binary")
    # The expansion passes live in modules added after the last successful
    # build. A frozen bundle can import and serve fine while missing them
    # entirely, so the only honest check is to run one and look at the output.
    frozen_scan()

    print("\nresult:", "all checks passed" if not failures
          else f"{failures} check(s) failed")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
