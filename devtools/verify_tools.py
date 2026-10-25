"""Check the MCP tools can read every discovery pass's output.

Drives the same tool functions an agent would call, against the shared fixture
site in ``tests/localsite.py``, so each result field is proven *reachable* and
not merely produced. A field the model cannot read is a field that does not
exist as far as a test is concerned.

Run: python devtools/verify_tools.py
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))

from localsite import Handler  # noqa: E402

from jsfind_mcp.server import ScanStore, build_server  # noqa: E402

FAILURES: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILURES.append(label)


async def run() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}/"

    mcp = build_server(ScanStore())
    names = {tool.name for tool in await mcp.list_tools()}

    async def call(name: str, **arguments):
        """Call a tool the way the MCP transport would, then unwrap the dict."""
        result = await mcp.call_tool(name, arguments)
        if isinstance(result, dict):
            return result
        for block in result:
            text = block.get("text") if isinstance(block, dict) \
                else getattr(block, "text", None)
            if text:
                return json.loads(text)
        return {}

    print("[tool inventory]")
    check("jsfind_specs registered", "jsfind_specs" in names)
    check("jsfind_routes registered", "jsfind_routes" in names)
    check("no CLI-only tools", not any(
        n.endswith(("_report", "_js_strings")) for n in names))

    scan = await call("jsfind_scan", url=base)
    scan_id = scan.get("scan_id", "")
    check("scan returned a scan_id", bool(scan_id), scan_id)
    if not scan_id:
        server.shutdown()
        return

    print("\n[jsfind_scan: output directory]")
    # The model must be able to place the files itself, and must be told where
    # they actually landed -- a relative config value resolves against the
    # server's cwd, which the model has no way to know.
    import tempfile
    from pathlib import Path as _P
    chosen = _P(tempfile.mkdtemp(prefix="jsfind-verify-")) / "chosen"
    placed = await call("jsfind_scan", url=base, js_dir=str(chosen))
    leaf = placed.get("js_dir", "")
    check("per-scan js_dir honoured",
          bool(leaf) and leaf.lower().startswith(str(chosen).lower())
          and _P(leaf).is_absolute(), leaf)
    check("directory really was written to",
          bool(leaf) and _P(leaf).is_dir(), leaf)
    check("js_saved reported", placed.get("js_saved") is True)
    dry = await call("jsfind_scan", url=base, save_js=False)
    check("save_js=false writes nothing",
          dry.get("js_dir") == "" and dry.get("js_saved") is False,
          str(dry.get("js_dir")))
    check("default scan still reports a directory",
          _P(scan.get("js_dir", "x")).is_absolute(), str(scan.get("js_dir")))

    print("\n[jsfind_scan]")
    check("routes_rendered reported", scan.get("routes_rendered", 0) >= 1,
          str(scan.get("routes_rendered")))
    check("api_specs reported", scan.get("api_specs") == 1,
          str(scan.get("api_specs")))
    check("spec_operations reported", scan.get("spec_operations", 0) >= 3,
          str(scan.get("spec_operations")))
    check("asset_manifests reported", scan.get("asset_manifests", 0) >= 1,
          str(scan.get("asset_manifests")))
    check("graphql_operations reported", scan.get("graphql_operations", 0) >= 1,
          str(scan.get("graphql_operations")))
    check("no collection failure", not scan.get("issues"), str(scan.get("issues")))

    print("\n[jsfind_routes]")
    routes = await call("jsfind_routes", scan_id=scan_id)
    by_path = {r["path"]: r for r in routes["routes"]}
    check("renders reported", routes.get("rendered", 0) >= 1,
          f"{routes.get('rendered')}/{routes.get('count')}")
    user_list = by_path.get("/user/list", {})
    check("per-route scripts exposed",
          any("routes.js" in s for s in user_list.get("scripts", [])),
          str(user_list.get("scripts")))
    dynamic = next((r for r in routes["routes"] if r.get("parameterized")), {})
    check("parameterized route flagged", dynamic.get("parameterized") is True,
          str(dynamic.get("params")))
    only = await call("jsfind_routes", scan_id=scan_id, rendered_only=True)
    check("rendered_only filter",
          all(r["rendered"] for r in only["routes"]), str(only["count"]))

    print("\n[jsfind_specs]")
    specs = await call("jsfind_specs", scan_id=scan_id)
    check("spec document listed", len(specs.get("specs", [])) == 1,
          str(specs.get("specs"))[:120])
    check("manifests listed", len(specs.get("asset_manifests", [])) >= 1)
    check("operations listed", specs.get("operation_count", 0) >= 3,
          str(specs.get("operation_count")))
    role = next((o for o in specs["operations"] if "/admin/role" in o["path"]), {})
    check("spec-only path exposed", bool(role), str(specs.get("operation_count")))
    check("declared body params exposed",
          "roleName" in role.get("declared_body_params", []),
          str(role.get("declared_body_params")))
    check("declared params never probed", role.get("probed") is False)
    check("graphql operations exposed", specs.get("graphql_count", 0) >= 1,
          str(specs.get("graphql_count")))
    operation = (specs.get("graphql_operations") or [{}])[0]
    check("graphql operation named", operation.get("name") == "GetUserDetail",
          str(operation.get("name")))
    check("graphql field set exposed",
          "isAdmin" in operation.get("fields", []), str(operation.get("fields")))
    check("graphql sensitive fields flagged",
          {"isAdmin", "rawPassword"}
          <= set(operation.get("sensitive_fields", [])),
          str(operation.get("sensitive_fields")))

    print("\n[jsfind_endpoints]")
    endpoints = await call("jsfind_endpoints", scan_id=scan_id, limit=200)
    sockets = [e for e in endpoints["endpoints"] if e.get("kind") == "socket"]
    check("sockets reachable through the tool", bool(sockets),
          str([e["url"] for e in sockets]))
    check("socket rows carry their kind",
          all(e.get("kind") == "socket" for e in sockets))
    check("socket rows are unprobed, not falsely absent",
          all(e.get("signal") == "unprobed" for e in sockets),
          str([e.get("signal") for e in sockets]))
    check("kind legend explains socket",
          "socket" in (endpoints.get("kind_legend") or {}),
          str(endpoints.get("kind_legend")))
    only_sockets = await call("jsfind_endpoints", scan_id=scan_id, kind="socket")
    check("kind filter works", only_sockets["endpoints"]
          and all(e["kind"] == "socket" for e in only_sockets["endpoints"]),
          str(only_sockets.get("total")))

    print("\n[jsfind_surface]")
    surface = await call("jsfind_surface", scan_id=scan_id)
    kinds = {lead["kind"] for lead in surface["leads"]}
    check("spec leads surfaced", "spec_operation" in kinds, str(sorted(kinds)))
    check("graphql leads surfaced", "graphql_operation" in kinds,
          str(sorted(kinds)))
    check("socket leads surfaced", "socket" in kinds, str(sorted(kinds)))
    coverage = surface["coverage"]
    check("coverage reports specs", coverage.get("api_specs") == 1)
    check("coverage reports manifests", coverage.get("asset_manifests", 0) >= 1)
    check("coverage reports renders", coverage.get("routes_rendered", 0) >= 1,
          str(coverage.get("routes_rendered")))
    check("coverage admits sockets were not probed",
          any("WebSocket" in c for c in coverage.get("caveats", [])),
          str(coverage.get("caveats"))[:160])

    print("\n[call hygiene: a timeout that is not a number]")
    # A model forwarding an operator's config sends whatever it saw there, and
    # a bare env-var name is the common case. That must cost a default budget,
    # not the call: a strict-typed client rejects it before it is even sent,
    # which surfaces as "the tools vanished".
    bad = await call("jsfind_scan", url=base,
                     timeout_seconds="REQUEST_TIMEOUT")
    check("non-numeric timeout does not fail the call",
          bool(bad.get("scan_id")), str(bad)[:160])
    check("falls back to the configured default budget",
          float(bad.get("timeout_seconds", 0)) > 0,
          str(bad.get("timeout_seconds")))

    server.shutdown()


def main() -> int:
    # Run from a scratch directory. One scan deliberately exercises the default
    # output directory, and that resolves against the process cwd -- without
    # this the suite drops a jsfind-js/ tree into the repository every time it
    # runs. A test that dirties the working tree is a test people stop running.
    scratch = tempfile.mkdtemp(prefix="jsfind-verify-tools-")
    previous = os.getcwd()
    os.chdir(scratch)
    try:
        asyncio.run(run())
    finally:
        os.chdir(previous)
        shutil.rmtree(scratch, ignore_errors=True)
    print("\n" + ("ALL PASS" if not FAILURES
                  else f"{len(FAILURES)} FAILED: {FAILURES}"))
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())