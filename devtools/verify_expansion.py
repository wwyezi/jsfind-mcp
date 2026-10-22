"""Verify the three expansion paths: asset manifests, route crawling, API specs.

Each is checked by what only that path could have found:

* **manifest** — ``/static/only-in-manifest.js`` is listed in the manifest and
  referenced by no page, so recovering it proves the manifest was read.
* **routes** — ``/internal/user/audit/list`` exists only inside the script a
  route loads, so recovering it proves the route was rendered.
* **spec** — ``/admin/role`` exists only in the OpenAPI document.

Run: ``python devtools/verify_expansion.py``
"""

import asyncio
import json
import logging
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "tests"))
logging.disable(logging.CRITICAL)

from jsfind_mcp.config import load_config  # noqa: E402
from jsfind_mcp.scanner import Scanner, Target  # noqa: E402
from localsite import LocalSite  # noqa: E402

failures = 0


def _caveats(result) -> list[str]:
    """The coverage caveats a caller would see, without building the whole view."""
    from jsfind_mcp.surface import build_surface

    view = build_surface(result)
    return list(view.get("coverage", {}).get("caveats", []))


def check(label: str, ok: bool, detail: str = "") -> None:
    global failures
    if not ok:
        failures += 1
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f": {detail}" if detail else ""))


async def main() -> int:
    with LocalSite() as site, tempfile.TemporaryDirectory() as js_dir:
        config = load_config()
        config.js_dir = js_dir
        result = await Scanner(config).scan(Target(url=site.base_url))

        urls = [e.url for e in result.endpoints]
        js_urls = {r.url for r in result.resources
                   if r.local_path and r.type.value in ("script", "chunk")}
        findings = [(f.rule_name, f.value) for f in result.findings]

        print("summary")
        print(f"  resources={result.statistics.resources} "
              f"endpoints={result.statistics.endpoints} "
              f"routes={result.statistics.routes} "
              f"findings={result.statistics.findings}")

        # -- B: asset manifest ------------------------------------------------
        print("\nB  asset manifest")
        check("manifest recorded", bool(result.assets),
              json.dumps(result.assets, ensure_ascii=False)[:120])
        check("only-in-manifest script fetched",
              any("only-in-manifest" in url for url in js_urls),
              str(sorted(u for u in js_urls if "manifest" in u)))
        check("endpoint found only in that script",
              any("/sys/audit/export" in u for u in urls))
        check("secret found only in that script",
              any("sk-admin-8f2c1e77b9d04a6f" in v for _n, v in findings))

        # -- A: route crawling ------------------------------------------------
        print("\nA  route crawling")
        check("routes recorded", bool(result.routes))
        check("at least one route rendered",
              any(r.get("rendered") for r in result.routes),
              str([r.get("path") for r in result.routes]))
        check("route-reported /user/list rendered",
              any(r["path"] == "/user/list" and r["rendered"]
                  for r in result.routes))
        check("dynamic route /user/:userId probed",
              any(r["params"] and r["parameterized"] for r in result.routes),
              str([(r["path"], r["params"]) for r in result.routes]))
        check("endpoint found only via a route",
              any("/internal/user/audit/list" in u for u in urls))
        check("route-loaded script analyzed",
              any("routes.js" in u for u in js_urls))

        # -- OpenAPI ----------------------------------------------------------
        print("\nOpenAPI spec")
        check("spec recorded", bool(result.specs),
              json.dumps(result.specs, ensure_ascii=False)[:140])
        spec_ops = [e for e in result.endpoints if e.evidence == "spec"]
        check("spec operations became endpoints", len(spec_ops) >= 3,
              f"got {len(spec_ops)}")
        check("spec-only path /admin/role present",
              any("/admin/role" in u for u in urls))
        check("spec path params recovered",
              any(e.method == "GET" and "id" in e.body_params
                  for e in spec_ops),
              str([(e.method, e.body_params) for e in spec_ops][:4]))
        check("request body fields recovered",
              any("roleName" in e.body_params for e in spec_ops))
        check("deprecated operation kept",
              any(e.method == "DELETE" for e in spec_ops))

        # -- protocols: WebSocket / SSE / GraphQL ----------------------------
        print("\nprotocols")
        sockets = [e for e in result.endpoints if e.type == "socket"]
        check("websocket addresses reported", len(sockets) >= 1,
              str([e.url for e in sockets]))
        check("websocket not typed as an HTTP api",
              all(e.type != "api" for e in sockets))
        check("websocket never GET-probed",
              all(not e.status_code for e in sockets),
              str([e.status_code for e in sockets]))
        check("websocket gets no HTTP request template",
              all(e.template is None for e in sockets))
        check("websocket leads surfaced in coverage",
              any("WebSocket" in c for c in _caveats(result)))
        check("sse endpoint found",
              any("/notify/stream" in u for u in urls))
        check("graphql endpoint found", any("/graphql" in u for u in urls))
        check("graphql operation document recovered",
              len(result.graphql) >= 1, str(len(result.graphql)))
        operation = result.graphql[0] if result.graphql else {}
        check("graphql operation named",
              operation.get("name") == "GetUserDetail",
              str(operation.get("name")))
        check("graphql field set extracted",
              "isAdmin" in operation.get("fields", []),
              str(operation.get("fields")))
        check("graphql camelCase sensitive fields flagged",
              {"isAdmin", "rawPassword", "internalToken"}
              <= set(operation.get("sensitive_fields", [])),
              str(operation.get("sensitive_fields")))

        # -- new sensitive rule groups ----------------------------------------
        print("\nsensitive rules")
        values = {f.value for f in result.findings}
        for label, needle in (("employee no", "E10293"),
                             ("login name", "zhangsan"),
                             ("OA base path", "/weaver/")):
            check(label, any(needle in v for v in values))

        # -- source map recovery ---------------------------------------------
        print("\nsource map")
        # The reason a leaked map is worth anything is its sourcesContent: a map
        # that is fetched but never parsed yields a resource entry and nothing
        # else, which reads as covered when it is not.
        from jsfind_mcp.jssearch import collect_js_files
        maps = [r for r in result.resources
                if getattr(getattr(r, "type", None), "value", "") == "sourcemap"]
        check("the map itself was fetched", bool(maps),
              str([getattr(getattr(r, "type", None), "value", "") for r in maps]))
        # The point of a map is its sourcesContent. Assert the content, not the
        # plumbing: a map that is fetched but never parsed still satisfies
        # every structural check while leaving the frontend unreadable.
        recovered = [f for f in collect_js_files(result)
                     if f.origin == "sourcemap-source"]
        check("a recovered original was saved to disk", bool(recovered),
              str([f.local_path for f in recovered]))
        check("recovered content is searchable",
              any("sk-map-recovered" in (f.local_path and open(
                  f.local_path, encoding="utf-8", errors="replace").read() or "")
                  for f in recovered),
              "searchable" if recovered else "no recovered file")
        check("the recovery is stated in hints",
              any("source map" in h for h in result.hints),
              str([h for h in result.hints if "source map" in h]))

        # -- transparency -----------------------------------------------------
        print("\ntransparency")
        joined = " | ".join(result.hints)
        check("manifest hit is stated", "清单" in joined, joined[:140])
        check("route render outcome is stated", "渲染了" in joined, joined[:160])
        check("spec contribution is stated", "接口规范" in joined)
        check("spec marked unverified", "未经请求验证" in joined)

    print("\nresult:", "all checks passed" if not failures
          else f"{failures} check(s) failed")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
