"""Full-chain verification of the banner feature: engine, pipeline, report, MCP.

Run with ``python devtools/verify_banners.py``. It starts the bundled fixture
site, scans it, and asserts the contract end to end:

* every versioned fingerprint the site discloses is reported;
* the deliberately versionless headers on ``/api/v1`` produce nothing;
* the 404 error-page banner is recovered from the body;
* the report and the MCP tools carry the same data.
"""

import asyncio
import json
import logging
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "tests"))
logging.disable(logging.CRITICAL)

from jsfind_mcp.banner import BannerEngine  # noqa: E402
from jsfind_mcp.config import load_config  # noqa: E402
from jsfind_mcp.scanner import Scanner, Target  # noqa: E402
from jsfind_mcp.server import ScanStore, build_server  # noqa: E402
from localsite import LocalSite  # noqa: E402

#: what the fixture site discloses
EXPECTED = {
    ("Nginx", "1.18.0"),
    ("PHP", "8.2.1"),
    ("Express", "4.18.2"),
    ("Apache HTTP Server", "2.4.41"),
}

#: header sets carrying a product but no version
VERSIONLESS = ({"Server": "nginx"}, {"X-Powered-By": "Express"})


def check(label: str, ok: bool, detail: str = "") -> bool:
    mark = "PASS" if ok else "FAIL"
    print(f"  {mark}  {label}" + (f": {detail}" if detail and not ok else ""))
    return ok


async def call(server, name: str, **kwargs):
    out = await server.call_tool(name, kwargs)
    return json.loads(out[0].text)


async def main() -> int:
    ok = True
    with LocalSite() as site, tempfile.TemporaryDirectory() as output:
        config = load_config()
        config.js_dir = output
        result = await Scanner(config).scan(Target(url=site.base_url))

        found = {(b.product, b.version) for b in result.banners}
        print("banners found:")
        for banner in result.banners:
            print(f"    {banner.product:<22} {banner.version:<12} "
                  f"via {banner.header or 'body'}")

        print("\nengine contract")
        engine = BannerEngine.default()
        for headers in VERSIONLESS:
            ok &= check(f"{list(headers.values())[0]!r} -> nothing",
                        not engine.match_headers(headers))

        print("\npipeline contract")
        ok &= check("every versioned fingerprint reported",
                    EXPECTED <= found, f"missing {EXPECTED - found}")
        ok &= check("no versionless fingerprint reported",
                    not any(b.version == "" for b in result.banners))
        apache = [b for b in result.banners if b.product == "Apache HTTP Server"]
        ok &= check("404 error-page banner read from the body",
                    bool(apache) and apache[0].scope == "body")

        print("\nmcp")
        server = build_server(ScanStore(config))
        tools = await server.list_tools()
        names = {tool.name for tool in tools}
        ok &= check("jsfind_banners registered", "jsfind_banners" in names)
        ok &= check("tool count is stable", len(names) >= 18, f"got {len(names)}")
        ok &= check("no CLI-only tools", not any(
            n.endswith(("_report", "_js_strings")) for n in names), str(names))
        diagnostics = await call(server, "jsfind_diagnostics")
        ok &= check("diagnostics reports the tool list",
                    diagnostics["tool_count"] == len(names),
                    str(diagnostics.get("tool_count")))
        ok &= check("AST enabled", diagnostics["ast_enabled"] is True)

        scanned = await call(server, "jsfind_scan", url=site.base_url)
        ok &= check("scan summary carries banners",
                    scanned["banners"] == len(found))

        listed = await call(server, "jsfind_banners", scan_id=scanned["scan_id"])
        ok &= check("jsfind_banners returns them", listed["count"] == len(found))

        filtered = await call(server, "jsfind_banners",
                              scan_id=scanned["scan_id"], category="web_server")
        ok &= check("category filter works",
                    all(row["category"] == "web_server"
                        for row in filtered["banners"]))

        rules = await call(server, "jsfind_rules", kind="banner")
        ok &= check("banner rules exposed",
                    rules["count"] == len(BannerEngine.default()))

    print("\nresult:", "all checks passed" if ok else "FAILURES PRESENT")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
