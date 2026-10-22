"""Banner rule tests.

The central contract of :mod:`jsfind_mcp.banner` is that **a match without a
version is not a finding**. These tests pin both halves of that: versionless
banners must produce nothing, and versioned ones must be recognized.

Run directly (``python tests/test_banners.py``) or under pytest.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jsfind_mcp.banner import BannerEngine, dedupe, summarize  # noqa: E402

#: Header sets that disclose a product but no version. None may be reported:
#: "Server: nginx" is the header's default and tells a tester nothing.
VERSIONLESS = [
    {"Server": "nginx"},
    {"Server": "Apache"},
    {"Server": "cloudflare"},
    {"Server": "Microsoft-IIS"},
    {"Server": "Jetty"},
    {"X-Powered-By": "Express"},
    {"X-Powered-By": "ASP.NET"},
    {"Server": "gunicorn"},
    {"Server": "Tengine"},
    {"X-AspNet-Version": "hidden"},
]

#: Header string -> expected (product, version). Every one must be reported.
VERSIONED = {
    "Server: nginx/1.18.0 (Ubuntu)": ("Nginx", "1.18.0"),
    "Server: openresty/1.21.4.1": ("OpenResty", "1.21.4.1"),
    "Server: Tengine/3.0.0": ("Tengine", "3.0.0"),
    "Server: Apache/2.4.41 (Ubuntu)": ("Apache HTTP Server", "2.4.41"),
    "Server: Microsoft-IIS/10.0": ("Microsoft IIS", "10.0"),
    "X-AspNet-Version: 4.0.30319": ("ASP.NET", "4.0.30319"),
    "Server: Jetty(9.4.35.v20210427)": ("Eclipse Jetty", "9.4.35"),
    "Server: Apache-Coyote/1.1": ("Apache Tomcat (Coyote)", "1.1"),
    "Server: Resin/4.0.30": ("Caucho Resin", "4.0.30"),
    "X-Powered-By: JBoss-EAP/7.4.5": ("JBoss", "7.4.5"),
    "X-Powered-By: PHP/8.2.1": ("PHP", "8.2.1"),
    "Server: Werkzeug/2.0.1 Python/3.9.7": ("Werkzeug", "2.0.1"),
    "Server: Python/3.9.7": ("Python", "3.9.7"),
    "Server: gunicorn/20.1.0": ("Gunicorn", "20.1.0"),
    "Server: uvicorn/0.23.2": ("Uvicorn", "0.23.2"),
    "Server: puma/5.6.4": ("Puma", "5.6.4"),
    "X-Powered-By: Express/4.18.2": ("Express", "4.18.2"),
    "X-Powered-By: Node.js/18.16.0": ("Node.js", "18.16.0"),
    "Server: LiteSpeed/7.4": ("LiteSpeed", "7.4"),
    "Server: h2o/2.2.0": ("H2O", "2.2.0"),
    "Server: haproxy/2.8.1": ("HAProxy", "2.8.1"),
    "Server: Kong/3.4.1": ("Kong", "3.4.1"),
    "Server: APISIX/3.9.1": ("Apache APISIX", "3.9.1"),
    "Server: envoy/1.27.0": ("Envoy", "1.27.0"),
    "Server: WebLogic Server 12.2.1": ("Oracle WebLogic", "12.2.1"),
    "Server: IBM WebSphere Application Server/9.0.5": (
        "IBM WebSphere", "9.0.5"),
    "Server: WildFly/26.1.3": ("WildFly", "26.1.3"),
    "Server: GlassFish Server Open Source Edition/4.0": ("GlassFish", "4.0"),
    "Server: Passenger/5.0.30": ("Phusion Passenger", "5.0.30"),
    "Server: WEBrick/1.7.0": ("WEBrick", "1.7.0"),
    "X-Powered-By: Ruby/3.2.2": ("Ruby", "3.2.2"),
    "X-Powered-By: Spring Boot/2.7.18": ("Spring Boot", "2.7.18"),
    "X-Oss-Server: AliyunOSS/2.0": ("阿里云 OSS", "2.0"),
}

#: An error page often prints the banner the header truncated.
ERROR_BODY = (
    "<html><head><title>404 Not Found</title></head><body>"
    "<h1>Not Found</h1><p>Apache/2.4.41 (Ubuntu) Server at example.com "
    "Port 80</p></body></html>"
)


def _split(raw: str) -> dict[str, str]:
    name, _, value = raw.partition(":")
    return {name.strip(): value.strip()}


def test_no_banner_without_version() -> None:
    engine = BannerEngine.default()
    for headers in VERSIONLESS:
        found = engine.match_headers(headers)
        assert not found, f"{list(headers.values())[0]!r} must not be reported"


def test_versioned_banners_are_reported() -> None:
    engine = BannerEngine.default()
    for raw, (product, version) in VERSIONED.items():
        found = engine.match_headers(_split(raw))
        pairs = [(banner.product, banner.version) for banner in found]
        assert (product, version) in pairs, \
            f"{raw!r} -> {pairs}, expected {(product, version)}"


def test_error_page_banner_is_read_from_body() -> None:
    engine = BannerEngine.default()
    found = engine.match_body(ERROR_BODY)
    assert ("Apache HTTP Server", "2.4.41") in [
        (banner.product, banner.version) for banner in found
    ]
    assert all(banner.scope == "body" for banner in found)


def test_every_shipped_rule_captures_a_version() -> None:
    """A rule with no capture group can never yield a version, so it is dropped."""
    engine = BannerEngine.default()
    fatal = [item for item in engine.diagnostics if "no version capture" in item]
    assert not fatal, f"rules without a version group: {fatal}"
    assert len(engine) >= 40, f"expected a full rule set, got {len(engine)}"


def test_dedupe_keeps_one_entry_per_product_version_host() -> None:
    engine = BannerEngine.default()
    found = engine.match_headers({"Server": "nginx/1.18.0"}, host="a.example")
    found += engine.match_headers({"Server": "nginx/1.18.0"}, host="a.example")
    banners = dedupe(found)
    assert len(banners) == 1
    summary = summarize(banners)
    assert summary["total"] == 1
    assert summary["by_product"] == {"Nginx": 1}


def test_same_product_on_two_hosts_stays_separate() -> None:
    engine = BannerEngine.default()
    found = engine.match_headers({"Server": "nginx/1.18.0"}, host="a.example")
    found += engine.match_headers({"Server": "nginx/1.18.0"}, host="b.example")
    assert len(dedupe(found)) == 2


def test_disabled_rule_is_dropped() -> None:
    engine = BannerEngine.default(disabled=["nginx"])
    assert not any(rule.id == "nginx" for rule in engine.rules)
    assert not engine.match_headers({"Server": "nginx/1.18.0"})


def main() -> int:
    failures = 0
    for name, function in sorted(globals().items()):
        if not name.startswith("test_") or not callable(function):
            continue
        try:
            function()
            print(f"  PASS  {name}")
        except AssertionError as exc:
            failures += 1
            print(f"  FAIL  {name}: {exc}")
    print("banner tests:", "all passed" if not failures else f"{failures} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())