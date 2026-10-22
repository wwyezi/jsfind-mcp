"""Probe which discovery shapes the current extractor set misses.

Development aid: run it to see what is already covered before adding a rule,
so new work is genuinely new rather than a duplicate.

Four discovery paths are exercised per probe, because they fail independently:
the rule engine finds secrets, the dynamic-import pass finds lazily loaded
chunks, the protocol pass finds non-HTTP transports, and the manifest pass
finds the build's own file inventory.
"""

import sys

sys.path.insert(0, "src")

from jsfind_mcp.analyze import Engine, ResourceRef  # noqa: E402
from jsfind_mcp.discover import (  # noqa: E402
    find_manifest_references, find_spec_references, from_dynamic,
    from_protocols,
)

BACKTICK = chr(96)
DOLLAR = chr(36)

PROBES = {
    "websocket": 'const ws = new WebSocket("wss://push.example.com/ws/notify");',
    "graphql-op": "const Q = gql" + BACKTICK + "query GetUser(" + DOLLAR +
                  "id: ID!) { user(id: " + DOLLAR + "id) { name } }" + BACKTICK + ";",
    "asset-manifest": 'fetch("/asset-manifest.json").then(r=>r.json());',
    "sw-register": 'navigator.serviceWorker.register("/service-worker.js");',
    "precache": 'self.__precacheManifest = ["static/js/main.abc.js","static/css/main.css"];',
    "iframe": '<iframe src="/admin/frame.html" name="f"></iframe>',
    "openapi": 'const spec = "/v3/api-docs/swagger-config";',
    "config-js": '<script src="/config.js"></script><script src="/env.js"></script>',
    "sse": 'const es = new EventSource("/api/stream/events");',
    "graphql-url": 'axios.post("/graphql", {query:"{__typename}"});',
    "oa-wechat": 'var u = "/weixin/entry?src=wxwork";',
    "oa-seeyon": 'var s = "/seeyon/rest/";',
    "oa-ecology": 'var e = "/ecology/";',
    "employee-no": 'var u = {loginName:"zhangsan", employeeNo:"E10293"};',
    "cn-name": 'var realname = "zhangsan"; var account = "li.wang";',
    "phone-intl": 'var tel = "+8613800138000";',
    "bank-card": 'var card = "6222021234567890123";',
}


def main() -> int:
    engine = Engine(Engine.default_ruleset())
    print("discovery coverage probe\n")
    header = ("shape", "findings", "candidates", "dynamic", "protocol",
              "manifest", "spec")
    print("  %-16s %-9s %-11s %-18s %-22s %-9s %s" % header)
    for name, body in PROBES.items():
        result = engine.analyze(ResourceRef(url="probe.js"), body)
        dynamic, _hints = from_dynamic("http://x.test/app.js", body)
        protocol, operations, _hints = from_protocols(
            "http://x.test/app.js", body)
        manifests = find_manifest_references("http://x.test/", body)
        specs = find_spec_references("http://x.test/", body)
        protocol_ids = [c.rule_id for c in protocol]
        protocol_ids += [f"op:{o.kind}/{o.name or '-'}" for o in operations[:2]]
        print("  %-16s %-9d %-11d %-18s %-22s %-9d %d" % (
            name, len(result.findings), len(result.candidates),
            ", ".join(d.rule_id for d in dynamic) or "-",
            ", ".join(protocol_ids) or "-",
            len(manifests), len(specs)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
