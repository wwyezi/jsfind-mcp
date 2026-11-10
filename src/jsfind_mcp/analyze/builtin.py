"""URL-extraction rules hard-wired into the scanner.

These are compiled unconditionally and cannot be disabled through rule files, so
API discovery never depends on configuration. User rule files may add to this
set but not remove it.
"""

from __future__ import annotations

from ..model import RuleCategory, Severity
from ..rules import CompiledRule

# Method-bearing patterns capture the verb in a second group.
API_RULES: list[dict] = [
    {
        "id": "url.wrapped-call",
        "name": "Wrapped API call",
        # webpack-minified bundles almost always wrap the request layer:
        # `ce("/checkToken", {...}, "post")`. A bare identifier followed by a
        # quoted path is the most common API shape there is, and it is not
        # reachable through any other rule. Non-API callees are excluded so
        # `import("/x")` and `alert("/x")` do not inflate the report.
        "pattern": r"""(?i)\b(?!import(?:Scripts)?\b|require\b|alert\b"""
                   r"""|confirm\b|prompt\b|push\b|replace\b|assign\b"""
                   r"""|exec\b|match\b|test\b|split\b|indexOf\b"""
                   r"""|querySelector\w*\b|getElement\w+\b|addEventListener\b"""
                   r"""|setAttribute\b)[A-Za-z_$][\w$]*\s*\(\s*"""
                   r"""["'](/[\w./?=&%~-]+)["']""",
        "group": 1,
    },
    {
        "id": "url.request-config",
        "name": "Request config URL",
        # `url: D.a+"/downloadList"` and `url: "/agentLogin"` -- a request
        # config field, so the path is a request target however it was built.
        "pattern": r"""(?i)\b(?:url|uri|endpoint|request_url|api_url)\s*[:=]\s*"""
                   r"""(?:[\w.$]+\s*\+\s*)?["'](/[\w./?=&%~-]+)["']""",
        "group": 1,
    },
    {
        "id": "url.api-call",
        "name": "API request URL",
        "pattern": r"""(?i)((?:\$fetch)|(?:ofetch)|(?:\$ofetch)|(?:ky)|(?:fetch)|"""
                   r"""(?:axios\.(?:get|post|put|delete|patch|request))|"""
                   r"""(?:\$\s*\.\s*(?:get|post|put|delete|patch|getJSON|ajax))|"""
                   r"""(?:ajax)|(?:request))\s*\(\s*["']([^"']+)["']""",
        "group": 2,
        "method_group": 1,
    },
    {
        "id": "url.xhr-open",
        "name": "XMLHttpRequest URL",
        "pattern": r"""(?i)\.open\s*\(\s*["'](get|post|put|delete|patch|head|options)["']\s*,"""
                   r"""\s*["']([^"']+)["']""",
        "group": 2,
        "method_group": 1,
    },
    {
        "id": "url.api-prefix",
        "name": "API path prefix",
        "pattern": r"""(?:^|[\s"'`])(/(?:api|v[0-9]+|rest|graphql|gateway|ws)/[^\s"'<>{}|\\`\[\]]+)""",
        "group": 1,
    },
    {
        "id": "url.vue-route",
        "name": "Vue router path",
        "pattern": r"""(?i)path\s*:\s*["']([a-zA-Z0-9_?=/.-]+)["'][\s\S]{0,40}component\s*:""",
        "group": 1,
    },
    {
        "id": "url.react-route-element",
        "name": "React router path (element config)",
        "pattern": r"""\{\s*path\s*:\s*["']([^"'\s]{1,200})["']\s*,\s*"""
                   r"""(?:element|children|Component|loader|index)\s*[,:]""",
        "group": 1,
    },
    {
        "id": "url.react-route-jsx",
        "name": "React router path (compiled JSX)",
        "pattern": r"""(?i)(?:createElement|jsx|jsxs)\s*\(\s*"?[A-Za-z$_][\w$]*"?\s*,\s*"""
                   r"""\{[^{}]{0,200}?path\s*:\s*["']([^"']{1,200})["']""",
        "group": 1,
    },
    {
        "id": "url.svelte-route",
        "name": "SvelteKit / Nuxt route path",
        "pattern": r"""(?i)(?:routes\s*[:=]|goto\s*\()\s*["'](/[a-zA-Z0-9_/?=&.-]*)["']""",
        "group": 1,
    },
    {
        "id": "url.assignment",
        "name": "URL assignment",
        "pattern": r"""(?i)(?:url|href|src)\s*[:=]\s*(?:[\w$.]+\s*\+\s*)?["']([^"']+)["']""",
        "group": 1,
    },
    {
        "id": "url.attribute",
        "name": "HTML URL attribute",
        "pattern": r"""(?i)(?:href|src|url|action|data-(?:url|src|href))\s*=\s*["']([^"'\s]+)["']""",
        "group": 1,
    },
    {
        "id": "url.path-variable",
        "name": "Path variable",
        "pattern": r"""(?i)(?:path|route|uri|url|endpoint|baseURL|base_url|prefix|api_?path|"""
                   r"""api_?url|redirect|next|callback_?url|return_?url)\s*[:=]\s*"""
                   r"""["']([^"']*/[^"']*)["']""",
        "group": 1,
    },
    {
        "id": "url.quoted",
        "name": "Quoted URL",
        # A quoted path that is immediately a value in a webpack module table —
        # "/ocq":function(e,t,n){...} — is a module key, not an interface. The
        # negative lookahead drops exactly that shape; the batch kind gate in
        # localfile then keeps real short paths (/api, /home).
        "pattern": r"""["'](https?://[^"'\s]+|(?:\.\./|\./|/)[^"'\s<>{}|\\`\[\]]+)["'](?!\s*:\s*function)""",
        "group": 1,
    },
    {
        "id": "url.static-resource",
        "name": "Static resource",
        "pattern": r"""(?i)["']((?:\.\./|\./|/)?[\w./-]+\.(?:js|mjs|jsx|ts|tsx|json|xml|html?|css|map|wasm))["']""",
        "group": 1,
    },
    {
        "id": "url.webpack-loader",
        "name": "Webpack loader path",
        "pattern": r"""function\s+\w+\([^)]*\)\s*\{\s*return\s+\w+\.p\s*\+\s*["']([^"']{2,})["']""",
        "group": 1,
    },
]

# Rule id -> what the discovery layer should do with a match. The AST layer
# reaches greater precision, so the regex pass is mainly a safety net and a
# fallback for bundles the parser cannot handle.
#: Evidence rank for an operation declared by an API specification. It sits
#: above a static inference because the author wrote it down.
EVIDENCE_SPEC = "spec"

RULE_KIND = {
    "url.wrapped-call": "endpoint",
    "url.request-config": "endpoint",
    "url.api-call": "endpoint",
    "url.api-prefix": "endpoint",
    "url.path-variable": "endpoint",
    "url.xhr-open": "endpoint",
    "url.vue-route": "route",
    "url.react-route-element": "route",
    "url.react-route-jsx": "route",
    "url.svelte-route": "route",
    "url.webpack-loader": "chunk",
    "url.static-resource": "resource",
    "url.assignment": "candidate",
    "url.attribute": "candidate",
    "url.quoted": "candidate",
}


def api_rules() -> list[CompiledRule]:
    """Compile and return the built-in URL rules."""
    out: list[CompiledRule] = []
    for spec in API_RULES:
        out.append(CompiledRule(
            id=spec["id"],
            name=spec["name"],
            category=RuleCategory.URL,
            severity=Severity.INFO,
            group=spec.get("group", 0),
            method_group=spec.get("method_group", 0),
            enabled=True,
            source_pattern=spec["pattern"],
            ignore_case=True,
        ))
    return out