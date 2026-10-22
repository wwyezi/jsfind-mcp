"""JavaScript text pass: regex candidates, SPA signals and base paths.

This pass runs on every script regardless of parseability, so it is the safety
net for truncated or malformed bundles the AST cannot read. It also owns the
cheap SPA signals that explain why runtime evidence may be absent.
"""

from __future__ import annotations

import re

from urllib.parse import urlparse

from ..analyze import Engine, ResourceRef
from ..model import ResourceType
from ..utils import (
    CONTEXT_SPAN_LINES,
    extract_context,
    is_static_asset_path,
    is_javascript_path,
    is_source_map_path,
    line_column,
    line_starts,
    looks_like_path,
)
from .basepath import MAX_BASE_PATHS_PER_FILE, scan_base_path_text
from .hosts import hosts_from_text
from .types import Candidate, JSResult, Kind, SPAEvidence, is_noise_endpoint

# A bundle past this size is worth rendering in a browser: it almost always
# loads chunks dynamically rather than declaring them in the HTML.
LARGE_BUNDLE_BYTES = 512 * 1024

# NOTE: this is a second source of truth alongside builtin.RULE_KIND. The two
# are kept in step by hand; adding a rule means touching both. They were not in
# step at one point and the classifier silently downgraded every new rule to
# Kind.ROUTE.
_ENDPOINT_RULES = frozenset({
    "url.api-call", "url.api-prefix", "url.path-variable", "url.xhr-open",
    "url.wrapped-call", "url.request-config",
})
_ROUTE_RULES = frozenset({
    "url.vue-route", "url.react-route-element", "url.react-route-jsx",
    "url.svelte-route",
})


def from_javascript(source_url: str, body: str, engine: Engine) -> JSResult:
    """Apply the regex rule set to one script and collect SPA signals."""
    result = JSResult()
    if not body:
        return result

    analysis = engine.analyze(ResourceRef(url=source_url, type=ResourceType.SCRIPT), body)
    result.findings.extend(analysis.findings)
    starts = line_starts(body)

    seen: dict[str, Candidate] = {}
    for extracted in analysis.candidates:
        kind = _classify(extracted.rule_id, extracted.raw)
        if kind in (Kind.ENDPOINT, Kind.ROUTE):
            # Quoted field names, i18n labels and regex fragments are not
            # request targets; keeping them floods the path reports.
            if not looks_like_path(extracted.raw) or is_noise_endpoint(extracted.raw):
                continue
        key = f"{kind}\x00{extracted.raw}"
        # Two rules can hit the same path: url.quoted sees "/checkToken" and
        # url.wrapped-call sees ce("/checkToken", ..., "post"). The second
        # knows the verb and the first does not, so a plain "already seen"
        # check would keep the weaker of the two and every wrapped call would
        # arrive with method="".
        method = _normalize_method(extracted.method) or (
            _infer_method(body, extracted.offset) if extracted.offset else "")
        if key in seen:
            if method and not seen[key].method:
                seen[key].method = method
            continue
        candidate = Candidate(
            raw=extracted.raw,
            kind=kind,
            source_url=source_url,
            source="regex",
            method=method,
            rule_id=extracted.rule_id,
        )
        seen[key] = candidate
        result.candidates.append(candidate)
        if kind in (Kind.ENDPOINT, Kind.ROUTE) and extracted.offset > 0:
            candidate.line, candidate.column = line_column(
                body, extracted.offset, starts)
            candidate.context_lines = extract_context(
                body, extracted.offset, CONTEXT_SPAN_LINES, extracted.raw
            )

    result.spa = spa_evidence(body)
    # A base path often lives in a config blob the AST does not model, so the
    # text pass looks for the same assignments.
    result.base_paths.extend(scan_base_path_text(body, MAX_BASE_PATHS_PER_FILE))
    result.hosts.extend(hosts_from_text(source_url, body))
    return result


#: Method names the rules carry are the callee text ("AXIOS.PUT", "FETCH",
#: "$AJAX"), not a verb. Normalising here keeps the report readable and makes
#: "which endpoints are writes" a query instead of a text-matching exercise.
_VERB_FROM_CALLEE = {
    "get": "GET", "post": "POST", "put": "PUT", "delete": "DELETE",
    "patch": "PATCH", "head": "HEAD", "options": "OPTIONS",
    "getjson": "GET", "ajax": "GET", "request": "", "fetch": "GET",
    "ofetch": "GET", "json": "GET",
}


def _normalize_method(value) -> str:
    """Turn a callee name into an HTTP verb, or "" when it says nothing."""
    text = (value or "").strip()
    if not text:
        return ""
    if text.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD",
                        "OPTIONS"):
        return text.upper()
    # "axios.put" / "$ajax.get" -- the last segment names the verb.
    tail = text.replace(" ", "").split(".")[-1].lower()
    if tail in _VERB_FROM_CALLEE:
        return _VERB_FROM_CALLEE[tail]
    if tail.startswith("ajax") or tail.startswith("json"):
        return "GET"
    return ""


#: HTTP verbs worth inferring from surrounding source.
_METHOD_NAMES = ("get", "post", "put", "delete", "patch", "head", "options")
_METHOD_RE = re.compile(
    r"(?i)\b(?:method|verb|httpMethod)\s*[:=]\s*[\"'](%s)\b" % "|".join(_METHOD_NAMES))
_TRAILING_ARG_RE = re.compile(
    r",[ \t]*[\"'](%s)[\"'][ \t]*\)" % "|".join(_METHOD_NAMES))
#: Characters that end a statement. A method found on the other side of one
#: belongs to a different call -- without this bound a fixed-size window walks
#: into the neighbouring line and labels every path in the file with the same
#: verb.
_STATEMENT_BREAKS = ";}\n"


def _statement_window(body: str, offset: int) -> str:
    """The slice of source around ``offset`` that belongs to one call.

    Bracket-balanced, not fixed-width: ``ce("/path", {token: e}, "post")``
    keeps its trailing verb while a neighbouring call's verb is left outside.
    A ``;`` or a newline still cuts it, so a whole minified line cannot bleed
    one method onto every path it contains.
    """
    start = offset
    depth = 0
    while start > 0:
        ch = body[start - 1]
        if ch in ";\n":
            break
        if ch in ")}]":
            depth += 1
        elif ch in "({[":
            # Include the opening bracket: the window is the balanced
            # expression, delimiters and all, so a trailing ")" is present for
            # the pattern to see.
            if depth == 0:
                start -= 1
                break
            depth -= 1
        start -= 1
    end = offset
    depth = 0
    while end < len(body):
        ch = body[end]
        if ch in ";\n":
            break
        if ch in "({[":
            depth += 1
        elif ch in ")}]":
            if depth == 0:
                end += 1
                break
            depth -= 1
        end += 1
    return body[start:end]


def _infer_method(body: str, offset: int) -> str:
    """Find the HTTP verb next to a path that did not declare one.

    Two shapes the regex rules cannot carry on their own:

    * ``{method: "post", url: "/agentLogin"}`` -- a request config object,
      where the verb is a sibling key;
    * ``ce("/checkToken", {token: e}, "post")`` -- a wrapped call whose last
      argument is the verb.

    The search is bounded by statement breaks so one call's verb cannot be
    attributed to its neighbours. Returns "" when nothing is nearby, which is
    the honest answer rather than guessing GET.
    """
    if offset <= 0 or not body:
        return ""
    window = _statement_window(body, offset)
    match = _METHOD_RE.search(window)
    if match:
        return match.group(1).upper()
    match = _TRAILING_ARG_RE.search(window)
    if match:
        return match.group(1).upper()
    return ""


def _classify(rule_id: str, raw: str) -> str:
    if rule_id in _ENDPOINT_RULES:
        return Kind.ENDPOINT
    if rule_id in _ROUTE_RULES:
        return Kind.ROUTE
    if rule_id == "url.webpack-loader":
        return Kind.CHUNK
    if is_source_map_path(raw):
        return Kind.SOURCEMAP
    if is_javascript_path(raw):
        return Kind.SCRIPT
    if is_static_asset_path(urlparse(raw).path):
        return Kind.ASSET
    # The fallback used to be Kind.ROUTE, which turned every generic quoted
    # path into a page route. A bare path with no extension is an HTTP
    # surface, and page routes only come from the explicit route rules --
    # the fallback now says so instead of guessing.
    return Kind.ENDPOINT


def spa_evidence(body: str) -> SPAEvidence:
    """Cheap signals that the page loads code dynamically."""
    lower = body.lower()
    return SPAEvidence(
        dynamic_import="import(" in lower,
        history_routing="history.pushstate" in lower or "history.replacestate" in lower,
        hash_routing=("createwebhashhistory" in lower
                      or 'mode:"hash"' in lower
                      or "mode:'hash'" in lower),
        dynamic_script='createelement("script"' in lower
                       or "createelement('script'" in lower,
        webpack="webpackchunk" in lower or "__webpack_require__" in lower,
        requirejs="requirejs.config" in lower or "require.config" in lower,
        large_bundle=len(body.encode("utf-8", "replace")) >= LARGE_BUNDLE_BYTES,
    )
