"""Front-end route enumeration, and what loading each one pulls in.

A router config is the closest thing a front end has to a map of itself. Reading
it yields every view path; *visiting* each path yields the scripts that view
loads on demand — which is the entire point, because a lazy-loaded view's code
is invisible until the route is rendered.

Route guards are frequently not authorization, so navigating straight to a view
often renders it and fires its own requests. Rendering is therefore read-only:
paths are fetched with GET, nothing is submitted, and the scan never
authenticates.

What cannot be enumerated is stated rather than guessed: a path whose dynamic
segment has an unbounded value space (``/user/:id``) is rendered once with a
probe value and marked ``parameterized``, so a reader knows the shape was
confirmed but the full space was not walked.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..utils import is_static_asset_path

#: Value substituted for a dynamic segment when rendering a route.
_PROBE_VALUE = "1"

#: Router configs frequently spell a param several ways.
_PLACEHOLDER_PATTERNS = (
    re.compile(r":([A-Za-z_][A-Za-z0-9_]*)"),          # /user/:id
    re.compile(r"\*([A-Za-z_][A-Za-z0-9_]*)"),         # /files/*path
    re.compile(r"\(\.\*\)"),                            # /(.*)
    re.compile(r"\[(\.\.\.)?([^\]]+)\]"),                # /a/[...b]
)

#: Segments that indicate a catch-all rather than a single view.
_CATCHALL = ("*", "**", "(.*)", "(:pathMatch)", "[...]", "0")

#: A probe value is enough to tell "this route renders" from "this 404s".
_PROBE_MARKERS = ("__not_a_real_user__", "1")

#: How many routes one scan will render before the budget is spent.
DEFAULT_ROUTE_BUDGET = 40

#: Routes shorter than this are almost certainly API paths, not views.
_MIN_ROUTE_LEN = 2


@dataclass
class Route:
    """One navigable front-end path and what is known about it."""

    path: str = ""
    #: names of the dynamic segments, in order
    params: list[str] = field(default_factory=list)
    #: True when a dynamic segment was substituted with a probe value
    parameterized: bool = False
    #: the router config or literal this route was read from
    source_url: str = ""
    line: int = 0
    #: scripts the rendered route pulled in, filled in by the crawler
    scripts: list[str] = field(default_factory=list)
    #: endpoints the rendered route exposed, filled in by the crawler
    endpoints: list[str] = field(default_factory=list)
    #: set when the route was fetched and what came back
    status_code: int = 0
    rendered: bool = False
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "params": self.params,
            "parameterized": self.parameterized,
            "source_url": self.source_url,
            "line": self.line,
            "status_code": self.status_code,
            "rendered": self.rendered,
            "scripts": self.scripts,
            "endpoints": self.endpoints,
            "note": self.note,
        }


def collect_routes(result) -> dict[str, Route]:
    """Build the route table from an already-extracted result.

    Reads the framework route records the pipeline collected, so it needs no
    second pass over the source. Anything with a file extension is dropped:
    a ``.json`` or ``.css`` reference is a static asset that some extractor
    flagged, not a path a router could render.
    """
    routes: dict[str, Route] = {}
    for endpoint in result.endpoints:
        if endpoint.type != "route":
            continue
        path = _route_path(endpoint.url, result.target)
        if not path or is_static_asset_path(path):
            continue
        route = routes.get(path)
        if route is None:
            route = Route(path=path, source_url=endpoint.source_url,
                          line=endpoint.line)
            routes[path] = route
        for name in route_param_names(path):
            if name not in route.params:
                route.params.append(name)
    for route in routes.values():
        route.parameterized = bool(route.params)
    return routes


def renderable_paths(routes: dict[str, Route],
                     budget: int = DEFAULT_ROUTE_BUDGET) -> list[tuple[Route, str]]:
    """Pair each route with the concrete path to GET.

    Ordered shallowest-first: the entry-level views are the ones that establish
    whether route crawling is working at all, and they load the shared chunks.
    """
    pairs = []
    for route in routes.values():
        concrete, ok = _concretize(route.path)
        if not ok:
            continue
        pairs.append((route, concrete))
    pairs.sort(key=lambda item: (item[1].count("/"), item[1]))
    return pairs[:budget]


def _concretize(path: str) -> tuple[str, bool]:
    """Turn a route template into a fetchable path."""
    if not path or len(path) < _MIN_ROUTE_LEN:
        return "", False
    if not path.startswith("/"):
        return "", False
    # An API-looking path is not a view; rendering it proves nothing.
    if _looks_like_api(path):
        return "", False
    if not _has_placeholder(path):
        return path, True
    out = _PLACEHOLDER_PATTERNS[0].sub(_PROBE_VALUE, path)
    out = _PLACEHOLDER_PATTERNS[1].sub(_PROBE_VALUE, out)
    out = _PLACEHOLDER_PATTERNS[2].sub("probe", out)
    out = _PLACEHOLDER_PATTERNS[3].sub("probe", out)
    return out, True


def _has_placeholder(path: str) -> bool:
    if ":(" in path:
        return True
    return any(pattern.search(path) for pattern in _PLACEHOLDER_PATTERNS)


def _looks_like_api(path: str) -> bool:
    """Whether a path is an interface rather than a view."""
    lowered = path.lower()
    if any(marker in lowered for marker in (
            "/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql",
            "/ajax/", "/service/", "/rpc/", ".json", ".xml")):
        return True
    # A file extension means it is a resource, not a route.
    tail = lowered.rstrip("/").rsplit("/", 1)[-1]
    return "." in tail and tail.rsplit(".", 1)[-1] in {
        "json", "xml", "js", "css", "png", "jpg", "svg", "ico", "map",
        "html", "htm", "pdf", "zip",
    }


def _route_path(url: str, target: str) -> str:
    """Path part of a route URL, relative to the target when possible."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    path = parsed.path or ""
    if not path:
        return ""
    base = urlparse(target).path or "/"
    if base not in ("", "/") and path.startswith(base.rstrip("/")):
        trimmed = path[len(base.rstrip("/")):]
        if trimmed.startswith("/"):
            return trimmed
    if parsed.query or parsed.fragment:
        return ""
    return path


def route_param_names(path: str) -> list[str]:
    """Dynamic segment names in a route path, in order."""
    names: list[str] = []
    for pattern in _PLACEHOLDER_PATTERNS:
        for match in pattern.findall(path):
            name = match if isinstance(match, str) else (match or [""])[-1]
            name = (name or "").strip()
            if name and name not in names:
                names.append(name)
    return names


#: A route record is an object literal with a ``path`` plus at least one other
#: router-shaped key. Requiring the second key is what keeps this from matching
#: every ``{path: "..."}`` in a codebase, and dropping the array-detection
#: entirely is what makes it survive minified bundles where the route table is
#: an argument (``createRouter([...])``) rather than an assignment.
_ROUTE_RECORD = re.compile(
    r"""(?s)\{(?=[^{}]*?\bpath\s*:\s*["'])"""
    r"""(?=[^{}]*?\b(?:component|element|name|children|redirect|meta"""
    r"""|loader|action)\s*:)[^{}]*\}"""
)
_ROUTE_PATH = re.compile(r"""\bpath\s*:\s*["']([^"']{1,200})["']""")


def routes_from_source(source_url: str, body: str,
                       limit: int = 200) -> list[Route]:
    """Recover routes from router configuration in a bundle.

    A regex fallback for bundles whose router config the AST pass did not
    model; the pipeline runs both and merges. Nested children routes are found
    by the same scan because each ``{path: ...}`` object matches on its own.
    """
    out: list[Route] = []
    seen: set[str] = set()
    for record in _ROUTE_RECORD.finditer(body):
        match = _ROUTE_PATH.search(record.group(0))
        if not match:
            continue
        path = match.group(1).strip()
        if not path.startswith("/") or path in seen:
            continue
        if is_static_asset_path(path):
            continue
        seen.add(path)
        route = Route(path=path, source_url=source_url)
        route.params = route_param_names(path)
        route.parameterized = bool(route.params)
        out.append(route)
        if len(out) >= limit:
            return out
    return out
