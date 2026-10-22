"""Minimal local target used by the end-to-end test.

Serves one HTML page, one application script and one webpack runtime, so the
scan exercises document parsing, the regex pass, the AST pass and chunk
discovery without touching the network.
"""

from __future__ import annotations

import http.server
import json
import socketserver
import threading
from pathlib import Path

APP_JS = ((Path(__file__).parent / "fixture.js").read_text(encoding="utf-8")
          + "\n//# sourceMappingURL=app.js.map\n")

# A webpack 5 runtime: public path + separate name map and hash map.
WEBPACK_RUNTIME = """
(function(){
  var r = {};
  r.p = "/static/js/";
  r.u = function(e){ return "js/" + e + "." + {3:"a1b2c3",7:"d4e5f6"}[e] + ".chunk.js"; };
  r.m = {};
  r.o = function(o,n){ for(var i in n) r.o(o,n[i]) || (r.o.d[n[i]]=o[n[i]]=i); return i; };
  window.webpackJsonp = window.webpackJsonp || [];
})();
"""

ROUTES_JS = (Path(__file__).parent / "fixture_routes.js").read_text(encoding="utf-8")
OPENAPI_JSON = (Path(__file__).parent / "fixture_openapi.json").read_text(
    encoding="utf-8")

#: Lists every chunk. The manifest is the only *deterministic* discovery path in
#: the project, so the fixture publishes one.
ASSET_MANIFEST = """{
  "files": {
    "main.js": "/static/app.js",
    "runtime.js": "/static/runtime.js",
    "routes.js": "/static/routes.js",
    "admin.js": "/static/only-in-manifest.js"
  },
  "entrypoints": ["static/app.js", "static/runtime.js"]
}"""

#: Listed in the manifest and referenced by no page. Finding it therefore proves
#: the manifest path works where heuristics would have missed it.
MANIFEST_ONLY_JS = """
var adminBase = "https://admin.example.com/api";
function loadAdminAudit(id) {
  return axios.post(adminBase + "/sys/audit/export", { auditId: id, format: "xlsx" });
}
var adminToken = "sk-admin-8f2c1e77b9d04a6f";
"""

#: A rendered route: the router config plus one view's on-demand script. The
#: /internal/user/audit/list call exists nowhere else, so recovering it proves
#: the route crawler reached code the entry page never loads.
#: A source map for app.js, carrying one original source with content.
#: ``sourcesContent`` is the whole reason a leaked map is worth anything, so
#: the fixture serves one and the suite asserts the content is recovered and
#: searchable. A map that is fetched but never parsed is otherwise invisible.
APP_SOURCEMAP = json.dumps({
    "version": 3,
    "file": "app.js",
    "sources": ["webpack://app/./src/admin/audit.ts"],
    "sourcesContent": [
        'var recoveredSecret = "sk-map-recovered-9f3a1c77b2";'
    ],
    "mappings": "AAAA",
})

ROUTE_PAGE_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>user list</title>
<script src="/static/routes.js"></script>
</head><body><div id="app"></div></body></html>
"""

#: A route that only exists behind a dynamic segment.
ROUTE_DETAIL_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>user detail</title>
<script src="/static/routes.js"></script>
</head><body><div id="app"></div></body></html>
"""

INDEX_HTML = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>local target</title>
  <link rel="stylesheet" href="/static/site.css">
</head>
<body>
  <div id="app"></div>
  <script>window.__APP__ = { apiBase: "/api/v1", tenant: "acme" };</script>
  <script src="/static/runtime.js"></script>
  <script src="/static/app.js"></script>
</body>
</html>
"""


class Handler(http.server.BaseHTTPRequestHandler):
    routes = {
        "/": ("text/html; charset=utf-8", INDEX_HTML),
        "/static/app.js": ("application/javascript; charset=utf-8", APP_JS),
        "/static/runtime.js": ("application/javascript; charset=utf-8", WEBPACK_RUNTIME),
        "/static/routes.js": ("application/javascript; charset=utf-8", ROUTES_JS),
        "/static/only-in-manifest.js": ("application/javascript; charset=utf-8",
                                        MANIFEST_ONLY_JS),
        "/static/app.js.map": ("application/json", APP_SOURCEMAP),
        "/asset-manifest.json": ("application/json", ASSET_MANIFEST),
        "/v3/api-docs": ("application/json", OPENAPI_JSON),
        "/user/list": ("text/html; charset=utf-8", ROUTE_PAGE_HTML),
        "/user/1": ("text/html; charset=utf-8", ROUTE_DETAIL_HTML),
    }

    #: Header sets per path, used to exercise the banner engine. The entry
    #: page discloses a versioned stack; the legacy endpoint answers with a
    #: bare, versionless ``Server`` header that must produce no banner; the
    #: 404 page leaks a full Apache banner in its body.
    banner_headers = {
        "/": {
            "Server": "nginx/1.18.0 (Ubuntu)",
            "X-Powered-By": "PHP/8.2.1",
        },
        "/static/app.js": {
            "Server": "nginx",
            "X-Powered-By": "Express/4.18.2",
        },
        "/api/v1": {
            # Versionless on purpose: only the header name is disclosed.
            "Server": "nginx",
            "X-Powered-By": "Express",
        },
        "/static/runtime.js": {"Server": "nginx/1.18.0 (Ubuntu)"},
    }

    #: An error page that prints the banner its header would have truncated.
    not_found_body = (
        "<html><head><title>404 Not Found</title></head><body>"
        "<h1>Not Found</h1><p>Apache/2.4.41 (Ubuntu) Server at example.com "
        "Port 80</p></body></html>"
    )

    def _respond(self, status: int, content_type: str, body: bytes | str) -> None:
        payload = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for name, value in self.banner_headers.get(
            self.path.split("?", 1)[0], {}
        ).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = self.path.split("?", 1)[0]
        if path in self.routes:
            content_type, body = self.routes[path]
            self._respond(200, content_type, body)
            return
        # A webpack chunk that really exists.
        if path.startswith("/static/js/") and path.endswith(".chunk.js"):
            self._respond(200, "application/javascript", b"/* chunk */")
            return
        self._respond(404, "text/html; charset=utf-8", self.not_found_body)

    def log_message(self, *_args) -> None:  # silence the default stderr log
        pass


class LocalSite:
    """Runs :class:`Handler` on an ephemeral port for the duration of a test."""

    def __init__(self) -> None:
        # Threading, not plain TCPServer: the scanner fetches concurrently and
        # httpx holds keep-alive connections open, so a single-threaded
        # server would sit on one connection while the rest wait on accept.
        self._server = socketserver.ThreadingTCPServer(
            ("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}/"

    def __enter__(self) -> "LocalSite":
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        self._server.shutdown()
        self._server.server_close()


if __name__ == "__main__":  # pragma: no cover
    import time

    with LocalSite() as site:
        print(site.base_url)
        time.sleep(30)
