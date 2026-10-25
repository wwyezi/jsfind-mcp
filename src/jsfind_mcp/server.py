"""MCP server exposing scan results to an LLM client.

Tools are split by *question*, not by data table:

* ``jsfind_scan``        — run a scan, get a ``scan_id`` back
* ``jsfind_endpoints``   — which interfaces exist, with methods and evidence
* ``jsfind_sensitive``   — what secrets leaked, ranked by severity
* ``jsfind_parameters``  — which fields the interfaces accept
* ``jsfind_banners``    — which server/middleware versions the target leaked
* ``jsfind_routes``      — which front-end routes exist
* ``jsfind_hosts``       — which hosts the code talks to
* ``jsfind_resources``   — what was actually downloaded
* ``jsfind_report``      — where the report files landed
* ``jsfind_rules``       — which rules are compiled
* ``jsfind_scans``       — list scans held in memory

Every listing tool takes a ``limit`` so a large SPA cannot flood a context
window. Scans live in memory only and are lost when the server restarts; the
``scan_id`` error message says so explicitly so a caller can recover by
re-scanning rather than guessing.

The server speaks stdio by default (what desktop MCP clients launch) and can
also serve streamable HTTP for remote or shared setups.
"""

from __future__ import annotations

import argparse
import asyncio
import functools
import json
import os
import time
import re
import sys
import threading
from uuid import uuid4
from copy import deepcopy
from pathlib import Path
from urllib.parse import urlparse

from . import mcpconfig
from .banner import summarize
from .collect import Client
from .config import Config, load_config, seed_user_rules
from .diff import diff_endpoints
from .model import (
    Result,
    RuleCategory,
    classify_status,
    route_param_names,
    severity_rank,
)
from .proxy import (
    ProxyError,
    bypass_hosts,
    describe as describe_proxy,
    normalize as normalize_proxy,
    redact as redact_proxy,
)
from .jssearch import collect_js_files, search
from .surface import build_surface
from .rules import regex_backend
from .scanner import Scanner, Target
from . import utils as _utils
from .pipeline import SerialWorker
from .utils import is_javascript_path

SERVER_NAME = "jsfind-mcp"
SERVER_VERSION = "0.1.0"

DEFAULT_LIMIT = 50
MAX_LIMIT = 1000

#: Ceiling on a per-call scan budget. A model that asks for a day gets this and
#: is told so: an unbounded wait is worse than a partial answer, because the
#: client gives up on the call and the tools disappear with it.
MAX_TIMEOUT_SECONDS = 3600.0

#: Where CPU-heavy tool bodies run instead of on the event loop. Daemon, so a
#: body still working at exit cannot hold the process open as an orphan.
_CPU = SerialWorker()


async def _offload(fn, /, *args, **kwargs):
    """Run ``fn`` on the CPU worker, off the event loop."""
    return await asyncio.get_running_loop().run_in_executor(
        _CPU, functools.partial(fn, *args, **kwargs))


#: How many finished scans are held at once. Past this the oldest is dropped
#: so a long session cannot grow without bound -- a Result holds every endpoint
#: and finding of a whole target, and a handful of big targets is hundreds of
#: megabytes.
DEFAULT_MAX_SCANS = 20
#: How long a scan stays addressable, in seconds. An id that has gone stale
#: answers "unknown" rather than returning a result nobody is still working
#: from, which is the difference between a stale answer and a clear one.
DEFAULT_SCAN_TTL = 600.0


class ScanStore:
    """Keeps finished scans addressable by a short id.

    In-memory on purpose: results hold live credentials, and writing them to a
    shared directory by default would be the wrong default. Bounded on purpose
    too: ``max_scans`` entries, each expiring after ``ttl`` seconds, so a long
    session releases what it collected instead of holding all of it.
    """

    #: Every id carries the run it came from. Without it, "scan-1" from the
    #: run before a restart and "scan-1" from the run after are different scans
    #: with the same name, and a tester reading the old id gets back a result
    #: that is silently not theirs.
    def __init__(self, base_config: Config | None = None,
                 max_scans: int = DEFAULT_MAX_SCANS,
                 ttl: float = DEFAULT_SCAN_TTL):
        self._lock = threading.Lock()
        self._next = 0
        self._scans: dict[str, tuple] = {}  # id -> (put_at, Result)
        self.base = base_config
        self.session = uuid4().hex[:6]
        self.max_scans = max(1, int(max_scans or DEFAULT_MAX_SCANS))
        self.ttl = float(ttl or DEFAULT_SCAN_TTL)

    def put(self, result: Result) -> str:
        with self._lock:
            self._next += 1
            scan_id = f"scan-{self.session}-{self._next}"
            self._scans[scan_id] = (time.monotonic(), result)
            self._evict_locked()
            return scan_id

    def get(self, scan_id: str) -> Result:
        with self._lock:
            entry = self._scans.get(scan_id)
            if entry is not None and self._expired_locked(entry):
                del self._scans[scan_id]
                entry = None
        if entry is None:
            raise KeyError(
                f"unknown scan_id {scan_id!r}. Scans live in memory only and are "
                f"gone once the server restarts or the entry ages out "
                f"({self.ttl:.0f}s), so an id from an earlier run cannot be "
                f"resolved here. This run's session is {self.session}; "
                f"live ids: {sorted(self.ids())[:20]}. Re-run jsfind_scan or "
                f"jsfind_analyze_file to get an id from the current run."
            )
        return entry[1]

    def ids(self) -> list[str]:
        with self._lock:
            self._evict_locked()
            # Ids are "scan-<session>-<n>"; the counter is the last segment.
            # Sorting on the session segment would raise ValueError on it.
            return sorted(self._scans, key=lambda key: int(key.rsplit("-", 1)[-1]))

    def release(self, scan_id: str) -> bool:
        """Drop one scan now. True when something was actually dropped."""
        with self._lock:
            return self._scans.pop(scan_id, None) is not None

    def clear(self) -> int:
        """Drop every scan. Returns how many went."""
        with self._lock:
            count = len(self._scans)
            self._scans.clear()
            return count

    def _expired_locked(self, entry: tuple) -> bool:
        return time.monotonic() - entry[0] > self.ttl

    def _evict_locked(self) -> None:
        """Drop expired entries, then the oldest until under the cap."""
        for scan_id in [sid for sid, entry in self._scans.items()
                        if self._expired_locked(entry)]:
            del self._scans[scan_id]
        while len(self._scans) > self.max_scans:
            oldest = min(self._scans, key=lambda sid: self._scans[sid][0])
            del self._scans[oldest]


#: Short names that mean something specific to a tester, so a minifier
#: happening to produce them does not make them noise.
_MEANINGFUL_SHORT = frozenset({
    "id", "ip", "ua", "os", "db", "fs", "ok", "to", "no", "at", "by", "on",
    "in", "is", "it", "of", "or", "up", "us", "we", "ts", "ms", "px", "rm",
    "cp", "dn", "kw", "id", "pk", "sn", "ttl", "uid", "gid", "sid", "rid",
})

#: Positions that mean the name reached an actual request.
_REQUEST_SCENARIOS = frozenset({"endpoint", "url_query", "body", "path"})


def _is_minifier_noise(name: str, scenarios) -> bool:
    """Whether a parameter name is minifier debris rather than a real name.

    Two shapes of debris:

    * a one or two character name that only ever turned up as a local variable
      or an object property;
    * a short fragment with no word shape at all -- ``AACD``, ``AAgB``,
      ``Jj7x`` -- which is what webpack leaves behind after mangling. These
      used to sort to the top of the list and bury the useful names.

    A name with a real word in it (``agentID``, ``usid``, ``Dial``) is kept
    however short it is, and so is anything seen in a request position.
    """
    if name.lower() in _MEANINGFUL_SHORT:
        return False
    if len(name) <= 2:
        return not (set(scenarios) & _REQUEST_SCENARIOS)
    # No run of three lowercase letters means no word in it. "AACD", "AAgB",
    # "BAAi", "EgsY" and "Jj7x" all fail this; "Dial", "usid", "roomId",
    # "agentID" and "startTime" all pass it.
    if len(name) <= 5 and not re.search(r"[a-z]{3,}", name):
        return not (set(scenarios) & _REQUEST_SCENARIOS)
    return False


def build_server(store: ScanStore):
    """Create the FastMCP server with every tool registered."""
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP(
        SERVER_NAME,
        instructions=(
            "jsfind-mcp collects a target's pages, JavaScript, webpack/RequireJS "
            "chunks and SPA runtime resources, then extracts API endpoints, "
            "parameters, routes and sensitive data (keys, tokens, ID numbers, "
            "internal IPs) with regex + Tree-sitter AST. "
            "Workflow: jsfind_scan -> jsfind_endpoints / jsfind_sensitive. "
            "Use only against targets you are explicitly authorized to test; "
            "results contain live secrets."
        ),
    )

    @mcp.tool()
    async def jsfind_scan(
        url: str,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        timeout_seconds: int | str = 0,
        probe: bool = True,
        crawl_routes: bool | None = None,
        max_resources: int = 0,
        max_response_bytes: int | str = 0,
        js_dir: str = "",
        save_js: bool = True,
        proxy: str = "",
        no_proxy: str = "",
        trust_env: bool = True,
        verify_tls: bool = False,
    ) -> dict:
        """Scan one web target and return a scan_id for the other tools.

        Collects the entry document, every referenced script, Webpack/RequireJS/
        Vite chunks and source-map-recovered originals, then extracts API
        endpoints, request parameters, routes, middleware versions and
        sensitive data with regex + Tree-sitter AST.

        Args:
            url: target URL, e.g. https://example.com
            headers: extra request headers, e.g. Authorization
            cookies: session cookies from an authenticated session
            timeout_seconds: wall-clock budget for this whole scan, all phases
                included (default 90). Collection stops when it is spent and
                returns what it has, rather than running on until the MCP
                client gives up and drops the connection. Raise it for a target
                that needs longer; a scan that returns timed_out=true was cut
                short, and the rest of this result is a partial view. Accepts a
                number or a numeric string ("300"); anything else falls back to
                the default rather than failing the call.
            probe: confirm discovered endpoints with read-only GET probes
                (default true). Turn off for a purely passive collection run.
            crawl_routes: render each front-end route to reach the scripts it
                loads on demand. Default is the config value, and is forced
                off for a target that is itself a JavaScript file — a single
                bundle has no routes to walk, and rendering would spend the
                budget on nothing.
            max_resources: cap on how many resources one scan fetches (0 = the
                configured default). Lower it to bound a scan against a huge
                site.
            max_response_bytes: ceiling on one response body in bytes, counted
                after decompression (default 10 MB, from config). A bigger
                body is fetched streaming and cut at the cap, and the scan
                returns issues[].code="response_truncated" for each cut URL
                instead of stalling on a 20 MB download. Raise it ("20MB",
                20971520) when the interesting region sits deeper in a giant
                bundle; 0 keeps the configured default.
            js_dir: where to write the downloaded scripts. Pass an absolute
                path to choose the location yourself, e.g. "/tmp/recon-acme".
                A leading ``~`` is expanded; a relative path resolves against
                the server's working directory, which under an MCP client is
                not predictable, so prefer absolute. Empty means "use the
                configured default". Each target gets its own subdirectory
                underneath, and the resolved absolute path comes back as
                ``js_dir`` so you always know where the files are.
                Collected code can contain live credentials, so choose a path
                you control and delete it when you are done.
            save_js: set false to keep nothing on disk. ``js_dir`` is then
                ignored and ``js_dir`` comes back empty.
            proxy: route every request through this proxy, e.g.
                "http://127.0.0.1:8080" or "socks5://host:1080". A bare
                "host:port" is treated as http. Credentials may be included
                (http://user:pass@host:8080) but are **redacted** in the
                response -- a proxy password is never echoed back. Empty
                falls back to the configured default. Needs
                ``pip install "httpx[socks]"`` for socks5/socks4.
            no_proxy: comma-separated hosts to bypass, e.g.
                "localhost,127.0.0.1,.corp.internal".
            trust_env: set false to ignore HTTP_PROXY / HTTPS_PROXY /
                ALL_PROXY / NO_PROXY and prove the scan went direct.
            verify_tls: verify the target's TLS certificate. Off by
                default -- real targets are routinely https://IP with a
                self-signed or mismatched certificate, and refusing them
                would make online probing useless. Set true when you want
                certificate errors to be treated as errors.
        """
        raw = _clean_text(url).strip()
        if not raw:
            return {"error": "url is required"}
        if not raw.startswith(("http://", "https://")):
            return {"error": f"url must start with http:// or https://, got {raw!r}"}

        # A fresh copy per call: one invocation must not leave its timeout or
        # probe setting behind for the next one.
        config = deepcopy(store.base) if store.base is not None else load_config()
        js_dir = _clean_text(js_dir)
        proxy = _clean_text(proxy)
        no_proxy = _clean_text(no_proxy)
        budget = _seconds(timeout_seconds, config.request.target_timeout)
        if budget > 0:
            config.request.target_timeout = float(budget)
        config.scope.probe_endpoints = probe
        # A target that is itself a bundle has no routes to render and no
        # entry document to walk: rendering would spend the whole budget
        # fetching the same file forty times. The caller can still force it.
        is_js_target = is_javascript_path(raw) or ".js" in urlparse(raw).path.lower()
        if crawl_routes is None:
            config.scope.crawl_routes = config.scope.crawl_routes and not is_js_target
        else:
            config.scope.crawl_routes = bool(crawl_routes) and not is_js_target
        if max_resources > 0:
            config.limits.max_resources = int(max_resources)
        # Oversized bodies are cut in the HTTP client itself, streaming, so a
        # 20 MB response costs one capped read instead of a memory spike that
        # happens before any check could run. Raise it for a target whose
        # interesting region sits deep in a giant bundle.
        cap = _size_bytes(max_response_bytes, config.request.max_response_bytes)
        if cap > 0:
            config.request.max_response_bytes = cap
        # The caller's directory wins over the config default, and save_js is
        # honoured here rather than deep in the pipeline so the response can
        # state plainly that nothing was written.
        if (js_dir or "").strip():
            config.js_dir = js_dir.strip()
        config.save_js = bool(save_js)
        # Validated here so a typo comes back as one clear sentence rather
        # than an httpx constructor error after the scan has started.
        config.request.trust_env = bool(trust_env)
        config.request.verify_tls = bool(verify_tls)
        if (proxy or "").strip():
            try:
                config.request.proxy = normalize_proxy(proxy)
            except ProxyError as exc:
                return {"error": str(exc)}
        if (no_proxy or "").strip():
            config.request.no_proxy = no_proxy.strip()

        target = Target(url=raw, headers=dict(headers or {}),
                        cookies=dict(cookies or {}))
        try:
            result = await Scanner(config).scan(target)
        except Exception as exc:  # noqa: BLE001 - reported, not raised
            return {"error": f"{type(exc).__name__}: {exc}"}

        # What the transport actually used, as opposed to what was asked
        # for. With trust_env on, an environment variable may be the real
        # path -- and a scan that silently went direct when the operator
        # expected a proxy is exactly the failure worth surfacing.
        proxy_report, proxy_note = _effective_proxy(config, result)

        scan_id = store.put(result)
        stats = result.statistics
        strong = [e for e in result.endpoints
                  if e.evidence in ("runtime", "full-url")]
        timed_out = any(i.code == "target_timeout" for i in result.issues)
        return {
            "scan_id": scan_id,
            "target": result.target,
            "mode": result.mode.value,
            # Absolute, or "" when nothing was written. Reported instead of left
            # for the caller to derive: a relative js_dir resolves against the
            # server cwd, which is rarely what anyone assumed it was.
            "js_dir": result.js_dir,
            "js_saved": bool(result.js_dir),
            # Redacted: the username is useful, the password is not ours to
            # print back into a log or a report.
            "proxy": redact_proxy(proxy_report),
            "proxy_configured": bool(proxy_report),
            "no_proxy": sorted(bypass_hosts(config.request.no_proxy)),
            "trust_env": bool(trust_env),
            "proxy_note": proxy_note or "",
            "resources": stats.resources,
            "endpoints": stats.endpoints,
            # True means the wall-clock budget ran out before every phase
            # finished: what follows is a subset, not the whole target. Reported
            # here because "endpoints: 12" reads the same either way, and a
            # model that takes a partial inventory for a complete one will stop
            # looking.
            "timed_out": timed_out,
            "timeout_seconds": float(config.request.target_timeout),
            # Structured, so a caller can branch on it: "code": "timeout" with
            # "partial": true means this inventory is a subset and the next
            # call should either raise the budget or narrow the target. A
            # timeout is a normal return, never an exception and never a
            # string sentinel in a numeric field.
            "code": "timeout" if timed_out else "ok",
            "partial": timed_out,
            "routes": stats.routes,
            "routes_rendered": sum(1 for r in result.routes if r.get("rendered")),
            "asset_manifests": len(result.assets),
            "api_specs": len(result.specs),
            "spec_operations": sum(1 for e in result.endpoints
                                   if e.evidence == "spec"),
            "graphql_operations": len(result.graphql),
            "sensitive_findings": len(
                [f for f in result.findings if f.category is RuleCategory.SENSITIVE]
            ),
            "parameters": stats.parameters,
            "hosts": stats.hosts,
            "banners": stats.banners,
            "banner_summary": summarize(result.banners),
            "banner_note": ("只列出带版本号的服务端/中间件指纹。"
                            if not result.banners else ""),
            "hints": result.hints[:10],
            "runtime_endpoints": len([e for e in result.endpoints
                                      if e.evidence == "runtime"]),
            "full_url_endpoints": len([e for e in result.endpoints
                                       if e.evidence == "full-url"]),
            "ast_enabled": _ast_available(),
            "regex_backend": regex_backend(),
            "technologies": result.technologies,
            "top_endpoints": [f"{e.method} {e.url}".strip() for e in strong[:10]],
            "issues": [{"code": i.code, "message": i.message}
                       for i in result.issues[:10]],
            "next_step": "接着调用 jsfind_surface 拿到排序后的测试切入点",
        }

    @mcp.tool()
    def jsfind_endpoints(
        scan_id: str,
        evidence: str = "",
        method: str = "",
        search: str = "",
        kind: str = "",
        authorized: str = "",
        with_context: bool = False,
        with_request: bool = False,
        offset: int = 0,
        limit: int = DEFAULT_LIMIT,
    ) -> dict:
        """List API endpoints with method, evidence level, source and parameters.

        Args:
            scan_id: scan id returned by jsfind_scan
            evidence: filter — "runtime", "full-url" or "static"
            method: filter by HTTP verb, e.g. "POST"
            search: substring match against the URL
            kind: filter by interface kind — "api" or "socket". Sockets are
                discovered WebSocket URLs; they always carry
                signal="unprobed" because a GET cannot confirm them.
            authorized: "true" keeps only endpoints on an origin you named
                (the scan root, or base_url on an offline run); "false"
                keeps the rest. Empty returns both. Offline without
                base_url, every row is unauthorized and filtering for
                "true" correctly returns nothing.
            with_context: include surrounding source lines
            with_request: include the reconstructed request packet
            offset: page offset; use it together with has_more to page
            limit: max rows (default 50)
        """
        try:
            result = store.get(scan_id)
        except KeyError as exc:
            return {"error": str(exc)}

        matched = _filter_endpoints(result.endpoints, evidence, method, search,
                                    kind, authorized)
        rows = []
        for endpoint in matched:
            row = {
                "url": endpoint.url,
                "method": endpoint.method,
                "kind": endpoint.type,
                "evidence": endpoint.evidence,
                "source": endpoint.source,
                "status_code": endpoint.status_code,
                "signal": endpoint.signal,
                "authorized": endpoint.authorized,
                "body_params": endpoint.body_params,
                "query_params": endpoint.spec.query if endpoint.spec else [],
                "content_type": endpoint.spec.content_type if endpoint.spec else "",
                "source_url": endpoint.source_url,
                "line": endpoint.line,
                "vendor": endpoint.vendor,
            }
            if with_context:
                row["context"] = [
                    f"{line.line_number} | {line.content}" for line in endpoint.context_lines
                ]
            if with_request and endpoint.template is not None:
                row["request"] = {
                    "method": endpoint.template.method,
                    "url": endpoint.template.url,
                    "headers": [{"key": h.key, "value": h.value}
                                for h in endpoint.template.headers],
                    "body": endpoint.template.body,
                    "notes": endpoint.template.notes,
                }
            rows.append(row)
        note = _zero_result_note(result, "endpoints") if not rows else ""

        # The numbers inside one response should add up. A caller who sees
        # "endpoints: 196" on the scan and "total: 50" here has no way to tell
        # which is right -- that exact mismatch cost a tester a whole round.
        # Reporting the arithmetic makes the difference visible instead of
        # leaving it to be discovered by hand.
        extracted = len(result.endpoints)
        queryable = sum(1 for e in result.endpoints
                        if e.type in _ENDPOINT_TYPES)
        reconciliation = {
            "extracted": extracted,
            "queryable": queryable,
            "filtered_by_query": max(0, queryable - len(rows)),
            "hidden_by_type": max(0, extracted - queryable),
        }
        warning = ""
        if reconciliation["hidden_by_type"]:
            warning = (f"{reconciliation['hidden_by_type']} 条结果的类型不在"
                       f"本工具展示范围内（{_ENDPOINT_TYPES}）；"
                       "extracted 与 total 的差就是这个数。")
        elif extracted != queryable:
            warning = "extracted 与 queryable 不一致，请报告这个情况。"

        return _page(rows, limit, offset, scan_id=scan_id,
                     endpoints=_limit(rows, limit, offset), note=note,
                     reconciliation=reconciliation, warning=warning,
                     signal_legend=_SIGNAL_LEGEND,
                     kind_legend={
                         "api": "HTTP 接口",
                         "socket": "WebSocket 地址；需要握手测试，本工具不发探测请求",
                     })

    @mcp.tool()
    def jsfind_sensitive(
        scan_id: str,
        min_severity: str = "",
        search: str = "",
        with_context: bool = False,
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> dict:
        """List sensitive-information findings (keys, tokens, credentials, PII).

        Args:
            scan_id: scan id returned by jsfind_scan
            min_severity: "info", "low", "medium", "high" or "critical"
            search: substring match against rule name or value
            with_context: include surrounding source lines
            limit: max rows (default 50, hard cap 1000)
            offset: skip this many rows, for paging through a long list
        """
        try:
            result = store.get(scan_id)
        except KeyError as exc:
            return {"error": str(exc)}

        minimum = severity_rank(min_severity)
        needle = (search or "").lower()
        selected = []
        for finding in result.findings:
            if finding.category is not RuleCategory.SENSITIVE:
                continue
            if severity_rank(finding.severity.value) < minimum:
                continue
            if needle and needle not in f"{finding.rule_name} {finding.rule_id} " \
                                       f"{finding.value}".lower():
                continue
            selected.append(finding)
        selected.sort(key=lambda f: (-severity_rank(f.severity.value), f.rule_name))

        rows = []
        for finding in _limit(selected, limit, offset):
            row = {
                "severity": finding.severity.value,
                "rule": finding.rule_name,
                "rule_id": finding.rule_id,
                "value": finding.value,
                "source_url": finding.source_url,
                "line": finding.line,
            }
            if with_context:
                row["context"] = [line.content for line in finding.context_lines]
            rows.append(row)
        # Same contract as jsfind_endpoints: the numbers in one response must
        # add up, so a caller can tell "there is little here" from "the filters
        # hid most of it". The 244-extracted / 4-useful case is exactly the
        # confusion this prevents.
        extracted = sum(1 for f in result.findings
                        if f.category is RuleCategory.SENSITIVE)
        return {
            "scan_id": scan_id,
            "count": len(rows),
            "total": len(selected),
            "offset": max(0, offset),
            "has_more": max(0, offset) + len(rows) < len(selected),
            "by_severity": _severity_histogram(selected),
            "reconciliation": {
                "extracted": extracted,
                "after_filters": len(selected),
                "returned": len(rows),
                "filtered_out": max(0, extracted - len(selected)),
                "cut_by_limit": max(0, len(selected) - len(rows)),
            },
            "findings": rows,
        }

    @mcp.tool()
    def jsfind_parameters(
        scan_id: str,
        search: str = "",
        endpoint_only: bool = False,
        drop_minified: bool = True,
        limit: int = 100,
    ) -> dict:
        """List request parameter names observed across endpoints and code.

        Args:
            scan_id: scan id returned by jsfind_scan
            search: substring match against the parameter name
            endpoint_only: only parameters belonging to a probed/known endpoint
            drop_minified: drop parameter names that are minifier noise. A short
                name that appears only in generic code positions (a local
                variable, an object property) is what a minifier leaves behind;
                the same short name appearing in a request position is a real
                parameter and is kept. The count of what was dropped is
                reported, so the filter never hides anything silently.
            limit: max rows (default 100)
        """
        try:
            result = store.get(scan_id)
        except KeyError as exc:
            return {"error": str(exc)}

        merged: dict[str, dict] = {}
        for hit in result.params:
            if search and search.lower() not in hit.name.lower():
                continue
            entry = merged.setdefault(hit.name, {
                "name": hit.name, "scenarios": set(), "example": hit.value,
                "first_seen": f"{hit.source_url}:{hit.line}", "vendor": False,
                "from_code": True,
            })
            entry["scenarios"].add(hit.scenario)
            entry["vendor"] = entry["vendor"] or hit.vendor
            if not entry["example"] and hit.value:
                entry["example"] = hit.value

        for endpoint in result.endpoints:
            keys = list(endpoint.body_params)
            if endpoint.spec is not None:
                keys += [p.key for p in endpoint.spec.query]
                keys += [p.key for p in endpoint.spec.body]
            for key in keys:
                if not key:
                    continue
                if search and search.lower() not in key.lower():
                    continue
                entry = merged.setdefault(key, {
                    "name": key, "scenarios": set(), "example": "",
                    "first_seen": endpoint.source_url or endpoint.url,
                    "vendor": False, "from_code": False,
                })
                entry["scenarios"].add("endpoint")
                entry["from_endpoint"] = True

        rows = []
        dropped = 0
        for name in sorted(merged):
            entry = merged[name]
            if endpoint_only and not entry.get("from_endpoint"):
                continue
            if drop_minified and _is_minifier_noise(name, entry["scenarios"]):
                dropped += 1
                continue
            rows.append({
                "name": entry["name"],
                "scenarios": sorted(entry["scenarios"]),
                "example": entry["example"],
                "first_seen": entry["first_seen"],
                "vendor": entry["vendor"],
            })
        # Ordered by how much the name is worth acting on: a parameter that
        # reached a request first, then one seen in a request-shaped position,
        # then the rest. Alphabetical order buries the useful names.
        _SCENARIO_RANK = {"endpoint": 0, "url_query": 1, "body": 1, "path": 1,
                          "function_param": 2, "object_property": 3,
                          "config_object": 3, "variable": 4}
        rows.sort(key=lambda row: (
            min((_SCENARIO_RANK.get(s, 9) for s in row["scenarios"]), default=9),
            row["name"]))
        return {"scan_id": scan_id, "count": len(rows),
                "dropped_minified": dropped,
                "parameters": _limit(rows, limit),
                "note": ("已按可信度排序（请求中出现过的在前）；"
                         f"另有 {dropped} 个压缩噪音名被过滤，"
                         "设 drop_minified=false 可全部返回。")}

    @mcp.tool()
    def jsfind_banners(
        scan_id: str,
        category: str = "",
        search: str = "",
        limit: int = DEFAULT_LIMIT,
    ) -> dict:
        """List versioned server / middleware products the target disclosed.

        Every row carries a real version: a bare ``Server: nginx`` yields
        nothing, because the header's default value tells a tester nothing
        actionable. Sources are response headers and error-page bodies.

        Args:
            scan_id: scan id returned by jsfind_scan
            category: filter — web_server, app_server, language, gateway,
                framework, cdn or db
            search: substring match against product or version
            limit: max rows (default 50)
        """
        try:
            result = store.get(scan_id)
        except KeyError as exc:
            return {"error": str(exc)}
        needle = (search or "").lower()
        banners = [
            banner for banner in result.banners
            if (not category or banner.category == category)
            and (not needle or needle in f"{banner.product} {banner.version}".lower())
        ]
        rows = [banner.to_dict() for banner in _limit(banners, limit)]
        return {
            "scan_id": scan_id,
            "count": len(rows),
            "note": ("只列出带版本号的指纹；Server: nginx 这类无版本值会被丢弃。"
                     if not result.banners else ""),
            "summary": summarize(result.banners),
            "banners": rows,
        }

    @mcp.tool()
    def jsfind_routes(scan_id: str, search: str = "", rendered_only: bool = False,
                      limit: int = DEFAULT_LIMIT) -> dict:
        """List front-end routes, and what loading each one pulled in.

        ``rendered`` says the route was actually fetched with GET, and its
        ``scripts`` / ``endpoints`` are what that render alone exposed — a
        lazy-loaded view's code is invisible until its path is visited.
        ``parameterized`` marks a route whose dynamic segment was replaced with
        a single probe value, so its value space was not walked.

        Args:
            scan_id: scan id returned by jsfind_scan or jsfind_analyze_file
            search: substring match against the route path
            rendered_only: keep only routes that were actually rendered with
                GET. A route the crawler did not reach has no scripts or
                endpoints of its own, so filtering to the rendered ones shows
                what a path visit actually exposed.
            limit: max rows (default 50)
        """
        try:
            result = store.get(scan_id)
        except KeyError as exc:
            return {"error": str(exc)}
        needle = (search or "").lower()
        crawled = {r.get("path", ""): r for r in result.routes}
        rows = []
        for endpoint in result.endpoints:
            if endpoint.type != "route":
                continue
            path = urlparse(endpoint.url).path or endpoint.url
            entry = crawled.get(path)
            if entry is None and not result.routes:
                entry = {}
            if entry is None:
                continue
            row = {
                "route": endpoint.url,
                "path": path,
                "source_url": endpoint.source_url,
                "line": endpoint.line,
                "authorized": endpoint.authorized,
                "params": entry.get("params", []),
                "parameterized": entry.get("parameterized", False),
                "rendered": entry.get("rendered", False),
                "status_code": entry.get("status_code", 0),
                "scripts": entry.get("scripts", []),
                "endpoints": entry.get("endpoints", []),
                "note": entry.get("note", ""),
            }
            if rendered_only and not row["rendered"]:
                continue
            if needle and needle not in endpoint.url.lower():
                continue
            rows.append(row)
        rows.sort(key=lambda item: item["route"])
        return {"scan_id": scan_id, "count": len(rows),
                "rendered": sum(1 for r in rows if r["rendered"]),
                "routes": _limit(rows, limit)}

    @mcp.tool()
    def jsfind_specs(scan_id: str, search: str = "",
                     limit: int = DEFAULT_LIMIT) -> dict:
        """List the interface the target documents about itself.

        Three sources, all of them the target's own words rather than inference:
        published OpenAPI/Swagger documents, the operations they declare, and
        GraphQL operation documents embedded in the bundles.

        Declared endpoints carry ``evidence="spec"`` and are deliberately *not*
        request-confirmed — ``authorized_per_spec`` reflects the security
        schemes the document states, not the server's behaviour.

        Args:
            scan_id: scan id returned by jsfind_scan or jsfind_analyze_file
            search: substring match against the declared path or GraphQL name
            limit: max rows (default 50)
        """
        try:
            result = store.get(scan_id)
        except KeyError as exc:
            return {"error": str(exc)}
        needle = (search or "").lower()
        operations = []
        for endpoint in result.endpoints:
            if endpoint.evidence != "spec":
                continue
            if needle and needle not in endpoint.raw.lower():
                continue
            operations.append({
                "method": endpoint.method,
                "path": endpoint.raw,
                "url": endpoint.url,
                "spec_url": endpoint.source_url,
                "declared_body_params": endpoint.body_params,
                "authorized_per_spec": endpoint.authorized,
                "probed": bool(endpoint.status_code),
            })
        operations.sort(key=lambda item: (item["path"], item["method"]))

        graphql = [
            op for op in result.graphql
            if not needle or needle in (op.get("name", "") + " "
                                        + " ".join(op.get("fields", []))).lower()
        ]
        graphql.sort(key=lambda item: (item["kind"], item["name"]))

        return {
            "scan_id": scan_id,
            "specs": result.specs,
            "asset_manifests": result.assets,
            "operation_count": len(operations),
            "operations": _limit(operations, limit),
            "graphql_count": len(graphql),
            "graphql_operations": _limit(graphql, limit),
            "note": "规范声明的接口未经请求验证；authorized_per_spec 仅代表"
                    "文档中的鉴权声明。GraphQL 字段集来自前端代码中嵌入的"
                    "操作文档，说明服务端会返回哪些字段。",
        }

    @mcp.tool()
    def jsfind_hosts(scan_id: str, internal_only: bool = False,
                      limit: int = DEFAULT_LIMIT) -> dict:
        """List hosts: those named in the code, and those the scan contacted.

        "content" hosts were *found*, not reached; "scan" hosts were requested.
        The two are reported separately so the numbers cannot be misread.

        Args:
            scan_id: scan id returned by jsfind_scan or jsfind_analyze_file
            internal_only: keep only hosts that look like internal addresses
                (RFC 1918, localhost, .internal/.local). Useful for the
                "someone left an internal hostname in the bundle" case.
            limit: max rows (default 50)
        """
        try:
            result = store.get(scan_id)
        except KeyError as exc:
            return {"error": str(exc)}
        rows = []
        for asset in list(result.hosts) + list(result.scan_hosts):
            if internal_only and "internal" not in " ".join(asset.attributes) \
                    and asset.kind != "internal_host":
                continue
            rows.append({
                "host": asset.value,
                "kind": asset.kind,
                "origin": asset.origin,
                "attributes": asset.attributes,
                "occurrences": asset.occurrences,
                "first_seen": asset.sources[0].source_url if asset.sources else "",
            })
        # The two sources answer different questions: "content" hosts were
        # named in the code, "scan" hosts were actually contacted. Offline
        # the second is always empty, and saying so stops that being read as
        # "the target never called anything".
        content = sum(1 for r in rows if r.get("origin") == "js")
        scanned = sum(1 for r in rows if r.get("origin") == "scan")
        return {
            "scan_id": scan_id,
            "count": len(rows),
            "hosts": _limit(rows, limit),
            "sources": {"content": content, "scan": scanned},
            "note": ("离线模式下 scan 来源恒为空——扫描未发起任何请求，"
                     "这不是目标没连过任何主机。") if scanned == 0 else "",
        }

    @mcp.tool()
    def jsfind_resources(scan_id: str, resource_type: str = "",
                          limit: int = DEFAULT_LIMIT) -> dict:
        """List the resources the scan actually downloaded.

        Args:
            scan_id: scan id returned by jsfind_scan or jsfind_analyze_file
            resource_type: filter — "script", "chunk", "html", "sourcemap"
            limit: max rows (default 50)
        """
        try:
            result = store.get(scan_id)
        except KeyError as exc:
            return {"error": str(exc)}
        resources = result.resources
        if resource_type:
            resources = [r for r in resources if r.type.value == resource_type]
        rows = [{
            "url": r.url,
            "type": r.type.value,
            "status_code": r.status_code,
            "size": r.size,
            "content_type": r.content_type,
            "depth": r.depth,
            "source_url": r.source_url,
        } for r in _limit(resources, limit)]
        return {"scan_id": scan_id, "count": len(rows), "resources": rows}

    @mcp.tool()
    def jsfind_js_files(scan_id: str, origin: str = "", search: str = "",
                        offset: int = 0, limit: int = 100) -> dict:
        """List the JavaScript artifacts a scan collected and saved to disk.

        Use this before searching, so a follow-up query can be narrowed to one
        file. ``origin`` distinguishes entry scripts, chunks and the unminified
        originals recovered from source maps.

        Args:
            scan_id: scan id returned by jsfind_scan
            origin: filter — "script", "chunk" or "sourcemap-source"
            search: substring match against the URL or local path
            offset: page offset
            limit: max rows (default 100)
        """
        try:
            result = store.get(scan_id)
        except KeyError as exc:
            return {"error": str(exc)}
        files = collect_js_files(result)
        if origin:
            files = [f for f in files if f.origin == origin]
        if search:
            needle = search.lower()
            files = [f for f in files
                     if needle in f.url.lower() or needle in f.local_path.lower()]
        rows = [{
            "url": f.url,
            "local_path": f.local_path,
            "origin": f.origin,
            "size": f.size,
            "exists": f.readable(),
            "source_url": f.source_url,
        } for f in files]
        # The directory itself, so a follow-up read or a cleanup does not
        # have to reconstruct it from the per-file paths.
        return _page(rows, limit, offset, scan_id=scan_id, files=_limit(rows, limit, offset),
                     js_dir=result.js_dir)

    @mcp.tool()
    async def jsfind_js_search(
        scan_id: str,
        pattern: str,
        url_filter: str = "",
        ignore_case: bool = False,
        with_context: bool = True,
        limit: int = 50,
    ) -> dict:
        """Regex-search every JavaScript file a scan collected.

        The escape hatch for anything the extractors do not model: a signing
        routine, a vendor field name, an internal hostname, a hardcoded key in
        a bundle the sensitive rules missed. Source-map-recovered originals are
        included, so a secret buried in a minified file is usually still
        readable here.

        Args:
            scan_id: scan id returned by jsfind_scan
            pattern: Python regular expression; a plain word also works
            url_filter: restrict the search to files whose URL contains this
            ignore_case: case-insensitive matching
            with_context: return the surrounding source text
            limit: max matches (default 50, hard cap 200)
        """
        try:
            result = store.get(scan_id)
        except KeyError as exc:
            return {"error": str(exc)}

        def run_search():
            # Regex over every collected bundle is seconds of CPU on a real
            # SPA. FastMCP invokes a sync tool inline on the event loop, where
            # it would stall tools/list for everything else -- so it runs on a
            # worker instead.
            found = collect_js_files(result)
            if not found:
                return None
            return found, search(found, _clean_text(pattern),
                                 ignore_case=ignore_case,
                                 url_filter=_clean_text(url_filter),
                                 max_matches=limit)

        packed = await _offload(run_search)
        if packed is None:
            return {"scan_id": scan_id, "count": 0, "total": 0,
                    "matches": [],
                    "note": "扫描没有保存任何 JS 产物；请用 download_js=true 重新扫描"}
        files, outcome = packed
        if outcome.error:
            return {"scan_id": scan_id, "error": outcome.error}
        rows = [m.to_dict() if with_context else
                {k: v for k, v in m.to_dict().items() if k != "snippet"}
                for m in outcome.matches]
        return {
            "scan_id": scan_id,
            "pattern": pattern,
            "count": len(rows),
            "total": len(outcome.matches),
            "truncated": outcome.truncated,
            "files_matched": outcome.files_matched,
            "files_scanned": outcome.files_scanned,
            "files_skipped": outcome.files_skipped,
            "matches": rows,
        }

    @mcp.tool()
    def jsfind_surface(scan_id: str) -> dict:
        """One-call attack-surface overview: what to test first, and why.

        Built to answer "where do I start" in a single round trip. Returns a
        ranked shortlist built from confirmed endpoints, unauthenticated write
        methods, leaked credentials, known-vulnerable middleware versions,
        internal hosts and attack-relevant parameters, plus the coverage
        caveats that tell you what the scan could *not* see.

        Args:
            scan_id: scan id returned by jsfind_scan
        """
        try:
            result = store.get(scan_id)
        except KeyError as exc:
            return {"error": str(exc)}
        return build_surface(result)

    @mcp.tool()
    async def jsfind_analyze_file(
        files: list,
        base_url: str = "",
        export_json: str = "",
    ) -> dict:
        """Analyze JavaScript / HTML already on disk, without touching the network.

        Use this when the target is unavailable but the artifact is not: a
        bundle the agent just downloaded, a script leaked out of another
        system, a saved ``.map``, or a JavaScript API endpoint whose bundle was
        served directly with no HTML root. Same extractors as a live scan, so
        results are directly comparable.

        Relative references resolve against ``base_url``; pass the real origin
        when you are authorized to test it. Every produced endpoint is marked
        authorized=false unless you do.

        Args:
            files: file, directory or glob-free list of paths (.js/.mjs/.map/.html).
                An entry may also be ``{"path": "...", "origin": "..."}`` to give
                one file its own origin -- a shared chunk can point at several
                origins, and resolving them all against one base misattributes
                every reference.
            base_url: origin the relative references belong to
            export_json: write the full result to this path as JSON. Useful for
                handing the result to another tool without re-reading it out
                of the conversation.
        """
        from .localfile import LocalFileError, analyze_local

        if not files:
            return {"error": "files is required"}
        config = deepcopy(store.base) if store.base is not None else load_config()
        scanner = Scanner(config)
        base_url = _clean_text(base_url)
        export_json = _clean_text(export_json)
        try:
            # Same extraction pass as a live scan, over files already on disk:
            # seconds of CPU on a big bundle, so it runs off the event loop
            # rather than stalling every other request while it works.
            cleaned = []
            for entry in files:
                if isinstance(entry, dict):
                    cleaned.append({k: _clean_text(v) if isinstance(v, str)
                                    else v for k, v in entry.items()})
                else:
                    cleaned.append(_clean_text(entry))
            local = await _offload(
                analyze_local, config, scanner.engine, cleaned,
                base_url=base_url)
        except LocalFileError as exc:
            return {"error": str(exc)}
        except Exception as exc:  # noqa: BLE001
            return {"error": f"{type(exc).__name__}: {exc}"}

        result = local.result
        scan_id = store.put(result)
        exported = ""
        if export_json:
            try:
                target = Path(export_json).expanduser()
                if target.parent and not target.parent.exists():
                    target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(
                    json.dumps(result.to_dict(), ensure_ascii=False, indent=2,
                               default=str),
                    encoding="utf-8")
                exported = str(target.resolve())
            except OSError as exc:
                return {"error": f"无法写入 export_json：{exc}"}
        return {
            "scan_id": scan_id,
            "mode": "local",
            "exported_json": exported,
            "files": local.files,
            "skipped": local.skipped,
            "resources": result.statistics.resources,
            "endpoints": result.statistics.endpoints,
            "sensitive_findings": result.statistics.findings,
            "parameters": result.statistics.parameters,
            "hints": result.hints[:10],
            "note": "离线分析未发起任何网络请求；接口默认标记为未授权。",
        }

    @mcp.tool()
    async def jsfind_diagnostics() -> dict:
        """Report what this installation can and cannot do.

        Call it before trusting a result: if the AST grammar failed to load, or
        a rule file is broken, or the JS artifacts are not being written to
        disk, ``jsfind_js_search`` and the endpoint methods degrade
        accordingly — and that degradation is otherwise invisible.
        """
        from .banner import BannerEngine
        from .resources import DATA_FILES, describe_environment, \
            is_frozen, safe_data_path

        scanner = Scanner(store.base)
        banner_engine = BannerEngine.default(
            rules_file=(store.base.banners_file if store.base else ""))
        env = describe_environment()

        # What each collection mode can actually answer. A caller who reads
        # "caveats: []" and then gets endpoints: 0 has no way to tell "the
        # target has no interfaces" from "this mode cannot see them", and in
        # a security assessment that difference is the whole game.
        mode_matrix = {
            "local": {
                "endpoints": "完整（正则 + AST）",
                "surface": "完整",
                "hosts": "仅 content（代码里出现的主机）",
                "banners": "不可用（离线无响应头）",
                "probe": "不适用（离线不发请求）",
                "routes_rendered": "不可用（离线不渲染路由）",
            },
            "online": {
                "endpoints": "完整",
                "surface": "完整",
                "hosts": "content + scan 双来源",
                "banners": "完整",
                "probe": "可用（需 probe: true）",
                "routes_rendered": "可用（需 crawl_routes）",
            },
        }

        caveats: list[str] = []
        if not _ast_available():
            caveats.append(
                "AST 不可用：接口方法与请求参数退化为纯正则结果，精度下降。")
        for diagnostic in scanner.engine.diagnostics + banner_engine.diagnostics:
            caveats.append(f"规则诊断：{diagnostic}")
        missing = [name for name in DATA_FILES if not safe_data_path(name).is_file()]
        if missing:
            caveats.append("内置数据文件缺失：" + "、".join(missing))

        return {
            "version": SERVER_VERSION,
            "frozen": is_frozen(),
            "environment": env,
            # Absolute, not as-configured: a relative default resolves against
            # the server cwd, and the model cannot know what that is.
            "js_dir": _default_js_dir(store.base),
            "proxy": describe_proxy(
                store.base.request.proxy if store.base else "",
                store.base.request.no_proxy if store.base else "",
                store.base.request.trust_env if store.base else True,
            ),
            "js_saved": bool(store.base.save_js) if store.base else True,
            "js_dir_overridable_per_scan": True,
            "mode_matrix": mode_matrix,
            "ast_enabled": _ast_available(),
            "regex_backend": regex_backend(),
            "url_rules": scanner.engine.url_count(),
            "sensitive_rules": scanner.engine.sensitive_count(),
            "banner_rules": len(banner_engine),
            # Where stderr goes when the client does not read it. Empty when
            # stderr is still the terminal it was started from.
            "diagnostic_log": str(_utils.DIAGNOSTIC_LOG or ""),
            # Reported, not enforced: several processes at once usually means
            # a client restarted without reaping the last one, and the fix is
            # to clean up, not to refuse the new one its server.
            "instances_running": _utils.count_siblings(),
            "tool_count": len(await mcp.list_tools()),
            "tools": sorted(tool.name for tool in await mcp.list_tools()),
            "caveats": caveats,
        }

    @mcp.tool()
    def jsfind_release(scan_id: str = "") -> dict:
        """Release collected scans from memory, now.

        A finished scan holds every endpoint, finding and parameter of a whole
        target, and a session that runs several targets accumulates all of
        them. Entries also age out on their own (10 minutes, 20 scans by
        default); this is for when the caller is done with a scan and wants the
        memory back immediately.

        Args:
            scan_id: scan to drop. Empty drops every scan.
        """
        if scan_id:
            try:
                store.get(scan_id)
            except KeyError as exc:
                return {"error": str(exc)}
            released = store.release(scan_id)
            return {"released": [scan_id] if released else [],
                    "remaining": store.ids()}
        dropped = store.clear()
        return {"released_count": dropped, "remaining": []}

    @mcp.tool()
    def jsfind_scans() -> dict:
        """List scans currently held in memory.

        Each entry carries when it ran and what it covered, so two runs of the
        same target can be told apart. The list is in-memory and is lost when
        the server restarts -- use jsfind_analyze_file's export_json to keep
        evidence for a report.

        Entries are bounded too: at most ``max_scans`` are kept and each expires
        ``ttl`` seconds after it was stored. jsfind_release drops one now.
        """
        rows = []
        for scan_id in store.ids():
            try:
                result = store.get(scan_id)
            except KeyError:
                continue
            rows.append({
                "scan_id": scan_id,
                "mode": getattr(getattr(result, "mode", None), "value", "unknown"),
                "target": result.target,
                "started_at": getattr(result, "started_at", ""),
                "endpoints": len(result.endpoints),
                "findings": len(result.findings),
                "js_dir": getattr(result, "js_dir", ""),
            })
        return {
            "scans": [r["scan_id"] for r in rows],
            "detail": rows,
            "session": store.session,
            "scan_count": len(rows),
            "max_scans": store.max_scans,
            "ttl_seconds": store.ttl,
            "note": "内存中保存，服务重启即失效，最多保留 max_scans 条、"
                    "每条 ttl_seconds 后过期；jsfind_release 可立即释放。"
                    "要留存证据请用 jsfind_analyze_file 的 export_json。",
        }

    @mcp.tool()
    def jsfind_diff(scan_id: str, known: list[str] | None = None,
                    known_file: str = "", suffix: bool = True,
                    limit: int = DEFAULT_LIMIT) -> dict:
        """Which endpoints does this scan expose that your list does not have?

        The everyday question: a list of interfaces came from somewhere, the
        code moved on, and the question is what is new. Feed in the list and
        get back the endpoints this scan found that the list does not mention
        -- plus, in the other direction, the entries the list still claims but
        the code no longer serves, which is how a stale list is noticed.

        Matching is on the path shape, not the full URL: ``/user/42`` and
        ``/user/{userId}`` are the same interface, and a query string in the
        list is ignored. An entry may be a bare path, a full URL, or
        ``METHOD path``; an entry without a method matches under any method,
        because a hand-kept list is usually a list of paths.

        Args:
            scan_id: scan id returned by jsfind_scan or jsfind_analyze_file
            known: the existing endpoint list
            known_file: path to a file holding that list, one per line.
                Lines starting with # are comments. Used when the list is long
                enough that passing it inline is awkward.
            suffix: also treat a known path as covering the same path behind
                a prefix, so /order/submit matches /api/v2/order/submit. Set
                false for exact-path comparison only.
            limit: max rows of new endpoints (default 50)
        """
        try:
            result = store.get(scan_id)
        except KeyError as exc:
            return {"error": str(exc)}

        entries = list(known or [])
        if known_file:
            try:
                with open(known_file, "r", encoding="utf-8") as handle:
                    for line in handle:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            entries.append(line)
            except OSError as exc:
                return {"error": f"无法读取 known_file：{exc}"}

        report = diff_endpoints(result.endpoints, entries, suffix)
        report["scan_id"] = scan_id
        report["new_endpoints"] = _limit(report["new_endpoints"], limit)
        report["note"] = (
            "new_endpoints 是本次扫描发现、但你给的清单里没有的接口；"
            "stale_known 是清单里有、但本次代码里没找到的条目。"
            "路径按形状匹配，数字段与 {占位符} 视作同一段。")
        return report

    @mcp.tool()
    async def jsfind_probe(
        scan_id: str,
        base_url: str = "",
        proxy: str = "",
        no_proxy: str = "",
        trust_env: bool = True,
        verify_tls: bool = False,
        business_codes: dict | None = None,
        limit: int = 100,
        timeout_seconds: int | str = 0,
        include_not_found: bool = False,
    ) -> dict:
        """Confirm an offline result's endpoints against a live target.

        The gap this closes: `jsfind_analyze_file` can name a hundred interfaces
        but cannot tell you which ones exist, because it never sends a request.
        Verifying them by hand with curl is the step where the tool loses to a
        human. This does that pass in one call — read-only ``GET``, nothing else.

        Only ``type="api"`` endpoints are probed. Routes are pages (the crawl
        already renders those) and sockets need a handshake a GET cannot do.
        A path still holding a ``{placeholder}`` is skipped: it can only 404.

        Args:
            scan_id: a scan from jsfind_scan or jsfind_analyze_file
            base_url: the live origin to probe against. **Required for offline
                results** — an offline scan resolves relative paths against a
                placeholder such as ``https://local.invalid/``, and probing
                that would only prove the placeholder does not exist. Paths are
                rewritten onto this origin; the query string is kept.
            proxy: route the probes through a proxy, same forms as jsfind_scan.
            no_proxy: comma-separated hosts to bypass the proxy.
            trust_env: honour HTTP_PROXY / HTTPS_PROXY / ALL_PROXY.
            verify_tls: verify the target certificate (off by default, because
                real targets are routinely https://IP with a self-signed cert).
            business_codes: category -> list of response-body substrings that
                mean it, e.g. ``{"biz_auth_fail": ["\"code\":477"]}``. A 200
                whose body matches takes that signal, so "200 but auth failed"
                stops being read as success. Offline analysis cannot do this at
                all — there is no body until something is requested.
            limit: max endpoints to probe (default 100). This sends traffic.
            timeout_seconds: cap on the whole probe pass (0 = use the config).
            include_not_found: keep 404 rows in the summary (they are always
                written back to the endpoint table; this only affects the
                ``not_found`` list in the response).
        """
        try:
            result = store.get(scan_id)
        except KeyError as exc:
            return {"error": str(exc)}

        config = deepcopy(store.base or load_config())
        config.request.trust_env = bool(trust_env)
        config.request.verify_tls = bool(verify_tls)
        if (proxy or "").strip():
            try:
                config.request.proxy = normalize_proxy(proxy)
            except ProxyError as exc:
                return {"error": str(exc)}
        if (no_proxy or "").strip():
            config.request.no_proxy = no_proxy.strip()
        if business_codes:
            config.request.business_codes = dict(business_codes)
        budget = _seconds(timeout_seconds)
        if budget > 0:
            config.request.timeout = float(budget)

        base = (base_url or "").strip().rstrip("/")
        targets = []
        skipped_placeholder = 0
        for endpoint in result.endpoints:
            if endpoint.type != "api":
                continue
            if route_param_names(endpoint.url):
                skipped_placeholder += 1
                continue
            if base:
                parsed = urlparse(endpoint.url)
                path = parsed.path or "/"
                query = f"?{parsed.query}" if parsed.query else ""
                endpoint.url = base + path + query
            targets.append(endpoint)

        if not targets:
            return {
                "scan_id": scan_id,
                "probed": 0,
                "note": "没有可探测的 api 端点（socket / route 不探测；"
                        "含 {占位符} 的路径会跳过）。",
                "skipped_placeholder": skipped_placeholder,
            }
        targets = targets[:max(1, limit)]

        signals: dict = {}
        not_found = []
        failures = 0

        async with Client(config) as client:
            for endpoint in targets:
                try:
                    response = await client.get(endpoint.url)
                except Exception:  # noqa: BLE001 - one dead endpoint is not a failure
                    failures += 1
                    continue
                endpoint.status_code = response.status_code
                endpoint.signal = classify_status(response.status_code)
                business = _business_signal(response.text or "",
                                            config.request.business_codes)
                if business:
                    endpoint.signal = business
                signals[endpoint.signal] = signals.get(endpoint.signal, 0) + 1
                if endpoint.signal == "not_found" and not include_not_found:
                    not_found.append(endpoint.url)

        titled = sorted(signals.items(), key=lambda kv: -kv[1])
        return {
            "scan_id": scan_id,
            "probed": len(targets) - failures,
            "failed_requests": failures,
            "base_url": base,
            "signals": {name: count for name, count in titled},
            "signal_legend": _SIGNAL_LEGEND,
            "not_found": not_found[:50],
            "not_found_count": len(not_found),
            "skipped_placeholder": skipped_placeholder,
            "reconciliation": {
                "endpoints_in_scan": len(result.endpoints),
                "probe_eligible": len(targets),
                "probed": len(targets) - failures,
                "skipped_placeholder": skipped_placeholder,
            },
            "note": ("已把 signal/status_code 写回该 scan，jsfind_endpoints 现在能看到。"
                     "探测只发 GET。" if not base else
                     "已把端点重写到 base_url 并写回 scan，jsfind_endpoints "
                     "现在显示真实主机。探测只发 GET。"),
        }

    @mcp.tool()
    def jsfind_rules(category: str = "", search: str = "",
                     kind: str = "body") -> dict:
        """List the compiled extraction rules and the regex backend in use.

        Args:
            category: filter by category, e.g. "sensitive" or "web_server"
            search: substring match against the rule id or name
            kind: "body" for the JS/HTML rule set (default), or "banner" for
                the server / middleware version rules
        """
        if kind == "banner":
            from .banner import BannerEngine

            engine = BannerEngine.default()
            rules = engine.describe()
            if category:
                rules = [rule for rule in rules if rule["category"] == category]
            if search:
                needle = search.lower()
                rules = [rule for rule in rules
                         if needle in rule["id"].lower()
                         or needle in rule["product"].lower()]
            return {
                "kind": "banner",
                "count": len(rules),
                "contract": "只匹配带版本号的指纹；无版本号的匹配一律丢弃。",
                "diagnostics": engine.diagnostics,
                "rules": rules,
            }

        scanner_engine = Scanner(store.base).engine
        rules = scanner_engine.describe()
        if category:
            rules = [rule for rule in rules if rule["category"] == category]
        if search:
            needle = search.lower()
            rules = [rule for rule in rules
                     if needle in rule["id"].lower() or needle in rule["name"].lower()]
        return {
            "kind": "body",
            "backend": regex_backend(),
            "ast_enabled": _ast_available(),
            "count": len(rules),
            "diagnostics": scanner_engine.diagnostics,
            "rules": rules,
        }

    return mcp


def _ast_available() -> bool:
    from .discover.jsparser import parser_available

    return parser_available()


def _as_bool(value: str):
    """Tri-state parse: None for "not specified".

    Anything unrecognised is treated as unspecified rather than False,
    so a typo does not silently return an empty table that reads like
    "nothing in scope".
    """
    text = (value or "").strip().lower()
    if text in ("", "any", "all", "*"):
        return None
    if text in ("1", "true", "yes", "y", "in", "in_scope", "authorized"):
        return True
    if text in ("0", "false", "no", "n", "out", "out_of_scope"):
        return False
    return None


#: What each probe signal means, shared by jsfind_endpoints and jsfind_probe so
#: the two can never drift apart.
_SIGNAL_LEGEND = {
    "exists": "2xx 接口真实存在",
    "protected": "401/403 接口存在但需要鉴权",
    "method": "405 接口存在，GET 不是正确方法",
    "gone": "410 已移除",
    "error": "5xx 接口存在但服务端异常",
    "not_found": "404 无存在证据（可能是通用 404 处理）",
    "unprobed": "未发起探测（socket 类型恒为此值：GET 无法确认 WebSocket 是否存在）",
    "biz_success": "响应体表示业务成功（按 request.business_codes 判定）",
    "biz_auth_fail": "响应体表示鉴权失败（按业务码判定）",
    "biz_param_missing": "响应体表示参数缺失（按业务码判定）",
    "biz_error": "响应体表示业务失败（按业务码判定）",
}


def _business_signal(body: str, rules: dict) -> str:
    """The signal the response *body* implies, if the operator defined one.

    Patterns are plain substrings. The operator writes ``"code":477`` to say
    what their own API means by 477; that beats any guess made here about what
    a number means.
    """
    if not body or not rules:
        return ""
    for category, patterns in rules.items():
        if isinstance(patterns, str):
            patterns = [patterns]
        for pattern in patterns or []:
            if pattern and pattern in body:
                return str(category)
    return ""


def _zero_result_note(result, kind: str) -> str:
    """Why a scan returned nothing, when the answer is not "there is nothing".

    A zero count from a local scan is ambiguous in a way that matters: it can
    mean the target has no such thing, or it can mean this mode cannot see it.
    Without a note, a tester reads endpoints: 0 as "no interfaces" and moves
    on. That is the false negative this exists to prevent.
    """
    if getattr(result, "mode", None) is not None:
        mode = getattr(result.mode, "value", str(result.mode))
    else:
        mode = ""
    if mode != "local":
        return ""
    return {
        "endpoints": "离线模式下 count=0 不代表目标没有接口：未探测、"
                     "未渲染路由，且正则提取只覆盖代码里出现的形态。"
                     "用 jsfind_js_search 做一次兜底检索再下结论。",
        "hosts": "离线模式只统计代码里出现的主机；scan 来源（实际请求过的）"
                 "恒为空，count=0 可能只是目标把主机写在了别处。",
        "banners": "离线模式没有响应头，banners 恒为空。",
    }.get(kind, "")


def _effective_proxy(config: Config, result) -> tuple:
    """(proxy_in_effect, note) with the password already removed."""
    described = describe_proxy(config.request.proxy,
                                config.request.no_proxy,
                                config.request.trust_env)
    note = ""
    for message in described.get("notes", []):
        note += message + " "
    notes = getattr(result, "issues", None) or []
    for issue in notes:
        if "proxy" in str(getattr(issue, "code", "")):
            note += str(getattr(issue, "message", "")) + " "
    return described.get("proxy", ""), note.strip()


def _default_js_dir(config: Config | None) -> str:
    """The absolute directory a scan uses when it passes no js_dir.

    Takes the config explicitly: the module-level ``store`` is a closure
    inside build_server(), so a sibling helper cannot read it.
    """
    raw = (config.js_dir if config else "") or "./jsfind-js"
    try:
        return str(Path(raw).expanduser().resolve())
    except (OSError, RuntimeError):
        return raw


def _clean_text(value) -> str:
    """Drop lone surrogates so a string can always be encoded and replied with.

    A model can emit ``\\udcff`` in a URL or a path — a code unit with no
    character behind it. Fine to hold in memory, but it cannot be written as
    UTF-8, so the reply carrying it fails to serialize and the caller is left
    waiting on a call that will never answer. Cheapest to strip it at the door.
    """
    text = str(value or "")
    if not any("\ud800" <= ch <= "\udfff" for ch in text):
        return text
    return text.encode("utf-8", "replace").decode("utf-8", "replace")


def _seconds(value, default: float = 0.0) -> float:
    """A timeout from a caller that may not have sent a number.

    Tool calls come out of a model, and a model reading an operator's config
    will happily forward whatever it saw there — a bare env-var name like
    ``REQUEST_TIMEOUT`` instead of the seconds it stands for. Strict typing
    turns that into a client-side parse failure before the request is even
    sent, which is what "the tools vanished" looked like from the outside.
    Take the plausible forms and fall back to the default for the rest, so a
    bad timeout costs the caller a default budget instead of the whole call.

    The result is always clamped to ``MAX_TIMEOUT_SECONDS``: a model that asks
    for a day of budget gets the cap and is told so, rather than a scan nobody
    can wait for.
    """
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        number = float(value)
    else:
        text = str(value or "").strip().lower().rstrip("s")
        if not text:
            return default
        try:
            number = float(text)
        except ValueError:
            return default
    if number <= 0:
        return default
    return min(number, MAX_TIMEOUT_SECONDS)


#: Ceiling on a caller-supplied response cap. Higher than any bundle worth
#: analyzing whole (chunking would refuse it long before), low enough that a
#: model asking for "unlimited" cannot turn a hostile target into an OOM.
MAX_RESPONSE_BYTES_CAP = 512 * 1024 * 1024


def _size_bytes(value, default: int = 0) -> int:
    """A byte count from a caller that may not have sent a plain number.

    Same failure mode ``_seconds`` exists for: a model forwards ``"20MB"`` or
    an env-var name where an integer is expected. Accept the plausible forms —
    a number, a digit string, a ``20MB``/``1gb``/``512kb`` literal — and fall
    back to the default for everything else, so one bad value costs the
    configured cap instead of the whole call. 0 and negatives read as "no
    opinion": the configured default wins.
    """
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        number = float(value)
    else:
        text = str(value or "").strip().lower().replace("_", "").replace(" ", "")
        if not text:
            return default
        multiplier = 1
        for suffix, factor in (("kb", 1024), ("mb", 1024 ** 2),
                               ("gb", 1024 ** 3), ("k", 1024),
                               ("m", 1024 ** 2), ("g", 1024 ** 3), ("b", 1)):
            if text.endswith(suffix):
                multiplier, text = factor, text[:-len(suffix)]
                break
        try:
            number = float(text) * multiplier
        except ValueError:
            return default
    if number <= 0:
        return default
    return min(int(number), MAX_RESPONSE_BYTES_CAP)


def _limit(rows: list, limit: int, offset: int = 0) -> list:
    """Page a result set, clamped to something a model can actually read.

    Every listing tool reports ``total`` and ``has_more`` alongside ``count``, so
    a caller can tell "that is all of them" from "that is the first page" —
    without that signal a small ``limit`` looks like a complete answer.
    """
    limit = max(1, min(limit or DEFAULT_LIMIT, MAX_LIMIT))
    start = max(0, offset)
    return rows[start:start + limit]


def _page(rows: list, limit: int, offset: int = 0, **extra) -> dict:
    """A paginated payload carrying the completeness signals a caller needs."""
    total = len(rows)
    window = _limit(rows, limit, offset)
    start = max(0, offset)
    return {
        "count": len(window),
        "total": total,
        "offset": start,
        "limit": max(1, min(limit or DEFAULT_LIMIT, MAX_LIMIT)),
        "has_more": start + len(window) < total,
        **extra,
    }


#: Endpoint types the interface tool will show. "socket" is listed because a
#: discovered WebSocket URL is a finding in its own right; hiding it behind an
#: api-only filter would make the protocol pass look like it found nothing.
# "route" is listed too: a front-end path and an API path are both HTTP
# surfaces a tester enumerates, and filtering routes out of the interface
# tool made every SPA path invisible while the caller counted them as
# "endpoints" in the scan summary.
_ENDPOINT_TYPES = ("api", "socket", "route")


def _filter_endpoints(endpoints, evidence: str, method: str, search: str,
                      kind: str = "", authorized: str = "") -> list:
    """Narrow the endpoint table.

    ``authorized`` is a tri-state: empty means "no opinion", which is
    what an offline run with no base_url produces for every row. Being
    able to ask for either side explicitly is the point -- an operator
    who supplied an origin needs to separate "in scope" from "found in
    someone else's bundle".
    """
    out = []
    needle = (search or "").lower()
    want_auth = _as_bool(authorized)
    for endpoint in endpoints:
        if endpoint.type not in _ENDPOINT_TYPES:
            continue
        if kind and endpoint.type != kind:
            continue
        if want_auth is not None and bool(endpoint.authorized) != want_auth:
            continue
        if evidence and endpoint.evidence != evidence:
            continue
        if method and (endpoint.method or "").upper() != method.upper():
            continue
        if needle and needle not in endpoint.url.lower():
            continue
        out.append(endpoint)
    out.sort(key=lambda e: (-{"runtime": 3, "full-url": 2, "static": 1}.get(
        e.evidence, 0), e.url))
    return out


def _severity_histogram(findings) -> dict:
    histogram: dict[str, int] = {}
    for finding in findings:
        histogram[finding.severity.value] = \
            histogram.get(finding.severity.value, 0) + 1
    return histogram


# -- entry points -------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for the MCP server."""
    # The config block is Chinese; without this a Windows console (or a frozen
    # build) writes it in the legacy code page and it arrives as mojibake.
    _utils.use_utf8_stdio()
    # An MCP client usually never reads the stderr pipe it hands us. A scan
    # logs every request, that pipe fills, and the server blocks in a write to
    # it — which is how "the tools vanish until I restart" happens. Off the
    # terminal, stderr goes to a log file instead.
    _utils.redirect_diagnostics()
    # A client that dies without closing the pipe leaves this process behind.
    _utils.watch_parent()
    parser = argparse.ArgumentParser(
        prog="jsfind-mcp-server",
        description="jsfind-mcp MCP server (JavaScript information collection)",
    )
    parser.add_argument("--version", action="version",
                        version=f"{SERVER_NAME} {SERVER_VERSION}",
                        help="print the version and exit")
    parser.add_argument("--transport", choices=("stdio", "http"), default="stdio",
                        help="stdio (default) or streamable HTTP")
    parser.add_argument("--host", default="127.0.0.1",
                        help="listen address for --transport http")
    parser.add_argument("--port", type=int, default=8765,
                        help="listen port for --transport http")
    parser.add_argument("--rules-file", default="",
                        help="custom rules file (HaE format)")
    parser.add_argument("--print-config", action="store_true",
                        help="print the paste-ready client config and exit")
    parser.add_argument("--write-config", default="",
                        metavar="DIR",
                        help="write the ready-to-paste mcp.json into DIR "
                             "(default: current directory)")
    parser.add_argument("--no-config", action="store_true",
                        help="do not print or write the client config at startup")
    args = parser.parse_args(argv)

    config = load_config()
    if args.rules_file:
        config.rules_file = args.rules_file
    try:
        seed_user_rules()
    except OSError:
        pass

    store = ScanStore(
        config,
        max_scans=int(os.getenv("JSFIND_MAX_SCANS", DEFAULT_MAX_SCANS)),
        ttl=float(os.getenv("JSFIND_SCAN_CACHE_TTL", DEFAULT_SCAN_TTL)),
    )
    server = build_server(store)

    # The client config is emitted before the transport starts, because this is
    # the moment the operator needs it: the server is up, and they now want to
    # wire it into a client.
    spec = mcpconfig.detect(
        argv=argv,
        transport=args.transport,
        url=f"http://{args.host}:{args.port}/mcp" if args.transport == "http" else "",
        # These only control this launcher, not the server a client would run.
        drop=(("--print-config", 0), ("--no-config", 0), ("--write-config", 1)),
    )
    if args.print_config:
        print(mcpconfig.render(spec))
        return 0
    if not args.no_config:
        target = args.write_config or "."
        mcpconfig.announce(spec, target)

    if args.transport == "http":
        return _serve_http(server, args.host, args.port)

    print(f"{SERVER_NAME} {SERVER_VERSION} ready (stdio), "
          f"regex backend={regex_backend()}, ast={_ast_available()}",
          file=sys.stderr)
    server.run(transport="stdio")
    # stdin closed: the client is gone. Exit now rather than waiting on some
    # thread to notice — a lingering process is exactly the pile of half-dead
    # instances that makes "the tools vanished" look like it persisted.
    os._exit(0)
    return 0


def _serve_http(server, host: str, port: int) -> int:
    """Serve streamable HTTP so several clients can share one scan store."""
    import uvicorn
    from starlette.applications import Starlette
    from starlette.routing import Mount

    app = Starlette(routes=[Mount("/", app=server.sse_app())])
    print(f"{SERVER_NAME} serving MCP on http://{host}:{port}", file=sys.stderr)
    uvicorn.run(app, host=host, port=port, log_level="warning")
    return 0


# Needed because the generated client config tells source-checkout users to run
# ``python -m jsfind_mcp.server``; without this guard that command starts and exits
# silently.
if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
