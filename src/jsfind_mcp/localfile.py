"""Offline analysis of JavaScript already on disk.

Several situations have no site to crawl but do have a file:

* a bundle an agent just downloaded and wants read *before* re-scanning;
* a ``.js`` leaked out of another system and saved locally;
* a source map or a single extracted script from an earlier report;
* a JavaScript API endpoint whose bundle was served directly, with no HTML
  root to start from.

Pointing the scanner at a local path answers these without a network round
trip. The extraction pipeline is the same one used for a live target, so
results are directly comparable.

Because no origin is known, relative references resolve against
``base_url`` (a guessable synthetic origin by default) and every produced
endpoint is marked ``authorized=False`` unless the caller supplies a base URL
they are actually authorized to test.
"""

from __future__ import annotations

from datetime import datetime, timezone

import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from .analyze import Engine
from .chunking import (
    AST_MAX_BYTES,
    REJECT_MAX_BYTES,
    body_bytes,
    is_rejected,
    split_by_lines,
    wants_ast,
)
from .collect import offline_response
from .config import Config
from .discover import (
    Kind,
    analyze_js,
    base_path_names,
    from_dynamic,
    joined_prefixes,
    prefix_values,
    resolve_joined,
    from_javascript,
    from_protocols,
    from_requirejs,
    from_webpack,
    routes_from_source,
    is_third_party_bundle,
    params_from_ast,
    parse_html,
    parse_source_map,
    source_map_reference,
)
from .discover.types import Candidate
from .model import (
    EVIDENCE_STATIC,
    Mode,
    Endpoint,
    Finding,
    Param,
    ParamHit,
    RequestSpec,
    Resource,
    ResourceType,
    Result,
    route_param_names,
)
from .pipeline import InlineItem, build_template, render_body
from .utils import is_filesystem_path, is_javascript_path, is_static_asset_path, join_base_url, looks_like_api_path, resolve_url

#: extensions treated as script
_SCRIPT_SUFFIXES = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".json",
                    ".map", ".html", ".htm")

#: Schemes no HTTP request can speak to. Reported as type="socket" and never
#: given a request template, for the same reason the online path does it.
_NON_HTTP_SCHEMES = frozenset({"ws", "wss"})

#: a local file larger than this is refused: it is almost certainly not the
#: artifact the caller meant to pass. Applied to every input, whether it was
#: named directly or turned up by walking a directory.
_MAX_BYTES = 64 * 1024 * 1024

#: How many files a single directory walk may contribute. The walk is meant
#: for one build output folder; without a bound it turns into an
#: unbounded rglob over whatever the caller happened to point at.
_MAX_FILES_PER_DIR = 500

#: inline base used when the caller supplies none
_DEFAULT_BASE = "https://local.invalid/"


@dataclass
class LocalFileError(Exception):
    """A local-input problem worth reporting verbatim to the caller."""

    message: str = ""


@dataclass
class LocalResult:
    """Outcome of one offline analysis."""

    result: Result
    #: Keys of GraphQL operation documents already recorded, so a document
    #: found in two files is reported once. Kept here because _absorb is
    #: called from several places and cannot carry its own accumulator.
    graphql_keys: set = field(default_factory=set)
    #: Hosts seen in code, keyed by hostname. Held here rather than on
    #: Result until the run finishes, so one host found twice is one row.
    hosts: dict = field(default_factory=dict)
    files: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def resolve_inputs(paths: list, default_origin: str = "") -> tuple:
    """Expand paths, directories and URLs into a list of local files.

    Returns ``(files, skipped, origins)``. A skipped entry carries the reason,
    because silently dropping an input would read to a caller as "nothing
    found". ``origins`` maps each resolved file to the origin its relative
    references belong to, so a bundle that points at two different origins
    can be told which is which.
    """
    files: list[Path] = []
    skipped: list[str] = []
    seen: set[str] = set()
    origins: dict = {}

    for raw in paths:
        origin = default_origin
        if isinstance(raw, dict):
            origin = str(raw.get("origin", "") or default_origin)
            raw = raw.get("path", "")
        candidate = str(raw).strip()
        if not candidate:
            continue
        if "://" in candidate:
            skipped.append(f"{candidate}（是 URL，请用 jsfind_scan 的 url 参数）")
            continue
        path = Path(candidate).expanduser()
        if not path.exists():
            skipped.append(f"{candidate}（不存在）")
            continue
        if path.is_dir():
            found = 0
            too_big = 0
            for child in sorted(path.rglob("*")):
                if found >= _MAX_FILES_PER_DIR:
                    skipped.append(
                        f"{candidate}（文件数已达 {_MAX_FILES_PER_DIR}，"
                        "后续未收集；请指向更具体的目录）")
                    break
                if not (child.is_file()
                        and child.suffix.lower() in _SCRIPT_SUFFIXES):
                    continue
                try:
                    if child.stat().st_size > _MAX_BYTES:
                        too_big += 1
                        continue
                except OSError:
                    continue
                if str(child) in seen:
                    continue
                seen.add(str(child))
                files.append(child)
                origins[str(child)] = origin
                found += 1
            if too_big:
                skipped.append(
                    f"{candidate}（{too_big} 个文件超过 "
                    f"{_MAX_BYTES // (1024 * 1024)} MB，已跳过）")
            if not found and not too_big:
                skipped.append(f"{candidate}（目录内没有 .js/.map/.html 文件）")
            continue
        if path.stat().st_size > _MAX_BYTES:
            skipped.append(f"{candidate}（超过 {_MAX_BYTES // (1024 * 1024)} MB）")
            continue
        if str(path) not in seen:
            seen.add(str(path))
            files.append(path)
            origins[str(path)] = origin
    return files, skipped, origins


def analyze_local(config: Config, engine: Engine, paths: list,
                  base_url: str = "") -> LocalResult:
    """Run the full extraction pipeline over local files. No network access.

    ``paths`` may hold plain strings, or ``{"path": ..., "origin": ...}``
    entries. The per-file origin exists because one bundle can carry
    references to several origins -- a shared chunk that a CDN serves and that
    also points at an internal API -- and resolving all of them against one
    base would misattribute every one of them.
    """
    files, skipped, origins = resolve_inputs(paths, base_url)
    if not files:
        raise LocalFileError(
            "没有可分析的文件：" + ("；".join(skipped) or "未提供输入"))

    base = base_url.strip() or _DEFAULT_BASE
    parsed = urlparse(base)
    if not parsed.scheme or not parsed.netloc:
        raise LocalFileError(f"base_url 必须是绝对地址，收到 {base_url!r}")
    if base_url.strip() == "":
        skipped.append(
            f"未提供 base_url，相对引用按合成源 {_DEFAULT_BASE} 解析，"
            "产出的接口均标记为未授权")

    # Mode.LOCAL, not EVIDENCE_STATIC: these are different vocabularies and
    # passing the evidence constant here left result.mode a bare string,
    # which made every downstream reader of mode.value raise AttributeError.
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    result = Result(target=f"file://{files[0].name}", mode=Mode.LOCAL,
                    user_agent="local-analysis", started_at=started)
    result.technologies.append("local-file-analysis")
    local = LocalResult(result=result, files=[str(f) for f in files],
                        skipped=skipped)

    finding_keys: set[tuple] = set()
    param_keys: set[tuple] = set()
    endpoint_keys: set[str] = set()
    base_paths: list[str] = []
    hints: list[str] = []
    saved: list[Resource] = []

    for path in files:
        # Fault isolation. One file that breaks an extractor must not cost
        # the caller every other file: a two-file analysis that reported a
        # bare IndexError left the whole batch unusable and gave no hint of
        # which file was at fault. The traceback is recorded so the next run
        # says where to look.
        try:
            try:
                body = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                local.skipped.append(f"{path}（读取失败：{exc}）")
                continue
            if not body.strip():
                local.skipped.append(f"{path}（空文件）")
                continue

            # The origin this file's relative references belong to: the one the
            # caller named for it, or the run-wide base.
            file_origin = origins.get(str(path), base)
            pseudo = _pseudo_url(path, file_origin or base)
            is_map = path.suffix.lower() == ".map"
            is_html = path.suffix.lower() in (".html", ".htm")

            saved.append(Resource(
                url=pseudo, type=ResourceType.SOURCEMAP if is_map else ResourceType.SCRIPT,
                local_path=str(path.resolve()), content_type=_content_type(path),
                size=len(body.encode("utf-8", "replace")),
            ))

            if is_map:
                recovered = parse_source_map(body)
                if not recovered:
                    local.skipped.append(f"{path}（不是可解析的 source map）")
                for source_file in recovered:
                    if not source_file.name:
                        continue
                    content = source_file.content
                    if is_third_party_bundle(content) and \
                            config.scope.skip_library_bundles:
                        continue
                    _absorb(result, engine, config, pseudo + "#" + source_file.name,
                            content, finding_keys, param_keys, endpoint_keys,
                            base_paths, hints, local, resolved=True,
                            base=file_origin)
                continue

            if is_html:
                parsed = parse_html(pseudo, body)
                for tech in parsed.technologies:
                    if tech not in result.technologies:
                        result.technologies.append(tech)
                for candidate in parsed.candidates:
                    _add_candidate(result, candidate, pseudo, file_origin,
                                   endpoint_keys)
                for inline in parsed.inline_scripts:
                    _absorb(result, engine, config, f"{pseudo}#inline", inline,
                            finding_keys, param_keys, endpoint_keys, base_paths,
                            hints, local, resolved=False, base=file_origin)
                for tech in parsed.technologies:
                    pass

            _absorb(result, engine, config, pseudo, body, finding_keys, param_keys,
                    endpoint_keys, base_paths, hints, local, resolved=is_map,
                    base=file_origin)

            # An inline or sibling source map may restore readable sources.
            inline_map, reference = source_map_reference(body)
            if inline_map:
                for source_file in parse_source_map(inline_map):
                    if source_file.name and not is_third_party_bundle(source_file.content):
                        _absorb(result, engine, config,
                                pseudo + "#" + source_file.name,
                                source_file.content, finding_keys, param_keys,
                                endpoint_keys, base_paths, hints, local, resolved=True,
                                base=file_origin)
            elif reference:
                sibling = path.parent / reference
                if sibling.is_file() and sibling.suffix.lower() == ".map":
                    saved.append(Resource(
                        url=_pseudo_url(sibling, base),
                        type=ResourceType.SOURCEMAP,
                        local_path=str(sibling.resolve()),
                    ))
                    for source_file in parse_source_map(
                            sibling.read_text(encoding="utf-8", errors="replace")):
                        if source_file.name and \
                                not is_third_party_bundle(source_file.content):
                            _absorb(result, engine, config,
                                    pseudo + "#" + source_file.name,
                                    source_file.content, finding_keys, param_keys,
                                    endpoint_keys, base_paths, hints, local,
                                    base=file_origin,
                                    resolved=True)

        except Exception as exc:  # noqa: BLE001 - one bad file is not fatal
            import traceback as _tb
            local.skipped.append(
                f"{path}（解析失败：{type(exc).__name__}: {exc}）")
            result.issues.append(_issue(
                "file_analysis_failed",
                f"{path}：{type(exc).__name__}: {exc}；"
                f"{_tb.format_exc(limit=4).strip()[:400]}"))
            continue
    result.resources.extend(saved)
    result.hints = hints
    result.issues.append(_issue(
        "local_analysis",
        f"离线分析了 {len(saved)} 个本地文件；未发起任何网络请求。"
        + (f" base_url={base}" if base_url.strip() else ""),
    ))
    result.statistics = _statistics(result, saved)
    result.finished_at = result.started_at
    result.hosts = sorted(local.hosts.values(),
                           key=lambda a: a.value)
    return local


def _absorb(result: Result, engine: Engine, config: Config, pseudo_url: str,
            body: str, finding_keys: set, param_keys: set,
            endpoint_keys: set, base_paths: list, hints: list,
            local: LocalResult, resolved: bool, base: str = "") -> None:
    """Run every extractor over one body and merge the outcome.

    A body past the chunk limit is cut on line boundaries and fed through the
    extractors a piece at a time. The pieces share the caller's seen-sets, so
    what comes out is merged and deduplicated exactly as if the whole body had
    been analyzed in one go — just without the minutes of CPU that one go costs
    on a 23 MB bundle. Line numbers survive the cut: each piece is padded with
    the newlines before it.
    """
    if is_rejected(body):
        local.skipped.append(
            f"{pseudo_url}（文件过大：{body_bytes(body)} 字节 > "
            f"{REJECT_MAX_BYTES}，请切出感兴趣区域后分块分析）")
        return
    vendor = is_third_party_bundle(body)
    skip = vendor and config.scope.skip_library_bundles
    ast = wants_ast(body)
    if not ast and not skip:
        hints.append(
            f"{pseudo_url} 超过 {AST_MAX_BYTES} 字节，已跳过 AST 解析，"
            "仅做正则提取。")

    joined = joined_prefixes(body)
    values = prefix_values(body) if joined else {}
    for piece in split_by_lines(body):
        _absorb_piece(result, engine, config, pseudo_url, piece, ast, skip,
                      vendor, finding_keys, param_keys, endpoint_keys,
                      base_paths, hints, local, resolved, base, joined, values)


def _absorb_piece(result: Result, engine: Engine, config: Config,
                  pseudo_url: str, body: str, ast: bool, skip: bool,
                  vendor: bool, finding_keys: set, param_keys: set,
                  endpoint_keys: set, base_paths: list, hints: list,
                  local: LocalResult, resolved: bool, base: str,
                  joined: dict | None = None, values: dict | None = None) -> None:
    """One piece of one body: the extractors themselves, unchunked."""
    regex_result = from_javascript(pseudo_url, body, engine)
    _merge_findings(result, regex_result.findings, finding_keys, vendor)
    # Hosts were never collected offline: _statistics reported hosts=0
    # regardless of what the code named, so a bundle hardcoding a
    # hostname reported no hosts at all.
    for host in getattr(regex_result, "hosts", None) or []:
        _merge_host(local.hosts, host, config, vendor)
    # The regex URL rules' candidates were computed and then thrown
    # away: only the AST pass's candidates reached the endpoint table,
    # so ce("/checkToken") and url:D.a+"/downloadList" were extracted
    # and dropped. Whatever a tester could see depended entirely on the
    # AST understanding the file.
    for candidate in getattr(regex_result, "candidates", None) or []:
        _add_candidate(result, candidate, pseudo_url, base,
                       endpoint_keys, joined, values)
    if not skip:
        _merge_params(result, regex_result.params, param_keys, vendor)
        base_paths.extend(base_path_names(regex_result.base_paths))

    if not skip and ast:
        for candidate in analyze_js(pseudo_url, body).candidates:
            _add_candidate(result, candidate, pseudo_url, base, endpoint_keys, joined, values)
        limit = config.limits.max_resources or 20_000
        candidates = from_webpack(pseudo_url, body, limit)
        candidates += from_requirejs(pseudo_url, body, limit)
        dynamic, found = from_dynamic(pseudo_url, body, limit=500)
        candidates += dynamic
        for text in found:
            if text not in hints:
                hints.append(text)
        for candidate in candidates:
            candidate.vendor = vendor
            _add_candidate(result, candidate, pseudo_url, base, endpoint_keys, joined, values)
        if ast:
            _merge_params(result, params_from_ast(pseudo_url, body), param_keys,
                          vendor)

        # Non-HTTP transports and the route table sit outside every call shape
        # the passes above understand. Without them the offline path reports
        # "nothing found" where the online path would report a lot.
        # from_protocols' own default (200) is the bound here; the online path
        # uses the same number, and a private constant is not worth importing.
        protocol_candidates, operations, protocol_hints = from_protocols(
            pseudo_url, body)
        candidates = list(protocol_candidates)
        for route in routes_from_source(pseudo_url, body):
            candidates.append(Candidate(
                raw=route.path, kind=Kind.ROUTE, source_url=pseudo_url,
                source="regex", rule_id="router.config",
            ))
        for candidate in candidates:
            candidate.vendor = vendor
            _add_candidate(result, candidate, pseudo_url, base, endpoint_keys, joined, values)
        for operation in operations:
            entry = operation.to_dict()
            key = (entry["kind"], entry["name"], tuple(entry["fields"]))
            if key not in local.graphql_keys:
                local.graphql_keys.add(key)
                result.graphql.append(entry)
        for text in protocol_hints:
            if text not in hints:
                hints.append(text)

    if config.scope.probe_source_maps and not resolved:
        pass
    _ = is_javascript_path


def _merge_findings(result: Result, findings, seen: set, vendor: bool) -> None:
    for finding in findings:
        key = (finding.rule_id, finding.value, finding.source_url, finding.line)
        if key in seen:
            continue
        seen.add(key)
        finding.vendor = vendor
        result.findings.append(finding)


def _merge_params(result: Result, hits, seen: set, vendor: bool) -> None:
    for hit in hits:
        key = (hit.name, hit.scenario, hit.source_url, hit.line)
        if not hit.name or key in seen:
            continue
        seen.add(key)
        hit.vendor = vendor
        result.params.append(hit)


#: Hosts that can never be a real authorization target. ``.invalid`` and
#: ``.test`` are reserved by RFC 2606 precisely to mean "not a real name", and
#: ``localhost`` names this machine. Offline analysis has to synthesise a base
#: so relative references resolve somewhere; treating that placeholder as an
#: authorization grant would mark endpoints in scope on the strength of a host
#: nobody ever named.
_NON_AUTHORIZABLE = ("invalid", "test", "localhost", "local")


_MAX_HOST_EVIDENCE = 20


def _merge_host(hosts: dict, candidate, config, vendor: bool) -> None:
    """Fold one host observation into the running set."""
    raw = (getattr(candidate, "raw", "") or "").strip().lower().rstrip(".")
    if not raw:
        return
    asset = hosts.get(raw)
    if asset is None:
        from .discover.hosts import classify as classify_host
        from .model import HostAsset

        info = classify_host(raw, tuple(config.hosts.internal_suffixes))
        asset = HostAsset(
            value=raw,
            kind=info["kind"],
            origin="js",
            attributes=list(info.get("attributes") or []),
            vendor=vendor,
        )
        hosts[raw] = asset
    asset.occurrences += 1
    if len(asset.sources) < _MAX_HOST_EVIDENCE:
        asset.sources.append(candidate.to_evidence())



def _in_scope(url: str, base: str) -> bool:
    """Whether this URL belongs to an origin the caller actually named.

    Host only, not scheme: a tester who names ``example.com`` means the
    asset's endpoints, whether the code referenced them over http or https.
    Ports are compared because ``:8080`` is a different origin in every sense
    that matters here.
    """
    if not base:
        return False
    host = urlparse(url)
    origin = urlparse(base if "://" in base else "http://" + base)
    name = (origin.hostname or "").lower()
    if not name or name in _NON_AUTHORIZABLE:
        return False
    if any(name == item or name.endswith("." + item)
           for item in _NON_AUTHORIZABLE):
        return False
    if host.hostname != name:
        return False
    return host.port == origin.port


def _add_candidate(result: Result, candidate, source_url: str,
                   base: str | None, endpoint_keys: set,
                   joined: dict | None = None, values: dict | None = None) -> None:
    """Normalize one candidate into an endpoint or route."""
    raw = (candidate.raw or "").strip()
    if not raw or raw.startswith(("data:", "javascript:", "blob:", "about:", "#")):
        return
    if "://" in raw:
        url = raw
    else:
        url = resolve_url(source_url, raw) or urljoin_safe(source_url, raw)
    if not url:
        return

    # Only the route extractor produces routes. A SCRIPT/CHUNK/SOURCEMAP
    # candidate is a code reference -- import("./views/Home.js") is the lazy
    # chunk behind a route, not a route itself -- and filing it here made
    # /views/Home.js show up in the route table next to /home.
    is_route = candidate.kind == Kind.ROUTE
    # A WebSocket URL is a finding, but not an HTTP interface. Filing it as
    # "api" would hand the model a GET to send and a meaningless status to
    # read as "exists" or "not_found".
    is_socket = (urlparse(raw).scheme or "").lower() in _NON_HTTP_SCHEMES
    if not is_route:
        # Webpack module keys (/PVX) and build paths (/home/jenkins/...) are
        # not interfaces. The build paths are reported by the 构建信息 rules
        # instead, so dropping them here loses no signal.
        # Webpack module keys (/PVX), URL-parser fixtures (/a/b) and build
        # paths (/home/jenkins/...) are not interfaces. Routes and sockets
        # pass through: a route is a page and a socket is a handshake, and
        # the build paths are reported by the 构建信息 rules instead.
        if not is_route and not is_socket:
            if (not looks_like_api_path(raw)
                    or is_filesystem_path(raw)
                    or is_static_asset_path(raw)):
                return
    kind = "route" if is_route else ("socket" if is_socket else "api")
    key = f"{kind}\x00{url}"
    if key in endpoint_keys:
        return
    endpoint_keys.add(key)

    spec = candidate.spec or RequestSpec()
    for prefix in base_paths_of(spec):
        if join_base_url(prefix, raw):
            spec.base_url = prefix
            spec.base_url_kind = "prefix"
            break

    resolved, unresolved = "", False
    if joined and raw in joined:
        resolved, unresolved = resolve_joined(raw, joined, values or {})
    endpoint = Endpoint(
        raw=raw,
        url=url,
        source_url=candidate.source_url or source_url,
        # Offline there is no scan root to authorize against, but the
        # caller can name one: when base_url is given, endpoints on that
        # origin are in scope by assertion, and everything else stays
        # unauthorized. Marking everything false regardless made the
        # column useless exactly when a tester had told us the origin.
        authorized=_in_scope(url, base),
        method=candidate.method,
        evidence=candidate.evidence or EVIDENCE_STATIC,
        source=candidate.source or "regex",
        type=kind,
        line=candidate.line,
        column=candidate.column,
        context_lines=candidate.context_lines,
        body_params=candidate.body_params or spec.param_keys(),
        spec=spec if (spec.query or spec.body) else None,
        vendor=candidate.vendor,
        resolved=resolved,
        unresolved_prefix=unresolved,
    )
    # A socket has no HTTP request to reconstruct; a wss:// request line is
    # worse than no template at all.
    if not is_socket:
        endpoint.template = build_template(endpoint)
    result.endpoints.append(endpoint)


def base_paths_of(spec: RequestSpec) -> list[str]:
    return [spec.base_url] if getattr(spec, "base_url", "") else []


def urljoin_safe(base: str, raw: str) -> str:
    from urllib.parse import urljoin

    try:
        return urljoin(base, raw)
    except ValueError:
        return ""


def _pseudo_url(path: Path, base: str) -> str:
    """A stable synthetic URL for a local file, used as the resolution base."""
    return resolve_url(base, path.name) or (base + path.name)


def _content_type(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".map":
        return "application/json"
    if suffix in (".html", ".htm"):
        return "text/html"
    if suffix == ".json":
        return "application/json"
    return "application/javascript"


def _issue(code: str, message: str):
    from .model import Issue

    return Issue(code=code, stage="local", message=message)


def _statistics(result: Result, saved: list[Resource]):
    from .model import Statistics

    return Statistics(
        resources=len(saved),
        scripts=sum(1 for r in saved if r.type is ResourceType.SCRIPT),
        chunks=0,
        endpoints=len(result.endpoints),
        findings=len(result.findings),
        routes=len([e for e in result.endpoints if e.type == "route"]),
        hosts=len(result.hosts),
        parameters=len({hit.name for hit in result.params if hit.name}),
        banners=0,
    )


_UNUSED = (offline_response, InlineItem, Finding, Param, ParamHit, render_body,
           route_param_names, re)
