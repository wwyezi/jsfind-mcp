"""Collection and extraction pipeline for one target.

Flow, per target:

1. fetch the entry document and parse its scripts, inline code and SPA signals;
2. walk a bounded queue — every fetched script is run through **both** engines
   (regex and Tree-sitter AST), then through the webpack / RequireJS chunk
   extractors, then through source-map recovery;
3. normalize every candidate into an endpoint, route or resource, resolving
   relative paths against the script that mentioned them;
4. probe in-scope endpoints to record status codes and response field names.

Every cap is configurable and concurrency is bounded per target and across
targets, so a scan against a large SPA terminates predictably instead of
dragging on. Only GET is ever sent: the collection phase stays read-only.
"""

from __future__ import annotations

import asyncio
import codecs
import functools
import hashlib
import math
import queue
import re
import threading
import time
from concurrent.futures import Executor, Future
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlencode, urljoin, urlparse

from .analyze import Engine, ResourceRef
from .banner import BannerEngine
from .chunking import (
    AST_MAX_BYTES,
    REJECT_MAX_BYTES,
    body_bytes,
    PIECE_OVERLAP,
    PieceCutter,
    is_rejected,
    split_by_lines,
    wants_ast,
)
from .collect import Client, Response, offline_response
from .config import Config
from .discover import (
    DEFAULT_ROUTE_BUDGET,
    MANIFEST_PATHS,
    SPEC_PATHS,
    Kind,
    Route,
    analyze_js,
    base_path_names,
    collect_routes,
    joined_prefixes,
    prefix_values,
    resolve_joined,
    find_manifest_references,
    find_spec_references,
    from_dynamic,
    from_javascript,
    from_protocols,
    from_requirejs,
    from_webpack,
    is_third_party_bundle,
    json_field_names,
    params_from_ast,
    parse_html,
    parse_manifest,
    parse_source_map,
    parse_spec,
    renderable_paths,
    routes_from_source,
    source_map_reference,
)
from .discover.hosts import HostCandidate
from .discover.hosts import classify as classify_host
from .discover.hosts import host_from_url
from .discover.types import Candidate
from .model import (
    EVIDENCE_FULL_URL,
    EVIDENCE_RUNTIME,
    EVIDENCE_SPEC,
    EVIDENCE_STATIC,
    classify_status,
    Banner,
    Endpoint,
    HeaderTpl,
    HostAsset,
    HostEvidence,
    Issue,
    Param,
    RequestSpec,
    RequestTemplate,
    Resource,
    ResourceType,
    Result,
    route_param_names,
    severity_rank,
)
from .scope import Scope
from .scheduler import Queue
from .utils import is_filesystem_path, is_javascript_path, is_static_asset_path, join_base_url, line_column, looks_like_api_path, looks_like_path, normalize_url, resolve_url

# Prefixes declared by the code; relative endpoints inherit them.
_MAX_BASE_PATHS = 8
_MAX_INLINE_SCRIPTS = 50
_MAX_HOST_EVIDENCE = 20
# Response field names are capped so one huge payload cannot flood a result.
_MAX_RESPONSE_FIELDS = 80

#: Banner categories in reporting order: what the target itself runs matters
#: more than what sits in front of it, and a database far more than a CDN.
#: How many manifest / spec locations one scan will try. The lists are
#: conventional and short; an unbounded wordlist against a target is not
#: something this tool should do.
_MAX_MANIFEST_PROBES = 12
_MAX_SPEC_PROBES = 12
#: Wall clock for one probe request. A well-known path that answers and then
#: never finishes (no Content-Length, connection held open) would otherwise
#: cost the full read-gap timeout per attempt — a dozen guesses at that price
#: silently eat a whole scan budget.
_PROBE_TIMEOUT = 6.0
#: Cap on operations expanded from one specification document.
_MAX_SPEC_OPERATIONS = 300
#: An extractor crash is reported, not swallowed, but a pathological target
#: should not be able to fill the result with thousands of identical issues.
_MAX_COLLECTION_ISSUES = 20
#: The protocol pass is regex-driven over whole bundles, so a single large file
#: can surface thousands of socket URLs. It contributes leads, not the endpoint
#: inventory, so it gets its own small budget instead of the resource cap.
_MAX_PROTOCOL_CANDIDATES = 200
#: Schemes the HTTP client cannot speak. A WebSocket handshake is a real thing
#: to test, but a GET to it is not, so these are reported as ``type="socket"``
#: and never enter the probe queue.
_NON_HTTP_SCHEMES = frozenset({"ws", "wss"})
#: Wall-clock budget for the drain that follows an expansion pass. The chunks
#: and view scripts these passes uncover are one layer down from what the first
#: pass already found, so they should not get a second full target timeout.
_EXPANSION_BUDGET = 120.0


class SerialWorker(Executor):
    """One daemon thread that runs submitted callables, one at a time.

    A plain :class:`ThreadPoolExecutor` is the wrong shape here twice over: its
    threads are non-daemon and the interpreter joins them at exit, so a scan
    still extracting when the client closes stdin keeps the process alive as an
    orphan — which is what a pile of half-dead ``jsfind-mcp.exe`` instances
    looks like from the outside. A daemon thread dies with the process, and a
    single worker keeps extraction strictly sequential so the shared result is
    mutated by one thread at a time, exactly as when it ran inline.
    """

    def __init__(self, name: str = "jsfind-extract"):
        self._jobs: queue.SimpleQueue = queue.SimpleQueue()
        self._thread = threading.Thread(target=self._run, name=name, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while True:
            job = self._jobs.get()
            if job is None:
                return
            fn, args, kwargs, future = job
            if future.set_running_or_notify_cancel():
                try:
                    future.set_result(fn(*args, **kwargs))
                except BaseException as exc:  # noqa: BLE001 - carried to the awaiter
                    future.set_exception(exc)

    def submit(self, fn, /, *args, **kwargs) -> Future:
        future = Future()
        self._jobs.put((fn, args, kwargs, future))
        return future

    def shutdown(self, wait: bool = True, *, cancel_futures: bool = False) -> None:
        self._jobs.put(None)
        if wait:
            self._thread.join(timeout=1.0)


class Budget:
    """The wall-clock budget one whole scan has to finish in.

    ``target_timeout`` used to bound only the first queue drain: manifest
    probing, route rendering, spec probing and endpoint probing then ran with no
    ceiling at all. Against a real target that adds up to far longer than an
    MCP client waits before it gives up and closes the stdio pipe -- which takes
    the server process, and with it the in-memory result, down with no error
    anywhere. One deadline now covers every phase, and each phase spends what is
    left of it or stops early and says so.

    Zero means unlimited, matching how the other configured limits read.
    """

    def __init__(self, seconds: float):
        self._unlimited = not seconds or seconds <= 0
        self._start = time.monotonic()
        self._deadline = self._start + seconds if not self._unlimited else math.inf

    def left(self) -> float:
        """Seconds still available. ``inf`` when no limit was configured."""
        if self._unlimited:
            return math.inf
        return max(0.0, self._deadline - time.monotonic())

    def expired(self) -> bool:
        return self.left() <= 0

    def timeout(self) -> float | None:
        """``left()`` in the form ``asyncio.wait_for`` takes it: None means wait."""
        return None if self._unlimited else self.left()

    def elapsed(self) -> float:
        return time.monotonic() - self._start

_CATEGORY_ORDER = {
    "app_server": 0,
    "language": 1,
    "web_server": 2,
    "framework": 3,
    "gateway": 4,
    "db": 5,
    "cdn": 6,
}


@dataclass
class InlineItem:
    """Stand-in queue item for content that was never fetched."""

    url: str = ""
    depth: int = 0
    source_url: str = ""
    kind: str = Kind.SCRIPT

    def __post_init__(self) -> None:
        if not self.source_url:
            self.source_url = self.url



class _OverflowExtractor:
    """Sliding-window extraction over the part of a body past the cap.

    A 20 MB bundle capped at 10 MB used to lose every interface in its back
    half. This consumer is handed each streamed byte as it arrives, keeps a
    rolling window cut like :func:`split_by_lines`, and runs the same passes
    ``_extract_piece`` runs — minus the AST — over each completed piece. The
    window starts a little before the cap (``PIECE_OVERLAP``) so a match
    straddling the cut is seen whole by one piece; the merge sets collapse the
    double hit against the prefix pass.

    Line numbers stay absolute: the window's line counter is seeded with the
    newlines of the retained prefix. The vendor decision comes from the same
    head region ``is_third_party_bundle`` reads in the batch path, so a
    library bundle is skipped here exactly as it is there.
    """

    #: Head bytes kept for the vendor decision; matches the license scanner.
    _SNIFF_BYTES = 200_000

    def __init__(self, pipeline: "Pipeline", item, scope, queue, result,
                 cap: int):
        self._pipeline = pipeline
        self._item = item
        self._source_url = item.url
        self._scope = scope
        self._queue = queue
        self._result = result
        self._start = max(0, cap - PIECE_OVERLAP)
        self._pos = 0
        self._decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self._head = ""
        self._head_lines = 0
        self._cutter: PieceCutter | None = None
        self._overflow_seen = False
        self._tail = ""

    async def feed(self, data: bytes) -> None:
        start, end = self._pos, self._pos + len(data)
        self._pos = end
        if end <= self._start:
            self._note_head(self._decoder.decode(data))
            return
        if start < self._start:
            self._note_head(
                self._decoder.decode(data[: self._start - start]))
            data = data[self._start - start:]
        if self._cutter is None:
            self._begin_window()
        text = self._decoder.decode(data)
        if text:
            self._overflow_seen = True
            self._tail = (self._tail + text)[-4096:]
            for piece in self._cutter.feed(text):
                await self._extract(piece)

    def _note_head(self, text: str) -> None:
        if not text:
            return
        self._head_lines += text.count("\n")
        if len(self._head) < self._SNIFF_BYTES:
            self._head += text[: self._SNIFF_BYTES - len(self._head)]

    def _begin_window(self) -> None:
        vendor = is_third_party_bundle(self._head)
        skip = bool(vendor and
                    self._pipeline.config.scope.skip_library_bundles)
        self._cutter = PieceCutter(initial_lines=self._head_lines)
        self._vendor = vendor
        self._skip = skip

    async def _extract(self, piece: str) -> None:
        await self._pipeline._offload(
            self._pipeline._extract_overflow_piece,
            self._source_url, piece, self._vendor, self._skip, self._item,
            self._scope, self._queue, self._result)

    async def finish(self, response: Response) -> None:
        if self._cutter is not None:
            for piece in self._cutter.flush():
                await self._extract(piece)
        # The sourceMappingURL comment sits at the very end of a bundle —
        # in the overflow region of a truncated download. Re-checking the
        # tail here is what keeps source map recovery alive past the cap.
        if (self._overflow_seen and self._tail
                and self._pipeline.config.scope.probe_source_maps):
            await self._pipeline._offload(
                self._pipeline._absorb_map_reference, self._item, self._tail,
                self._result, self._queue)


class Pipeline:
    """Runs one target end to end against a shared client and engine."""

    def __init__(self, config: Config, engine: Engine,
                 banners: BannerEngine | None = None):
        self.config = config
        self.engine = engine
        self.banners = banners if banners is not None else \
            BannerEngine.default(rules_file=config.banners_file)
        self._findings_seen: set[tuple] = set()
        self._failure_keys: set[tuple] = set()
        self._endpoint_keys: set[str] = set()
        self._params_seen: set[tuple] = set()
        self._hosts: dict[str, HostAsset] = {}
        self._scan_hosts: dict[str, HostAsset] = {}
        self._banners: list[Banner] = []
        self._banner_keys: set[tuple] = set()
        #: manifest / spec locations seen in documents, tried before guesses
        self._manifest_refs: set[str] = set()
        self._spec_refs: set[str] = set()
        #: candidates from the most recently parsed document, so a crawled
        #: route can be credited with the scripts it alone pulled in
        self._last_route_candidates: list = []
        #: GraphQL operation documents, keyed by kind+name+field set
        self._graphql: dict[tuple, dict] = {}
        #: dynamic code that exists but has no single resolvable file, e.g. a
        #: glob family; surfaced so a consumer knows it is not seeing everything
        self._hints: list[str] = []
        #: how many originals a source map restored, reported for transparency
        self._recovered_count = 0
        self._base_paths: list[str] = []
        #: script bodies keyed by URL, so a candidate's byte offset can
        #: be turned into a line number without re-reading the file
        self._source_cache: dict[str, str] = {}
        self._js_dir: Path | None = None
        self._entry: Response | None = None
        #: Set per run, so every phase draws from the same clock. Unlimited by
        #: default so a phase reached outside run() is never cut short by a
        #: budget that was never configured.
        self._budget = Budget(0.0)
        #: One worker for the extraction passes. Regex and Tree-sitter over a
        #: whole bundle are seconds of synchronous CPU each, and running them
        #: inline starves the event loop — which serves every other MCP request,
        #: including ``tools/list``. A single thread keeps the passes strictly
        #: sequential, so they mutate shared state exactly as they did when they
        #: ran inline; the loop is just no longer hostage to them. Daemon, so a
        #: scan still running at exit cannot hold the process open.
        self._worker = SerialWorker()

    def close(self) -> None:
        self._worker.shutdown(wait=False)

    async def _offload(self, fn, *args, **kwargs):
        """Run one extraction pass on the worker thread.

        Every caller of this holds no lock and touches ``result`` only after
        the await returns, so the sequential single worker is enough to keep
        the shared state as safe as it was when the pass ran inline.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._worker, functools.partial(fn, *args, **kwargs))

    # -- entry point ----------------------------------------------------

    async def run(self, target, result: Result, scope: Scope) -> None:
        """Collect and extract everything reachable from one target."""
        root_url = normalize_url(target.url)
        self._js_dir, js_problem = self._js_directory(root_url)
        result.js_dir = str(self._js_dir) if self._js_dir else ""
        if js_problem:
            result.issues.append(Issue(
                code="js_dir_unwritable", stage="setup", url=root_url,
                message=js_problem,
            ))
            result.hints.append(
                "本次未落盘任何脚本：js_dir 不可用。"
                "需要脚本内容时，在 jsfind_scan 传入可写的 js_dir。")
            # Recorded on self._hints, which is what run() publishes at the end.
            # Appending to result.hints here would be discarded by that assignment.
            self._hints.append(
                "本次未落盘任何脚本：js_dir 不可用，"
                "jsfind_js_files / jsfind_js_search 将无结果。")

        queue = Queue(max_depth=self.config.limits.max_depth,
                      max_items=self.config.limits.max_resources)
        queue.seed(root_url, Kind.SCRIPT, source_url=root_url)

        client = Client(self.config, getattr(target, "headers", None),
                        getattr(target, "cookies", None))
        self._budget = Budget(self.config.request.target_timeout)
        async with client:
            try:
                await asyncio.wait_for(
                    self._drain(queue, client, scope, result, root_url),
                    timeout=self._budget.timeout(),
                )
            except asyncio.TimeoutError:
                pass
            # Every later phase shares what is left of the same deadline, and
            # skips itself entirely once it is gone: either something ran out
            # here, or there was nothing left worth waiting for.
            if not self._budget.expired():
                await self._expand_manifests(client, scope, result, queue, root_url)
            if not self._budget.expired():
                await self._settle(queue, client, scope, result, root_url)
            if not self._budget.expired():
                await self._crawl_routes(client, scope, result, root_url)
            if not self._budget.expired():
                await self._expand_openapi(client, scope, result, root_url)
            if not self._budget.expired():
                await self._probe_endpoints(client, scope, result)
            if self._budget.expired():
                self._budget_note(result, root_url)

        self._publish_hosts(result)
        result.graphql = list(self._graphql.values())
        result.banners = self._sorted_banners()
        result.hints = list(self._hints)
        if self._recovered_count:
            result.hints.insert(0, f"source map 还原出 {self._recovered_count} "
                                    f"个原始源码文件，已保存并可检索。")

    def _budget_note(self, result: Result, root_url: str) -> None:
        """Say plainly that this scan stopped early, once.

        A partial scan looks exactly like a small site if nobody says otherwise,
        and "no endpoints here" is the wrong thing for a model to conclude from
        a run that ran out of time before looking.
        """
        if any(issue.code == "target_timeout" for issue in result.issues):
            return
        limit = self.config.request.target_timeout
        result.issues.append(Issue(
            code="target_timeout", stage="collect", url=root_url,
            message=f"达到单目标超时 {limit:.0f}s（耗时 "
                    f"{self._budget.elapsed():.0f}s），已停止后续阶段并"
                    "返回已获得的结果。要扫得更完整，用 jsfind_scan 的 "
                    "timeout_seconds 提高预算，或关掉 crawl_routes / "
                    "probe_endpoints 减少请求数。",
        ))

    # -- queue ----------------------------------------------------------

    async def _drain(self, queue: Queue, client: Client, scope: Scope,
                     result: Result, root_url: str) -> None:
        """Fetch queued resources concurrently, bounded by the config."""
        limit = self.config.concurrency_limit
        semaphore = asyncio.Semaphore(limit)
        window = max(limit * 4, 8)
        tasks: list[asyncio.Task] = []

        while True:
            item = queue.pop()
            if item is None:
                if not tasks:
                    break
                # The queue looks empty only because the in-flight script
                # fetches have not pushed their own children yet. Drain them
                # and look again, or the whole chunk layer is silently lost.
                await self._gather(tasks, result)
                tasks = []
                continue
            if item.url == root_url:
                await self._fetch_entry(item, client, scope, result, queue)
                continue
            if not scope.can_fetch(item.url):
                continue
            tasks.append(asyncio.ensure_future(
                self._fetch_one(item, client, scope, queue, result, semaphore)
            ))
            # Cap the in-flight window so a 500-resource site does not open 500
            # sockets at once.
            if len(tasks) >= window:
                await self._gather(tasks, result)
                tasks = []
        if tasks:
            await self._gather(tasks, result)

    async def _gather(self, tasks: list, result: Result) -> None:
        """Wait for a batch of fetches, recording anything that blew up.

        ``return_exceptions=True`` alone is a trap: one extractor's TypeError
        would discard that script's entire result set, and the scan would
        report success having analyzed nothing. Every non-cancellation failure
        becomes an issue so the loss is visible.
        """
        for outcome in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(outcome, asyncio.CancelledError):
                continue
            if isinstance(outcome, BaseException):
                self._record_analyzer_failure(outcome, result)

    def _record_analyzer_failure(self, error: BaseException,
                                 result: Result) -> None:
        if len(result.issues) >= _MAX_COLLECTION_ISSUES:
            return
        key = (type(error).__name__, str(error)[:120])
        if key in self._failure_keys:
            return
        self._failure_keys.add(key)
        result.issues.append(Issue(
            code="extractor_failed", stage="analyze", url="",
            message=f"{type(error).__name__}: {error}；"
                    "该资源的提取结果可能不完整。",
        ))

    async def _fetch_entry(self, item, client: Client, scope: Scope,
                           result: Result, queue: Queue) -> None:
        extractor = self._overflow_consumer(item, scope, queue, result)
        response = await client.get(
            item.url, allow_redirect=scope.can_fetch,
            on_chunk=extractor.feed if extractor else None)
        if extractor is not None:
            await extractor.finish(response)
        await self._offload(self._absorb_entry, item, response, scope,
                            result, queue)

    def _absorb_entry(self, item, response: Response, scope: Scope,
                      result: Result, queue: Queue) -> None:
        self._entry = response
        if response.error:
            result.issues.append(Issue(
                code="entry_fetch_failed", stage="collect", url=item.url,
                message=response.error, retryable=True,
            ))
            return
        self._note_truncation(item.url, response, result)
        result.resources.append(Resource(
            url=item.url, type=ResourceType.DOCUMENT,
            status_code=response.status_code, content_type=response.content_type,
            size=response.size, depth=0, final_url=response.final_url,
        ))
        self._record_scan_host(item.url)
        self._absorb_banner(response)
        if response.is_script():
            self._absorb_script(InlineItem(url=item.url), response,
                                self._decode(response), queue, scope, result)
        else:
            self._absorb_document(item.url, response, queue, scope, result)

    async def _fetch_one(self, item, client: Client, scope: Scope,
                         queue: Queue, result: Result,
                         semaphore: asyncio.Semaphore) -> None:
        extractor = self._overflow_consumer(item, scope, queue, result)
        async with semaphore:
            response = await client.get(
                item.url, allow_redirect=scope.can_fetch,
                on_chunk=extractor.feed if extractor else None)
        if extractor is not None:
            await extractor.finish(response)
        await self._offload(self._absorb_one, item, response, scope, queue,
                            result)

    def _absorb_one(self, item, response: Response, scope: Scope,
                    queue: Queue, result: Result) -> None:
        # Everything from here on touches the shared result, the queue and the
        # pipeline's own seen-sets. It runs as one unit on the single worker so
        # that stays strictly sequential, exactly as it was when this all ran
        # inline on the event loop — only the network I/O is left there.
        if response.error:
            result.issues.append(Issue(
                code="fetch_failed", stage="collect", url=item.url,
                message=response.error, retryable=True,
            ))
            return

        self._note_truncation(item.url, response, result)
        self._absorb_banner(response)

        if response.is_source_map():
            self._absorb_map(item, response, result)
            return

        if not response.ok or not response.is_textual():
            # A 404 or a binary body still records that the reference exists
            # and was tried; there is simply nothing to analyze.
            result.resources.append(Resource(
                url=item.url, type=self._resource_type(item.kind),
                source_url=item.source_url, status_code=response.status_code,
                content_type=response.content_type, size=response.size,
                depth=item.depth,
            ))
            return

        body = self._decode(response)
        result.resources.append(Resource(
            url=item.url, type=self._resource_type(item.kind),
            source_url=item.source_url, status_code=response.status_code,
            content_type=response.content_type, size=response.size,
            depth=item.depth,
            local_path=self._save_js(item.url, body) or "",
        ))
        self._record_scan_host(item.url, item.source_url)

        if response.is_script() or is_javascript_path(item.url):
            self._absorb_script(item, response, body, queue, scope, result)
        elif item.kind == Kind.SCRIPT:
            self._absorb_document(item.url, response, queue, scope, result)

    def _note_truncation(self, url: str, response: Response,
                         result: Result) -> None:
        """Record that a body was cut short by the response-size cap.

        The capped prefix is still analyzed and still saved, so the inventory
        stays useful; what must not happen is the caller mistaking a 10 MB
        prefix of a 20 MB bundle for the whole file. When the sliding-window
        extractor covered the overflow, say so — what the caller should do
        next depends on what the truncation actually cost.
        """
        if not response.truncated:
            return
        limit = max(0, int(self.config.request.max_response_bytes))
        kept = len(response.body)
        declared = (f"服务端声明 {response.declared_size} 字节"
                    if response.declared_size >= 0 else "服务端未声明长度")
        coverage = ("溢出部分已过滑动窗口正则提取，接口/密钥不受截断影响；"
                    if response.overflow_analyzed else
                    "接口与敏感信息仅覆盖保留的前缀。")
        if len(result.issues) < _MAX_COLLECTION_ISSUES:
            result.issues.append(Issue(
                code="response_truncated", stage="collect", url=url,
                message=(f"响应体超过 max_response_bytes={limit} 字节上限，"
                         f"保留前 {kept} 字节（全量 {response.size} 字节，"
                         f"{declared}）；" + coverage +
                         "AST 与全文检索只覆盖保留的前缀。"),
                retryable=False,
            ))
        if response.overflow_analyzed:
            hint = (f"{url} 响应超过 {limit} 字节上限被截断（保留前 {kept} 字节，"
                    f"全量 {response.size} 字节）；正则提取已覆盖全量。"
                    "AST/jsfind_js_search 只覆盖保留的前缀；需要对后半段做"
                    "AST 级分析时调高 max_response_bytes，或手工切片后用"
                    " jsfind_analyze_file。")
        else:
            hint = (f"{url} 响应超过 {limit} 字节上限被截断（保留前 {kept} 字节）；"
                    "需要完整内容时对感兴趣区域手工切片后用 jsfind_analyze_file 分析，"
                    "或单次调用 jsfind_scan 时调高 max_response_bytes。")
        if hint not in self._hints:
            self._hints.append(hint)

    # -- documents ------------------------------------------------------

    def _absorb_document(self, url: str, response: Response, queue: Queue,
                         scope: Scope, result: Result) -> None:
        """Parse an HTML document: scripts, inline code, framework signals."""
        body = self._decode(response)
        parsed = parse_html(url, body)
        for tech in parsed.technologies:
            if tech not in result.technologies:
                result.technologies.append(tech)
        if parsed.spa.any:
            result.spa.merge(parsed.spa)

        # Remember every manifest and spec reference the page mentions, so the
        # expansion passes try the real path before the well-known guesses.
        for candidate in find_manifest_references(url, body):
            self._manifest_refs.add(candidate.raw)
        for reference in find_spec_references(url, body):
            self._spec_refs.add(reference)
        self._last_route_candidates = parsed.candidates

        for candidate in parsed.candidates:
            self._route_resource(candidate, url, queue, scope, result)

        # A page's inline configuration leaks more than its markup does, so the
        # full rule set runs over the raw document too.
        analysis = self.engine.analyze(
            ResourceRef(url=url, type=ResourceType.DOCUMENT), body
        )
        for finding in analysis.findings:
            self._merge_finding(finding, result)
        for candidate in self._document_endpoints(url, analysis):
            self._route_resource(candidate, url, queue, scope, result)

        for index, code in enumerate(parsed.inline_scripts[:_MAX_INLINE_SCRIPTS]):
            pseudo = f"{url}#inline-{index}"
            synthetic = offline_response(pseudo, code, "application/javascript")
            self._absorb_script(InlineItem(url=pseudo), synthetic, code,
                                queue, scope, result)

    def _document_endpoints(self, url: str, analysis) -> list[Candidate]:
        """Route and API references declared in markup or inline scripts."""
        out: list[Candidate] = []
        for extracted in analysis.candidates:
            if extracted.hint not in ("route", "endpoint"):
                continue
            if not looks_like_path(extracted.raw) or \
                    is_static_asset_path(urlparse(extracted.raw).path):
                continue
            resolved = resolve_url(url, extracted.raw)
            if not resolved:
                continue
            out.append(Candidate(
                raw=resolved,
                kind=Kind.ROUTE if extracted.hint == "route" else Kind.ENDPOINT,
                source_url=url, source="html", method=extracted.method,
                rule_id=extracted.rule_id,
            ))
        return out

    def _route_resource(self, candidate: Candidate, source_url: str, queue: Queue,
                        scope: Scope, result: Result) -> None:
        """Send a candidate down the path its kind implies."""
        resolved = self._resolve_candidate(candidate, source_url)
        if resolved is None:
            return
        if candidate.offset and not candidate.line:
            # A candidate may arrive with only a byte offset; resolve it
            # once here so every finding can cite a line a reader can open.
            body = self._source_cache.get(source_url)
            if body:
                candidate.line, candidate.column = line_column(
                    body, candidate.offset)
        candidate.raw = resolved
        if candidate.kind in (Kind.SCRIPT, Kind.CHUNK, Kind.SOURCEMAP):
            if candidate.kind == Kind.SOURCEMAP and \
                    not scope.source_map_allowed(resolved):
                return
            queue.push(resolved, candidate.kind, source_url, depth=self._depth_of(source_url))
        elif candidate.kind == Kind.ENDPOINT:
            self._add_endpoint(candidate, scope, result)
        else:
            self._add_route(candidate, scope, result)

    @staticmethod
    def _depth_of(source_url: str) -> int:
        """Depth a child of ``source_url`` is queued at.

        Entry documents and inline code sit at depth 0, so their direct
        references are depth 1; a chunk discovered inside a script is one hop
        further, which keeps the resource cap meaningful.
        """
        return 1 if "#" in source_url or source_url.endswith((".html", ".htm")) else 2

    # -- scripts --------------------------------------------------------

    def _absorb_script(self, item, response: Response, body: str, queue: Queue,
                       scope: Scope, result: Result) -> None:
        """Run every extractor over one script body.

        A body past the chunk limit is cut on line boundaries and extracted a
        piece at a time. The pieces share this pipeline's seen-sets, so the
        merged outcome is the same as one whole-body pass would have produced,
        without the minutes of CPU that pass costs on a 23 MB bundle.
        """
        source_url = item.url
        self._source_cache[source_url] = body
        vendor = is_third_party_bundle(body)
        # Library bundles are large and hold none of the target's own
        # interfaces or secrets, so they are skipped unless the operator asked
        # for them (in which case their results are tagged vendor).
        skip = vendor and self.config.scope.skip_library_bundles

        if is_rejected(body):
            self._hints.append(
                f"{source_url} 体积 {body_bytes(body)} 字节超过 "
                f"{REJECT_MAX_BYTES} 上限，未做提取；请切出感兴趣区域后分析。")
            return

        findings: list = []
        params: list = []
        hosts: list = []
        base_paths: list = []
        candidates: list = []
        ast = wants_ast(body)
        if not ast and not skip:
            self._hints.append(
                f"{source_url} 超过 {AST_MAX_BYTES} 字节，跳过 AST 解析，"
                "仅做正则提取。")

        for piece in split_by_lines(body):
            self._extract_piece(source_url, piece, ast, skip, candidates,
                                findings, params, hosts, base_paths, result)

        joined = joined_prefixes(body)
        values = prefix_values(body) if joined else {}
        for candidate in candidates:
            if candidate.raw in joined:
                candidate.resolved, candidate.unresolved_prefix = \
                    resolve_joined(candidate.raw, joined, values)

        self._merge_extracted(source_url, vendor, candidates, findings,
                              params, hosts, base_paths, queue, scope, result)

        # 4. source maps: a leaked map restores the whole unminified front end.
        if self.config.scope.probe_source_maps:
            self._absorb_map_reference(item, body, result, queue)

    def _extract_piece(self, source_url: str, body: str, ast: bool,
                       skip: bool, candidates: list, findings: list,
                       params: list, hosts: list, base_paths: list,
                       result: Result) -> None:
        """The extraction passes themselves, run over one piece of one body."""
        # 1. regex pass — always runs; it is the only pass for libraries.
        regex_result = from_javascript(source_url, body, self.engine)
        findings.extend(regex_result.findings)
        if not skip:
            params.extend(regex_result.params)
            hosts.extend(regex_result.hosts)
            base_paths.extend(regex_result.base_paths)
            # The regex URL rules produce candidates too, and they were being
            # discarded here: every endpoint a caller saw came from the AST pass
            # alone, so a file the parser does not understand yielded nothing.
            candidates.extend(getattr(regex_result, "candidates", None) or [])
            if regex_result.spa.any:
                result.spa.merge(regex_result.spa)

        # 2. AST pass — API calls with methods, request shapes and base paths.
        if not skip and ast:
            ast_result = analyze_js(source_url, body,
                                    max_bytes=self.config.limits.max_ast_bytes)
            candidates.extend(ast_result.candidates)
            base_paths.extend(ast_result.base_paths)
            params.extend(params_from_ast(
                source_url, body, max_bytes=self.config.limits.max_ast_bytes
            ))

        # 3. chunk discovery: webpack/RequireJS runtimes plus the dynamic
        #    loading every modern bundler uses (import(), Vite chunk maps,
        #    web workers). This is where most of a large SPA actually lives.
        if not skip:
            limit = self._candidate_limit()
            candidates.extend(from_webpack(source_url, body, limit))
            candidates.extend(from_requirejs(source_url, body, limit))
            dynamic, hints = from_dynamic(source_url, body, limit=500)
            candidates.extend(dynamic)
            for text in hints:
                if text not in self._hints:
                    self._hints.append(text)

        # 4. router config arrays. A minified SPA's own route table is a plain
        #    array of object literals, which neither the API-call nor the chunk
        #    passes model; without this the route crawler has nothing to walk.
        if not skip:
            for route in routes_from_source(source_url, body):
                candidates.append(Candidate(
                    raw=route.path, kind=Kind.ROUTE, source_url=source_url,
                    source="regex", rule_id="router.config",
                ))

        # 5. transports that are not HTTP requests at all. WebSocket, SSE and
        #    GraphQL documents never appear in fetch()/axios call shapes, so
        #    without this pass they are invisible to the whole pipeline.
        if not skip:
            protocol_candidates, operations, protocol_hints = from_protocols(
                source_url, body, limit=_MAX_PROTOCOL_CANDIDATES)
            candidates.extend(protocol_candidates)
            for operation in operations:
                self._merge_graphql(operation)
            for text in protocol_hints:
                if text not in self._hints:
                    self._hints.append(text)

    def _merge_extracted(self, source_url: str, vendor: bool,
                         candidates: list, findings: list, params: list,
                         hosts: list, base_paths: list,
                         queue: Queue, scope: Scope, result: Result) -> None:
        """Fold one extraction pass's outputs into the shared result.

        Shared by the whole-body script path and the sliding-window overflow
        path so both merge identically — same vendor tagging, same
        de-duplication, same routing.
        """
        for candidate in candidates:
            candidate.vendor = vendor
            self._route_resource(candidate, source_url, queue, scope, result)

        for finding in findings:
            finding.vendor = vendor
            self._merge_finding(finding, result)
        for hit in params:
            hit.vendor = vendor
            self._merge_param(hit, result)
        for host in hosts:
            self._merge_host(host, vendor)

        for path in base_path_names(base_paths):
            if path not in self._base_paths and len(self._base_paths) < _MAX_BASE_PATHS:
                self._base_paths.append(path)

    def _overflow_consumer(self, item, scope: Scope, queue: Queue,
                           result: Result):
        """The sliding-window consumer for one fetch, or None to skip it.

        Only script-shaped fetches get one: a document's markup is read whole
        from the kept prefix, and a body that fits under the cap never
        overflows — the batch pass over it is already complete.
        """
        limit = max(0, int(self.config.request.max_response_bytes))
        if not limit:
            return None
        if not (item.kind in (Kind.SCRIPT, Kind.CHUNK)
                or is_javascript_path(item.url)):
            return None
        return _OverflowExtractor(self, item, scope, queue, result, limit)

    def _extract_overflow_piece(self, source_url: str, piece: str,
                                vendor: bool, skip: bool, item, scope,
                                queue, result) -> None:
        """One sliding-window piece of an over-cap body, on the worker.

        The same passes ``_extract_piece`` runs, minus the AST: parsing is
        what the AST cutoff already withholds from large bodies, and the
        window's job is recall — every regex the batch path runs sees every
        byte here.
        """
        candidates: list = []
        findings: list = []
        params: list = []
        hosts: list = []
        base_paths: list = []
        self._extract_piece(source_url, piece, False, skip, candidates,
                            findings, params, hosts, base_paths, result)
        self._merge_extracted(source_url, vendor, candidates, findings,
                              params, hosts, base_paths, queue, scope, result)

    def _absorb_map_reference(self, item, body: str, result: Result,
                              queue: Queue) -> None:
        inline, reference = source_map_reference(body)
        source_url = item.url
        if inline:
            self._absorb_recovered(source_url, inline, result)
            return
        if not reference:
            return
        resolved = resolve_url(source_url, reference)
        if not resolved:
            return
        scope = Scope(source_url, self.config.scope)
        if not scope.source_map_allowed(resolved):
            return
        # Queue it rather than listing it. Recording a map that was never
        # fetched puts an entry in jsfind_resources that reads as collected,
        # while the reason a map is worth anything -- its sourcesContent --
        # is never read. _absorb_map records the resource once the response
        # actually comes back, with a status code, so a map that fails to
        # download still shows up honestly as attempted.
        queue.push(resolved, Kind.SOURCEMAP, source_url,
                   depth=getattr(item, "depth", 0) + 1)

    def _absorb_map(self, item, response: Response, result: Result) -> None:
        """A fetched map: record it, then re-run extractors on its originals."""
        result.resources.append(Resource(
            url=item.url, type=ResourceType.SOURCEMAP,
            source_url=item.source_url, status_code=response.status_code,
            content_type=response.content_type, size=response.size,
            depth=item.depth,
        ))
        self._record_scan_host(item.url, item.source_url)
        self._absorb_recovered(item.url, self._decode(response), result)

    def _absorb_recovered(self, origin_url: str, map_body: str,
                          result: Result) -> None:
        """Feed every original embedded in a map back through the extractors.

        Each recovered source is also **saved to disk and recorded as a
        resource**. Without that, the unminified original is analyzed and then
        discarded: a consumer sees endpoints with no way to open the code they
        came from, and cannot search a bundle for a string it could not pre-
        guess. A leaked map is usually the whole application in readable form,
        so keeping it is the single highest-value thing a source map gives us.
        """
        queue = Queue(max_depth=self.config.limits.max_depth,
                      max_items=self.config.limits.max_resources)
        scope = Scope(origin_url, self.config.scope)
        for source_file in parse_source_map(map_body):
            if not source_file.name:
                continue
            pseudo = resolve_url(origin_url, source_file.name) or source_file.name
            content = source_file.content
            if is_third_party_bundle(content) and \
                    self.config.scope.skip_library_bundles:
                continue
            if not self._record_recovered(pseudo, content, origin_url, result):
                continue
            synthetic = offline_response(pseudo, content, "application/javascript")
            self._absorb_script(InlineItem(url=pseudo), synthetic, content,
                                queue, scope, result)

    def _record_recovered(self, pseudo_url: str, content: str,
                          origin_url: str, result: Result) -> bool:
        """Register one recovered original as a saved, searchable resource."""
        local = self._save_js(pseudo_url, content)
        result.resources.append(Resource(
            url=pseudo_url,
            type=ResourceType.SCRIPT,
            source_url=f"{origin_url} (source map)",
            local_path=local or "",
            content_type="application/javascript",
            size=len(content.encode("utf-8", "replace")),
            depth=0,
        ))
        self._recovered_count += 1
        return True

    # -- normalization --------------------------------------------------

    def _resolve_candidate(self, candidate: Candidate, source_url: str) -> str | None:
        """Turn an extracted value into an absolute, plausible URL."""
        raw = (candidate.raw or "").strip()
        if not raw:
            return None
        if raw.startswith(("data:", "javascript:", "blob:", "about:", "#")):
            return None
        if raw.startswith("//"):
            scheme = urlparse(source_url).scheme or "https"
            return f"{scheme}:{raw}"
        if "://" in raw:
            return raw
        if candidate.kind in (Kind.SCRIPT, Kind.CHUNK, Kind.SOURCEMAP):
            return resolve_url(source_url, raw)
        if raw.startswith(("/", "./", "../")):
            return resolve_url(source_url, raw)
        # A bare word with no path shape is a module specifier or a label.
        return None

    def _add_endpoint(self, candidate: Candidate, scope: Scope,
                      result: Result) -> None:
        raw = candidate.raw
        if not raw or (not looks_like_path(raw) and "://" not in raw):
            return
        # Webpack module keys (/PVX), URL-parser fixtures (/a/b) and build
        # paths (/home/jenkins/...) are not interfaces. The build paths are
        # reported by the 构建信息 rules, so dropping them here loses nothing.
        # Webpack module keys (/PVX), URL-parser fixtures (/a/b) and build
        # paths (/home/jenkins/...) are not interfaces. Routes and sockets
        # pass through: a route is a page and a socket is a handshake, and
        # the build paths are reported by the 构建信息 rules instead.
        # Decide on the path, not on raw: _route_resource has already resolved
        # raw to a full URL, and a URL does not start with "/". Webpack module
        # keys (/PVX), URL-parser fixtures (/a/b) and build paths
        # (/home/jenkins/...) are not interfaces -- the build paths are reported
        # by the 构建信息 rules instead.
        if (urlparse(raw).scheme or "").lower() not in _NON_HTTP_SCHEMES:
            _path = urlparse(raw).path or raw
            if (not looks_like_api_path(_path)
                    or is_filesystem_path(_path)
                    or is_static_asset_path(_path)):
                return
        url = raw if "://" in raw else urljoin(result.target, raw)
        # A WebSocket URL is a real finding — but it is not an HTTP interface.
        # Filing it as ``type="api"`` invites the model to test it with GETs
        # and to read the meaningless result as "exists" or "not_found".
        is_socket = (urlparse(raw).scheme or "").lower() in _NON_HTTP_SCHEMES
        kind = "socket" if is_socket else "api"
        key = f"{kind}\x00{candidate.method}\x00{url}"
        if key in self._endpoint_keys:
            return
        self._endpoint_keys.add(key)

        spec = candidate.spec
        if spec is not None and not spec.base_url:
            for prefix in self._base_paths:
                if join_base_url(prefix, raw):
                    spec.base_url = prefix
                    spec.base_url_kind = "prefix"
                    break

        endpoint = Endpoint(
            raw=raw,
            url=url,
            source_url=candidate.source_url,
            authorized=scope.is_authorized(url),
            method=candidate.method,
            evidence=candidate.evidence or EVIDENCE_STATIC,
            source=candidate.source or "regex",
            type=kind,
            line=candidate.line,
            column=candidate.column,
            context_lines=candidate.context_lines,
            body_params=candidate.body_params or (spec.param_keys() if spec else []),
            spec=spec,
            vendor=candidate.vendor,
            resolved=candidate.resolved,
            unresolved_prefix=candidate.unresolved_prefix,
        )
        # A socket has no HTTP request to reconstruct, and a template with a
        # wss:// request line is worse than no template at all.
        if self.config.request_template and not is_socket:
            endpoint.template = build_template(endpoint)
        result.endpoints.append(endpoint)

    def _add_route(self, candidate: Candidate, scope: Scope, result: Result) -> None:
        raw = candidate.raw
        url = raw if "://" in raw else urljoin(result.target, raw)
        key = f"route\x00{url}"
        if key in self._endpoint_keys:
            return
        self._endpoint_keys.add(key)
        result.endpoints.append(Endpoint(
            raw=raw,
            url=url,
            source_url=candidate.source_url,
            authorized=scope.is_authorized(url),
            evidence=EVIDENCE_STATIC,
            source=candidate.source or "regex",
            type="route",
            line=candidate.line,
            column=candidate.column,
            context_lines=candidate.context_lines,
            vendor=candidate.vendor,
        ))

    # -- probing --------------------------------------------------------

    # -- expansion passes ------------------------------------------------

    async def _settle(self, queue: Queue, client: Client, scope: Scope,
                      result: Result, root_url: str) -> None:
        """Drain what an expansion pass queued, under a smaller budget.

        The later passes only fetch what the earlier ones made visible, so they
        get a slice of what the target's whole budget has left and say so if
        they could not finish, rather than silently returning a partial view.
        """
        if not len(queue):
            return
        if self._budget.expired():
            self._hints.append("预算已耗尽，扩展阶段加入的资源未再继续获取。")
            return
        if self._budget.left() < _EXPANSION_BUDGET:
            budget = self._budget.left()
        else:
            budget = _EXPANSION_BUDGET
        try:
            await asyncio.wait_for(
                self._drain(queue, client, scope, result, root_url),
                timeout=budget,
            )
        except asyncio.TimeoutError:
            self._hints.append(
                f"扩展阶段追加的资源在 {budget:.0f}s 预算内未取完，"
                "结果中仅包含已获取的部分。"
            )

    def _probe_targets(self, refs, well_known, root_url: str) -> list[str]:
        """Referenced locations first, then the conventional ones.

        A path the target's own code names is worth far more than a guess, so
        references lead; the well-known list only fills in behind them.
        """
        out: list[str] = []
        seen: set[str] = set()
        for raw in sorted(refs):
            resolved = resolve_url(root_url, raw)
            if resolved and resolved not in seen:
                seen.add(resolved)
                out.append(resolved)
        for path in well_known:
            resolved = resolve_url(root_url, path)
            if resolved and resolved not in seen:
                seen.add(resolved)
                out.append(resolved)
        return out

    def _host_is_target(self, url: str, root_url: str) -> bool:
        """Whether a URL sits on the target's own host.

        Guessing ``/v3/api-docs`` against a third-party origin finds someone
        else's documentation, which would be reported as the target's interface.
        External probing stays behind the flag that already governs it elsewhere.
        """
        host = host_from_url(url)
        root_host = host_from_url(root_url)
        if not host or not root_host:
            return False
        return host == root_host or self.config.scope.probe_external_endpoints

    async def _expand_manifests(self, client: Client, scope: Scope,
                                result: Result, queue: Queue,
                                root_url: str) -> None:
        """Queue every script an asset manifest or precache list names.

        This is the one place chunk discovery is not a guess. A manifest is the
        build's own inventory, and a service workerprecache list is the set of
        URLs the app deliberately holds offline, so a file named there exists
        even when no loaded script references it.
        """
        if not self.config.scope.probe_asset_manifests:
            return
        targets = self._probe_targets(self._manifest_refs, MANIFEST_PATHS,
                                      root_url)
        added = 0
        found: list[dict] = []
        for url in targets[:_MAX_MANIFEST_PROBES]:
            # Checked per candidate rather than once: 12 requests against a slow
            # origin is how this phase turns into minutes.
            if self._budget.expired():
                self._hints.append("预算已耗尽，资源清单只探测了一部分。")
                break
            if not scope.can_fetch(url):
                continue
            try:
                response = await client.get(url, timeout=_PROBE_TIMEOUT)
            except Exception:  # noqa: BLE001 - an unreachable guess is not a failure
                continue
            if not response.ok or not response.is_textual():
                continue
            added += await self._offload(self._absorb_manifest, url, response,
                                         queue, root_url, found)
        result.assets.extend(found)
        if found:
            self._hints.append(
                f"发现 {len(found)} 个资源清单，其中 {added} 个此前未引用的脚本"
                "已加入收集队列。"
            )

    async def _crawl_routes(self, client: Client, scope: Scope,
                            result: Result, root_url: str) -> None:
        """Render each route to reach the scripts it loads on demand.

        A lazy-loaded view's code exists in the build but no loaded script
        mentions it, so reading the bundle cannot find it — only rendering the
        path can. Route guards are frequently not authorization, which is why
        this is GET-only and never authenticates.
        """
        if not self.config.scope.crawl_routes:
            return
        routes = collect_routes(result)
        budget = self.config.scope.route_budget or DEFAULT_ROUTE_BUDGET
        pairs = renderable_paths(routes, budget)
        if not pairs:
            # The table is still published: "these are the paths, and none were
            # eligible to render" is a different fact from "no routes found".
            result.routes.extend(route.to_dict() for route in routes.values())
            if routes:
                self._hints.append(
                    f"{len(routes)} 条前端路由全部形似接口路径或过短，未做渲染抓取。"
                )
            return

        route_queue = Queue(max_depth=self.config.limits.max_depth,
                            max_items=self.config.limits.max_resources)
        rendered = 0
        for route, concrete in pairs:
            # Rendering is one GET plus a full extraction pass per route, so the
            # deadline is checked before every single one.
            if self._budget.expired():
                route.note = "预算耗尽，未渲染"
                continue
            url = urljoin(root_url, concrete)
            if not scope.can_fetch(url):
                route.note = "不在采集范围内"
                continue
            try:
                response = await client.get(url, allow_redirect=scope.can_fetch)
            except Exception:  # noqa: BLE001 - a failed route is not a scan failure
                route.note = "抓取失败"
                continue
            route.status_code = response.status_code
            if not response.ok:
                route.note = f"HTTP {response.status_code}，未渲染"
                continue
            if not response.is_textual():
                route.note = "非文本响应，无懒加载脚本"
                continue
            await self._offload(self._absorb_route, route, url, response,
                                route_queue, scope, result, root_url)
            rendered += 1

        # Published after the loop: the table records what each render pulled
        # in, which only exists once every path has been visited.
        result.routes.extend(route.to_dict() for route in routes.values())
        if rendered:
            self._hints.append(
                f"渲染了 {rendered}/{len(pairs)} 条前端路由"
                "（GET，只读，未携带凭据）。"
            )
        await self._settle(route_queue, client, scope, result, root_url)

    def _absorb_spec(self, url: str, response: Response, result: Result,
                     root_url: str) -> None:
        """Read one published API specification and record its operations."""
        spec = parse_spec(url, self._decode(response))
        if not spec and not spec.notes:
            return
        result.specs.append(spec.to_dict())
        self._record_scan_host(url, root_url)
        if spec:
            self._add_spec_operations(spec, result)

    def _absorb_manifest(self, url: str, response: Response, queue: Queue,
                         root_url: str, found: list) -> int:
        """Read one manifest and queue the scripts it names. Returns how many."""
        manifest = parse_manifest(url, self._decode(response))
        if not manifest.files and not manifest.notes:
            return 0
        found.append(manifest.to_dict())
        self._record_scan_host(url, root_url)
        added = 0
        for name in manifest.scripts():
            resolved = resolve_url(url, name)
            if resolved and queue.push(resolved, Kind.CHUNK, url, depth=2):
                added += 1
        return added

    def _absorb_probe(self, endpoint: Endpoint, response: Response) -> None:
        """Record what one GET probe learned about an endpoint."""
        endpoint.status_code = response.status_code
        endpoint.signal = classify_status(response.status_code)
        # A 200 with a business failure code is not a success. The
        # operator tells us what their codes mean; the status line
        # alone cannot tell them.
        business = self._business_signal(response.text)
        if business:
            endpoint.signal = business
        # An interface often lives on a different stack than the site
        # itself (a PHP front end proxying a Tomcat API), so probing is a
        # second chance to learn the real middleware.
        self._absorb_banner(response)
        if response.ok and "json" in response.media_type():
            endpoint.response_params = json_field_names(response.text)[
                :_MAX_RESPONSE_FIELDS
            ]

    def _absorb_route(self, route: Route, url: str, response: Response,
                      route_queue: Queue, scope: Scope, result: Result,
                      root_url: str) -> None:
        """Record one rendered route and pull in what its document exposed."""
        result.resources.append(Resource(
            url=url, type=ResourceType.ROUTE,
            status_code=response.status_code,
            content_type=response.content_type, size=response.size,
            depth=1, final_url=response.final_url,
        ))
        self._record_scan_host(url, root_url)
        self._absorb_banner(response)
        self._last_route_candidates = []
        self._absorb_document(url, response, route_queue, scope, result)
        self._credit_route(route, url)
        route.rendered = True

    def _credit_route(self, route: Route, url: str) -> None:
        """Record what rendering one path uniquely pulled in."""
        for candidate in self._last_route_candidates:
            resolved = self._resolve_candidate(candidate, url)
            if not resolved:
                continue
            if is_javascript_path(resolved):
                if resolved not in route.scripts:
                    route.scripts.append(resolved)
            elif candidate.kind == Kind.ENDPOINT and \
                    resolved not in route.endpoints:
                route.endpoints.append(resolved)

    async def _expand_openapi(self, client: Client, scope: Scope,
                              result: Result, root_url: str) -> None:
        """Read a published OpenAPI/Swagger document if the target serves one.

        Everywhere else an endpoint is inferred from a string literal and might
        not exist. A published specification is the target's own statement of
        what it exposes, including fields no response ever showed.
        """
        if not self.config.scope.probe_api_specs:
            return
        targets = [url for url in self._probe_targets(self._spec_refs,
                                                      SPEC_PATHS, root_url)
                   if self._host_is_target(url, root_url)]
        for url in targets[:_MAX_SPEC_PROBES]:
            if self._budget.expired():
                self._hints.append("预算已耗尽，接口规范只探测了一部分。")
                break
            if not scope.can_probe(url):
                continue
            try:
                response = await client.get(url, timeout=_PROBE_TIMEOUT)
            except Exception:  # noqa: BLE001 - an unreachable guess is not a failure
                continue
            if not response.ok or not response.is_textual():
                continue
            await self._offload(self._absorb_spec, url, response, result,
                                root_url)

    def _add_spec_operations(self, spec, result: Result) -> None:
        """Write declared operations into the endpoint table.

        These carry the ``spec`` evidence level instead of being presented as
        inferred, and are deliberately left out of the GET probe pass: a spec
        can declare hundreds of paths, and confirming the target's own written
        interface is not what a collection scan was asked to do.
        """
        root = urljoin(spec.url, "/")
        added = 0
        for operation in spec.operations[:_MAX_SPEC_OPERATIONS]:
            url = urljoin(root, operation.path)
            key = f"{operation.method}\x00{url}"
            if key in self._endpoint_keys:
                continue
            self._endpoint_keys.add(key)
            result.endpoints.append(Endpoint(
                raw=operation.path, url=url, source_url=spec.url,
                method=operation.method, type="api", evidence=EVIDENCE_SPEC,
                source="spec", signal="declared",
                authorized=operation.requires_auth,
                # Declared path/query parameters matter as much as the
                # request body: on a GET the body is empty and the
                # parameters are the entire statement of what the
                # endpoint accepts.
                body_params=operation.param_names(),
            ))
            added += 1
        if added:
            self._hints.append(
                f"接口规范 {spec.url} 声明了 {added} 个操作"
                "（未经请求验证，来自目标自身文档）。"
            )

    async def _probe_endpoints(self, client: Client, scope: Scope,
                               result: Result) -> None:
        """Confirm in-scope endpoints with read-only GET probes.

        Only GET is ever sent, and only to hosts the scope authorizes, so the
        collection phase cannot write to the target.
        """
        if not self.config.scope.probe_endpoints:
            return
        targets = [endpoint for endpoint in result.endpoints
                   if endpoint.type == "api"
                   and scope.can_probe(endpoint.url)
                   # Operations a specification declares are the target's own
                   # written interface; confirming hundreds of them is active
                   # load, not collection.
                   and endpoint.evidence != EVIDENCE_SPEC
                   # A URL still holding a {placeholder} can only 404; probing
                   # it adds noise without adding knowledge.
                   and not route_param_names(endpoint.url)]
        if not targets:
            return
        batch_size = max(1, self.config.concurrency_limit)
        total = min(len(targets), self._candidate_limit())

        async def probe(endpoint: Endpoint) -> None:
            try:
                response = await client.get(endpoint.url, timeout=_PROBE_TIMEOUT)
            except Exception:  # noqa: BLE001 - a failed probe is not a scan failure
                return
            await self._offload(self._absorb_probe, endpoint, response)

        probed = 0
        for start in range(0, total, batch_size):
            # The most expensive phase by request count, and the easiest to leave
            # unfinished: everything already collected stays valid without it.
            if self._budget.expired():
                self._hints.append(
                    f"预算已耗尽，{total - probed}/{total} 个接口未做 GET 探测"
                    "（signal 保持 unprobed）。")
                break
            batch = targets[start:start + batch_size]
            # Each batch is capped by what is left, so one slow endpoint cannot
            # carry the batch past the deadline.
            try:
                await asyncio.wait_for(
                    asyncio.gather(*(probe(item) for item in batch),
                                   return_exceptions=True),
                    timeout=self._budget.timeout(),
                )
            except asyncio.TimeoutError:
                pass  # the next iteration sees an expired budget and stops
            probed += len(batch)

    # -- merging --------------------------------------------------------

    def _merge_graphql(self, operation) -> None:
        """Record one GraphQL operation document, once per distinct field set.

        The field selection is the valuable part: it states what the server
        hands over, including fields the UI never renders.
        """
        entry = operation.to_dict()
        key = (entry["kind"], entry["name"], tuple(entry["fields"]))
        if key in self._graphql:
            return
        self._graphql[key] = entry

    def _merge_finding(self, finding, result: Result) -> None:
        key = (finding.rule_id, finding.value, finding.source_url, finding.line)
        if key in self._findings_seen:
            return
        self._findings_seen.add(key)
        result.findings.append(finding)

    def _merge_param(self, hit, result: Result) -> None:
        key = (hit.name, hit.scenario, hit.source_url, hit.line)
        if not hit.name or key in self._params_seen:
            return
        self._params_seen.add(key)
        result.params.append(hit)

    def _merge_host(self, candidate: HostCandidate, vendor: bool) -> None:
        raw = (candidate.raw or "").strip().lower().rstrip(".")
        if not raw:
            return
        asset = self._hosts.get(raw)
        if asset is None:
            info = classify_host(raw, tuple(self.config.hosts.internal_suffixes))
            asset = HostAsset(
                value=raw,
                kind=info["kind"],
                origin="js",
                attributes=list(info.get("attributes") or []),
                vendor=vendor,
            )
            self._hosts[raw] = asset
        asset.occurrences += 1
        if len(asset.sources) < _MAX_HOST_EVIDENCE:
            asset.sources.append(candidate.to_evidence())

    def _record_scan_host(self, url: str, source_url: str = "") -> None:
        """Note a host the scan itself touched.

        Kept in its own table: a host found inside code and a host the scan
        requested are different facts and must not be counted as one number.
        """
        host = host_from_url(url)
        if not host:
            return
        asset = self._scan_hosts.get(host)
        if asset is None:
            info = classify_host(host, tuple(self.config.hosts.internal_suffixes))
            asset = HostAsset(value=host, kind=info["kind"], origin="scan",
                              attributes=list(info.get("attributes") or []))
            self._scan_hosts[host] = asset
        asset.occurrences += 1
        if len(asset.sources) < _MAX_HOST_EVIDENCE:
            asset.sources.append(HostEvidence(
                source_url=source_url or url, raw=url, method="url",
                associated_url=url, note="scan_role",
            ))

    def _publish_hosts(self, result: Result) -> None:
        result.hosts = sorted(self._hosts.values(), key=lambda a: a.value)
        result.scan_hosts = sorted(self._scan_hosts.values(), key=lambda a: a.value)

    # -- banners --------------------------------------------------------

    def _absorb_banner(self, response: Response) -> None:
        """Read versioned middleware fingerprints off one response.

        Headers are the primary source; the body is scanned too because an
        error page often prints the full banner that the header truncates
        (``Apache/2.4.41 (Ubuntu) Server at ... Port 80``).

        Both passes yield nothing when no version is present, so a target that
        merely sets ``Server: nginx`` produces no banner at all.
        """
        url = response.final_url or response.url
        host = host_from_url(url) or ""
        found = self.banners.match_headers(
            response.headers, host=host, source_url=url,
            status_code=response.status_code,
        )
        # Only error pages are worth a body scan: a 200 page's HTML is already
        # mined for endpoints, and re-scanning it here would double the work
        # for the same answer.
        if response.body and (response.status_code >= 400 or
                              not response.is_textual()):
            found.extend(self.banners.match_body(
                self._decode(response), host=host, source_url=url,
                status_code=response.status_code,
            ))
        for banner in found:
            key = banner.key()
            if key in self._banner_keys:
                continue
            self._banner_keys.add(key)
            self._banners.append(banner)

    def _sorted_banners(self) -> list[Banner]:
        """Order banners so the most actionable ones come first.

        Severity leads, then category, then product name: a WebLogic version on
        a public interface matters more than a CDN edge version.
        """
        return sorted(
            self._banners,
            key=lambda banner: (
                -severity_rank(banner.severity.value),
                _CATEGORY_ORDER.get(banner.category, 9),
                banner.product.lower(),
                banner.version,
            ),
        )

    # -- storage --------------------------------------------------------

    def _js_directory(self, root_url: str) -> tuple[Path | None, str]:
        """Where this run's scripts go, and why not if nowhere.

        A per-target subdirectory is always appended so two targets cannot
        overwrite each other's files. The base is resolved to an absolute path
        first: a relative one would land wherever the MCP client happened to
        launch the server.
        """
        if not self.config.save_js:
            return None, ""
        try:
            base = Path(self.config.js_dir).expanduser().resolve()
        except (OSError, RuntimeError) as exc:
            return None, (f"js_dir 无法解析：{self.config.js_dir!r}"
                             f"（{exc}）")
        path = base / target_directory(root_url) / "js"
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return None, (f"js_dir 不可写：{path}（{exc}）；"
                             "本次未保存任何脚本，"
                             "jsfind_js_files / jsfind_js_search 将无结果")
        return path, ""

    def _save_js(self, url: str, body: str) -> str | None:
        """Persist one downloaded script so a report reader can open it."""
        if self._js_dir is None:
            return None
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]
        suffix = Path(urlparse(url).path).suffix
        if not suffix.isascii() or len(suffix) > 8:
            suffix = ".txt"
        target = self._js_dir / f"{digest}{suffix}"
        try:
            target.write_text(body, encoding="utf-8", errors="replace")
        except OSError:
            return None
        return str(target)

    # -- helpers --------------------------------------------------------

    def _decode(self, response: Response) -> str:
        if not response.body:
            return ""
        content_type = (response.content_type or "").lower()
        if "charset=" in content_type:
            encoding = content_type.split("charset=", 1)[1].split(";")[0].strip()
            try:
                return response.body.decode(encoding, "replace")
            except LookupError:
                pass
        if response.body[:3] == b"\xef\xbb\xbf":
            return response.body[3:].decode("utf-8", "replace")
        return response.text

    def _business_signal(self, body: str) -> str:
        """The signal the response *body* implies, if any.

        Patterns are plain substrings, matched against the body as text.
        A real body pattern is more than a code: the operator writes
        ``\"code\":477`` or ``\"errno\":10001`` to say what their own
        API means by it, and that is more precise than any guess made
        here about what a number means.
        """
        if not body:
            return ""
        rules = getattr(self.config.request, "business_codes", None) or {}
        if not rules:
            return ""
        for category, patterns in rules.items():
            if isinstance(patterns, str):
                patterns = [patterns]
            for pattern in patterns or []:
                if pattern and pattern in body:
                    return str(category)
        return ""

    def _candidate_limit(self) -> int:
        return self.config.limits.max_resources or 20_000

    @staticmethod
    def _resource_type(kind: str) -> ResourceType:
        return {
            Kind.SCRIPT: ResourceType.SCRIPT,
            Kind.CHUNK: ResourceType.CHUNK,
            Kind.SOURCEMAP: ResourceType.SOURCEMAP,
            Kind.ROUTE: ResourceType.ROUTE,
            Kind.ASSET: ResourceType.ASSET,
        }.get(kind, ResourceType.SCRIPT)


# -- request reconstruction ---------------------------------------------


def build_template(endpoint: Endpoint) -> RequestTemplate | None:
    """Reconstruct a copy-pasteable HTTP request for one endpoint.

    Values the source carried literally are kept; values that must be invented
    become ``{{fuzz:name}}`` placeholders, so the packet is honest about what is
    known and what a tester still has to supply.
    """
    spec = endpoint.spec
    if spec is None:
        if endpoint.evidence not in (EVIDENCE_RUNTIME, EVIDENCE_FULL_URL):
            return None
        spec = RequestSpec()

    template = RequestTemplate(method=endpoint.method or "GET", url=endpoint.url)
    template.headers = [
        HeaderTpl(key="User-Agent", value="{{fuzz:user-agent}}",
                  evidence="placeholder"),
        HeaderTpl(key="Accept", value="application/json", evidence="inferred"),
    ]
    if endpoint.evidence == EVIDENCE_RUNTIME:
        template.headers.append(
            HeaderTpl(key="Cookie", value="{{cookie:session}}", evidence="placeholder")
        )
    if spec.content_type:
        template.headers.append(HeaderTpl(
            key="Content-Type", value=spec.content_type,
            evidence=spec.content_type_evidence or "inferred",
        ))

    if spec.query:
        template.url = _append_query(template.url, spec.query)
    if spec.body:
        template.body = render_body(spec.body)
    elif endpoint.body_params:
        template.body = render_body([
            Param(key=name, evidence="inferred") for name in endpoint.body_params
        ])

    notes: list[str] = []
    placeholders = route_param_names(endpoint.url)
    if placeholders:
        notes.append("路径含占位符 " + "、".join(placeholders) + "，替换后再发送。")
    if spec.base_url and spec.base_url_kind:
        notes.append(f"源码声明的接口前缀：{spec.base_url}（{spec.base_url_kind}）。")
    template.notes = notes
    return template


def _append_query(url: str, params: list[Param]) -> str:
    pairs = [(param.key, str(param.value or "{{fuzz:%s}}" % param.key))
             for param in params]
    encoded = urlencode(pairs, quote_via=quote, safe="{{}}:/")
    return url + ("&" if "?" in url else "?") + encoded


def render_body(params: list[Param]) -> str:
    """Render a JSON body from a recovered parameter list."""
    lines = ["{"]
    for index, param in enumerate(params):
        value = param.value or "{{fuzz:%s}}" % param.key
        comma = "," if index < len(params) - 1 else ""
        lines.append(f'  "{param.key}": "{value}"{comma}')
    lines.append("}")
    return "\n".join(lines)


def target_directory(url: str) -> str:
    """Filesystem-safe directory name for one target."""
    parsed = urlparse(url)
    host = (parsed.hostname or "target").lower()
    name = f"{host}_{parsed.port}" if parsed.port else host
    path = parsed.path.strip("/").replace("/", "_")
    if path:
        name = f"{name}_{path}"
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:80] or "target"
