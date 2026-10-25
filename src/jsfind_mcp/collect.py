"""HTTP collection client.

One async client per scan target. Responsibilities are deliberately narrow:
fetch a URL, return the body plus enough metadata to classify it, and follow a
redirect only while it stays inside scope — recording where it landed so the
report shows the real address rather than the one the code referenced.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

from .chunking import REJECT_MAX_BYTES
from .config import Config
from .proxy import bypass_hosts, mounts_for, normalize, ProxyError
from .utils import normalize_url

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# Content types whose body is worth parsing. Anything else is recorded as a
# resource but never analyzed.
_JS_TYPES = ("javascript", "ecmascript")
_TEXTUAL_EXACT = frozenset({
    "application/json", "application/xml", "application/wasm",
    "application/octet-stream", "application/x-www-form-urlencoded",
    "application/manifest+json", "application/xhtml+xml",
})
_SCRIPT_SUFFIXES = (".js", ".mjs", ".jsx", ".ts", ".tsx")

#: Streaming read granularity. Small enough that a decompression bomb's
#: expansion is noticed within one chunk of hitting the cap, large enough that
#: per-chunk overhead is noise even for hundreds of responses.
_READ_CHUNK = 64 * 1024


@dataclass
class Response:
    """One fetched resource."""

    url: str = ""
    final_url: str = ""
    status_code: int = 0
    content_type: str = ""
    body: bytes = b""
    #: full response headers, lowercased keys — the banner engine's input
    headers: dict[str, str] = field(default_factory=dict)
    elapsed: float = 0.0
    error: str = ""
    redirected: bool = False
    redirect_to: str = ""
    #: True when the retained body is only a prefix of the full response —
    #: cut short by the response-size cap or by the reject ceiling. The prefix
    #: is still analyzed in full (AST included), but downstream passes must
    #: not treat it as the whole file.
    truncated: bool = False
    #: Content-Length as declared by the server, or -1 when absent/chunked.
    declared_size: int = -1
    #: Total decompressed bytes the transfer actually carried, even when
    #: ``body`` kept only the prefix. -1 when nothing was streamed.
    streamed_size: int = -1
    #: True when the bytes past the cap were still run through the sliding-
    #: window extractor, so regex-level findings cover the whole transfer
    #: even though ``body`` holds only the prefix.
    overflow_analyzed: bool = False

    @property
    def ok(self) -> bool:
        return not self.error and 200 <= self.status_code < 400

    @property
    def size(self) -> int:
        """The response's real size: what was streamed, not what was kept."""
        return self.streamed_size if self.streamed_size >= 0 else len(self.body)

    @property
    def text(self) -> str:
        """Body decoded leniently.

        A truncated or partly binary body yields mojibake rather than raising:
        the regex pass copes with that, and an exception here would abandon a
        resource that still holds findable interfaces.
        """
        if not self.body:
            return ""
        return self.body.decode("utf-8", "replace")

    def path(self) -> str:
        return urlparse(self.final_url or self.url).path.lower()

    def media_type(self) -> str:
        return (self.content_type or "").split(";")[0].strip().lower()

    def is_script(self) -> bool:
        media = self.media_type()
        if any(token in media for token in _JS_TYPES):
            return True
        return self.path().endswith(_SCRIPT_SUFFIXES)

    def is_source_map(self) -> bool:
        return self.path().endswith(".map") and "json" in self.media_type()

    def is_textual(self) -> bool:
        media = self.media_type()
        if not media:
            # No content-type at all: assume it may be worth reading.
            return True
        if media.startswith("text/"):
            return True
        if any(token in media for token in _JS_TYPES):
            return True
        return media in _TEXTUAL_EXACT


class Client:
    """Async HTTP client bound to one scan configuration."""

    def __init__(self, config: Config, headers: dict[str, str] | None = None,
                 cookies: dict[str, str] | None = None):
        self.config = config
        self.user_agent = config.request.user_agent or DEFAULT_USER_AGENT
        self.headers = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        }
        self.headers.update(config.request.headers or {})
        if headers:
            self.headers.update(headers)
        self.cookies = dict(config.request.cookies or {})
        self.cookies.update(cookies or {})
        self._client: httpx.AsyncClient | None = None
        #: Why the proxy was not applied, if it was not. Surfaced rather
        #: than swallowed: a silent fallback to a direct connection is the
        #: kind of thing that leaks a tester's real IP to the target.
        self.proxy_note = ""

    async def __aenter__(self) -> "Client":
        await self.start()
        return self

    async def __aexit__(self, *_exc) -> None:
        await self.close()

    async def start(self) -> None:
        if self._client is not None:
            return
        kwargs = {
            "timeout": httpx.Timeout(self.config.request.timeout),
            "follow_redirects": False,
            "verify": self.config.request.verify_tls,
            "limits": httpx.Limits(max_connections=32, max_keepalive_connections=16),
            "headers": self.headers,
            "cookies": self.cookies,
            "trust_env": self.config.request.trust_env,
        }
        # httpx raises from inside the constructor on a malformed proxy,
        # which would abort the scan with a message about transports. It is
        # parsed and checked here instead, and a bad value degrades to a
        # direct connection plus a recorded note -- refusing to scan at all
        # because a convenience setting is malformed helps nobody.
        try:
            proxy = normalize(self.config.request.proxy)
        except ProxyError as exc:
            proxy, self.proxy_note = "", str(exc)
        if proxy:
            kwargs["proxy"] = proxy
        mounts = mounts_for(bypass_hosts(self.config.request.no_proxy))
        if mounts:
            kwargs["mounts"] = mounts
        self._client = httpx.AsyncClient(**kwargs)

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def get(self, url: str, follow: bool = True,
                  allow_redirect=None,
                  timeout: float | None = None,
                  on_chunk=None) -> Response:
        """Fetch one URL, following redirects while they remain allowed.

        ``allow_redirect`` is a predicate the scope controller supplies; a
        redirect it rejects stops the chain instead of leaving the target.

        ``timeout`` overrides the transfer wall clock for this one request.
        The probe passes use it: a well-known path that answers and then never
        finishes (no Content-Length, connection held open) costs the configured
        read-gap timeout per attempt, and a scan probing ten of those must not
        spend a bundle-sized budget on them.

        ``on_chunk`` is an async consumer of the decompressed body bytes, in
        stream order. It is handed every chunk of the final (non-redirect)
        response regardless of the retention cap — that is how the sliding-
        window extractor reaches the part of a 20 MB bundle the kept prefix
        cannot. Time spent inside the consumer is refunded to the transfer
        wall clock: that clock bounds the network, not our own analysis.
        """
        await self.start()
        target = normalize_url(url)
        current = target
        hops = self.config.request.max_redirects if follow else 0
        for hop in range(hops + 1):
            response = await self._once(current, timeout, on_chunk)
            if not response.redirected or hop >= hops:
                return response
            location = response.redirect_to
            if not location:
                return response
            if allow_redirect is not None and not allow_redirect(location):
                response.redirect_to = ""
                return response
            current = location
        return Response(url=target, error="too many redirects")

    async def _once(self, url: str, timeout: float | None = None,
                    on_chunk=None) -> Response:
        attempts = max(1, self.config.request.retry + 1)
        last = Response(url=url, final_url=url)
        for attempt in range(attempts):
            try:
                last = await self._fetch_streaming(url, timeout, on_chunk)
            except httpx.TooManyRedirects:
                return Response(url=url, final_url=url, error="too many redirects")
            except httpx.TimeoutException as exc:
                # ReadTimeout and kin: the server was slow once; an immediate
                # retry just reads slowly twice. Connection-level failures in
                # the branch below are the ones an attempt can fix.
                return Response(url=url, final_url=url,
                                error=f"{type(exc).__name__}: {exc}")
            except httpx.HTTPError as exc:
                last = Response(url=url, final_url=url,
                                error=f"{type(exc).__name__}: {exc}")
                if attempt + 1 < attempts:
                    await asyncio.sleep(0.3 * (attempt + 1))
                continue
            except asyncio.TimeoutError:
                # Not an httpx error: this is our own wall clock on the whole
                # transfer. A server streaming one byte just under httpx's
                # read-gap timeout would otherwise hold a fetch slot forever,
                # because that timeout bounds the gap between reads, never the
                # transfer itself. Retrying cannot beat the same wall.
                seconds = (timeout if timeout and timeout > 0
                           else self.config.request.download_timeout)
                return Response(url=url, final_url=url,
                                error=f"download timeout after {seconds:g}s")
            return last
        return last

    async def _fetch_streaming(self, url: str,
                               timeout: float | None = None,
                               on_chunk=None) -> Response:
        """Fetch one URL with the body read in bounded pieces.

        ``client.get()`` buffers the entire response before returning, so a
        20 MB bundle (or a gzip bomb, or a chunked body with no length at all)
        lands whole in memory before any size check could run — the same
        memory-exhaustion shape that gets crawler clients CVE'd. Here the body
        is streamed in chunks, counted after decompression, and the retained
        ``body`` stops at ``max_response_bytes``: the first cap bytes of a
        bundle carry nearly every interface it has. With an ``on_chunk``
        consumer the stream itself continues past the cap (up to the reject
        ceiling) so the consumer sees every byte, and the read stops there.
        """
        limit = max(0, int(self.config.request.max_response_bytes))
        started = time.monotonic()
        assert self._client is not None
        wall = timeout if timeout is not None and timeout > 0 else None
        request_timeout = httpx.Timeout(wall) if wall else None
        loop = asyncio.get_running_loop()
        effective_wall = wall if wall else self.config.request.download_timeout
        deadline = (loop.time() + effective_wall
                    if effective_wall and effective_wall > 0 else None)
        async with self._time_download(wall) as clock:
            async with self._client.stream("GET", url,
                                           timeout=request_timeout) as raw:
                response = Response(
                    url=url,
                    final_url=str(raw.url),
                    status_code=raw.status_code,
                    content_type=raw.headers.get("content-type", ""),
                    headers={name.lower(): value
                             for name, value in raw.headers.items()},
                )
                declared = raw.headers.get("content-length")
                if declared is not None:
                    try:
                        response.declared_size = int(declared)
                    except ValueError:
                        pass
                # The cap applies after decompression, so the declared length
                # is advisory only: a chunked body has none, and a compressed
                # one can expand far past it. Whatever the headers claim, the
                # first cap bytes are read and kept — for a bundle that prefix
                # carries nearly every interface — and the consumer, when
                # present, is handed the rest as it streams by. A redirect hop
                # or a binary body feeds nobody: one is not the resource, the
                # other is not text to extract from.
                feed = None
                if (on_chunk is not None and response.is_textual()
                        and not (300 <= raw.status_code < 400)):
                    feed = on_chunk
                chunks: list[bytes] = []
                kept = 0
                total = 0
                stopped_early = False
                async for chunk in raw.aiter_bytes(_READ_CHUNK):
                    if feed is not None:
                        tick = loop.time()
                        await feed(chunk)
                        # Our own analysis must not count against the network
                        # budget, or a big bundle would be cut off mid-download
                        # for being expensive to read.
                        if deadline is not None and clock is not None:
                            deadline += loop.time() - tick
                            clock.reschedule(deadline)
                    total += len(chunk)
                    if limit and kept < limit:
                        take = chunk[: limit - kept]
                        chunks.append(take)
                        kept += len(take)
                    elif not limit:
                        chunks.append(chunk)
                        kept += len(chunk)
                    if feed is None and limit and kept >= limit:
                        stopped_early = True
                        break
                    if total >= REJECT_MAX_BYTES:
                        stopped_early = True
                        break
                body = b"".join(chunks)
                if limit and len(body) > limit:
                    body = body[:limit]
                response.body = body
                response.streamed_size = total
                # Truncated means the retained body is not the whole story:
                # either the stream really ran past it, or the read stopped
                # at the cap / ceiling where more may well have been waiting.
                response.truncated = stopped_early or total > kept
                response.overflow_analyzed = bool(feed) and total > (limit or 0)
                if 300 <= raw.status_code < 400:
                    response.redirected = True
                    location = raw.headers.get("location", "")
                    if location:
                        response.redirect_to = urljoin(str(raw.url), location)
                response.elapsed = time.monotonic() - started
                return response

    def _time_download(self, seconds: float | None = None):
        """A wall-clock context over the whole transfer.

        ``None`` means the configured ``download_timeout``; a positive value
        overrides it; zero means unlimited.
        """
        limit = (self.config.request.download_timeout
                 if seconds is None else seconds)
        if limit and limit > 0:
            return asyncio.timeout(limit)
        return contextlib.nullcontext()


def offline_response(url: str, body: str, content_type: str = "text/html") -> Response:
    """Build a Response for content that did not come over the wire.

    Used for inline scripts and for map sources recovered from a bundle, which
    have a URL for provenance but no HTTP exchange behind them.
    """
    return Response(
        url=url,
        final_url=url,
        status_code=200,
        content_type=content_type,
        body=body.encode("utf-8", "replace"),
    )
