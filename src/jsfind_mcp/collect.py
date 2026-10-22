"""HTTP collection client.

One async client per scan target. Responsibilities are deliberately narrow:
fetch a URL, return the body plus enough metadata to classify it, and follow a
redirect only while it stays inside scope — recording where it landed so the
report shows the real address rather than the one the code referenced.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

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

    @property
    def ok(self) -> bool:
        return not self.error and 200 <= self.status_code < 400

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
                  allow_redirect=None) -> Response:
        """Fetch one URL, following redirects while they remain allowed.

        ``allow_redirect`` is a predicate the scope controller supplies; a
        redirect it rejects stops the chain instead of leaving the target.
        """
        await self.start()
        target = normalize_url(url)
        current = target
        hops = self.config.request.max_redirects if follow else 0
        for hop in range(hops + 1):
            response = await self._once(current)
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

    async def _once(self, url: str) -> Response:
        attempts = max(1, self.config.request.retry + 1)
        last = Response(url=url, final_url=url)
        for attempt in range(attempts):
            try:
                assert self._client is not None
                raw = await self._client.get(url)
            except httpx.TooManyRedirects:
                last = Response(url=url, final_url=url, error="too many redirects")
                return last
            except httpx.HTTPError as exc:
                last = Response(url=url, final_url=url,
                                error=f"{type(exc).__name__}: {exc}")
                if attempt + 1 < attempts:
                    await asyncio.sleep(0.3 * (attempt + 1))
                continue
            last = Response(
                url=url,
                final_url=str(raw.url),
                status_code=raw.status_code,
                content_type=raw.headers.get("content-type", ""),
                body=raw.content,
                headers={name.lower(): value
                         for name, value in raw.headers.items()},
            )
            if 300 <= raw.status_code < 400:
                last.redirected = True
                location = raw.headers.get("location", "")
                if location:
                    last.redirect_to = urljoin(str(raw.url), location)
            return last
        return last


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
