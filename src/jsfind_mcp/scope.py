"""Scope control: which hosts and path suffixes the queue is allowed to touch.

Two populations are kept strictly apart:

* **fetchable** — a resource the scan will actually request (scripts, chunks,
  maps). Defaults to the target's own host plus anything the operator allows.
* **reportable** — an endpoint merely *mentioned* in the code. An endpoint may
  be reported even when it lives outside the fetch scope; it is simply never
  probed and never marked authorized. Conflating the two is how a scanner ends
  up sending requests to third parties it was never authorized to test.
"""

from __future__ import annotations

from urllib.parse import urlparse

from .config import ScopeConfig
from .utils import origin_of

# Characters that make a path a download rather than an interface.
_DEFAULT_SUFFIX_BLACKLIST = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp", ".tif",
    ".tiff", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".wav", ".ogg",
    ".flac", ".mp4", ".webm", ".avi", ".mov", ".mkv", ".zip", ".rar", ".7z",
    ".tar", ".gz", ".pdf", ".wasm", ".exe", ".dll", ".dmg", ".iso", ".css",
)

# Schemes no HTTP probe can speak to. Kept here rather than in the pipeline so
# this module stays the single place that decides what a request may target.
_NON_HTTP_SCHEMES = frozenset({"ws", "wss"})


class Scope:
    """Decides whether a URL may be fetched, probed or only reported."""

    def __init__(self, root: str, config: ScopeConfig):
        self.root = root
        self.config = config
        self.root_host = (urlparse(root).hostname or "").lower()
        self.root_origin = origin_of(root)
        self.allowed = [host.lower() for host in config.allow_domains]
        self.restricted = [host.lower() for host in config.restrict_domains]
        self.blacklist = tuple(
            suffix.lower() for suffix in (config.suffix_blacklist
                                         or _DEFAULT_SUFFIX_BLACKLIST)
        )
        self.restrict_active = bool(self.restricted)

    # -- host matching ---------------------------------------------------

    def _host_matches(self, host: str, pattern: str) -> bool:
        """``pattern`` is an exact host, or ``.suffix`` for any subdomain."""
        if pattern.startswith("."):
            return host == pattern[1:] or host.endswith(pattern)
        return host == pattern

    def _in_allowlist(self, host: str) -> bool:
        return any(self._host_matches(host, pattern) for pattern in self.allowed)

    def _in_restrictlist(self, host: str) -> bool:
        if not self.restrict_active:
            return False
        if host == self.root_host:
            return True
        return any(self._host_matches(host, pattern) for pattern in self.restricted)

    # -- decisions -------------------------------------------------------

    def is_same_host(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        return bool(host) and host == self.root_host

    def can_fetch(self, url: str) -> bool:
        """Whether the scan may issue a request for this resource URL."""
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return False
        if self.restrict_active and not self._in_restrictlist(host):
            return False
        if host == self.root_host:
            return not self.is_blacklisted(url)
        if not self.config.fetch_external_scripts:
            return False
        if not (self._in_allowlist(host) or self._in_restrictlist(host)):
            return False
        return not self.is_blacklisted(url)

    def can_probe(self, url: str) -> bool:
        """Whether the scan may send a probe request to this endpoint.

        Probing an external host is off by default: it turns a read-only
        collection run into active traffic against a third party. A non-HTTP
        scheme is refused outright rather than by host, because the answer does
        not depend on who owns the host.
        """
        if (urlparse(url).scheme or "").lower() in _NON_HTTP_SCHEMES:
            return False
        if self.is_same_host(url):
            return not self.is_blacklisted(url)
        if self.restrict_active and not self._in_restrictlist(
            (urlparse(url).hostname or "").lower()
        ):
            return False
        return bool(self.config.probe_external_endpoints) and \
            self._in_allowlist((urlparse(url).hostname or "").lower())

    def is_authorized(self, url: str) -> bool:
        """Whether an endpoint is in scope for *testing*.

        Reported separately from fetchability so a report can show "found, not
        authorized" instead of silently dropping third-party endpoints.
        """
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return False
        if host == self.root_host:
            return True
        return self._in_allowlist(host) or self._in_restrictlist(host)

    def is_blacklisted(self, url: str) -> bool:
        """Whether a path ends in a suffix the queue ignores (images, fonts…)."""
        parsed = urlparse(url)
        path = parsed.path.lower()
        for suffix in self.blacklist:
            if path.endswith(suffix):
                return True
        return False

    def source_map_allowed(self, url: str) -> bool:
        """Whether a source map may be fetched.

        A leaked map restores the whole front end, so the default is yes; known
        library maps are excluded because they are large and useless.
        """
        if not self.config.probe_source_maps:
            return False
        if not self.can_fetch(url):
            return False
        path = urlparse(url).path.lower()
        for fragment in self.config.source_map_blacklist:
            fragment = fragment.lower().strip()
            if fragment and fragment in path:
                return False
        return True
