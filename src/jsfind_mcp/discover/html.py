"""HTML document extraction: scripts, inline code, SPA and framework signals."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from ..utils import ensure_directory_url, is_javascript_path, is_source_map_path
from .types import Candidate, HTMLResult, Kind, SPAEvidence

# Attributes that can carry a fetchable resource.
_RESOURCE_ATTRS = {
    "script": ("src",),
    "link": ("href",),
    "img": ("src", "data-src"),
    "iframe": ("src",),
    "embed": ("src",),
    "source": ("src", "srcset"),
    "video": ("src", "poster"),
    "audio": ("src",),
    "object": ("data",),
}

# Framework fingerprints worth reporting as technologies.
_FRAMEWORK_SIGNATURES = (
    ("vue", re.compile(r"(?i)(?:createApp|new Vue|vue\.runtime|__VUE__)")),
    ("react", re.compile(r"(?i)(?:ReactDOM\.createRoot|React\.createElement|__REACT_DEVTOOLS)")),
    ("angular", re.compile(r"(?i)(?:angular\.module|ng-app|\[ngVersion\])")),
    ("svelte", re.compile(r"(?i)(?:svelte|sveltekit)")),
    ("jquery", re.compile(r"(?i)jQuery\.fn\.jquery|jQuery v\d")),
    ("axios", re.compile(r"(?i)axios\.isAxiosObject|axios\.defaults")),
    ("next.js", re.compile(r"(?i)__NEXT_DATA__|/_next/static")),
    ("nuxt", re.compile(r"(?i)__NUXT__|/_nuxt/")),
    ("umi", re.compile(r"(?i)__umi|umi\.production")),
    ("webpack", re.compile(r"(?i)webpackChunk|__webpack_require__")),
    ("vite", re.compile(r"(?i)/@vite/client|vite/dist/client")),
    ("requirejs", re.compile(r"(?i)requirejs\.config|require\.config")),
)

_SKIP_SCHEMES = ("data:", "javascript:", "mailto:", "tel:", "#", "blob:", "about:")

_INLINE_SCRIPT_RE = re.compile(
    r"(?is)<script\b(?P<attrs>[^>]*)>(?P<code>.*?)</script\s*>"
)
_SRC_RE = re.compile(r"""\bsrc\s*=\s*["']([^"']+)["']""", re.I)
_HREF_RE = re.compile(r"""\bhref\s*=\s*["']([^"']+)["']""", re.I)
_META_REFRESH_RE = re.compile(
    r"""(?i)<meta[^>]+http-equiv=["']?refresh["']?[^>]*content=["']([^"']+)"""
)
_INLINE_ATTR_RE = re.compile(
    r"""(?is)<(?:a|img|iframe|form)\b[^>]*?\b(?:href|src|action|data-src|data-url)"""
    r"""\s*=\s*["']([^"']+)["']"""
)


def parse_html(base_url: str, body: str) -> HTMLResult:
    """Extract scripts, inline code and framework signals from a document."""
    result = HTMLResult()
    if not body:
        return result

    if _has_parser():
        _parse_with_bs4(base_url, body, result)
    else:
        _parse_with_regex(base_url, body, result)

    result.technologies = _detect_frameworks(body)
    result.spa = _detect_spa(result.technologies)
    _dedupe(result)
    return result


def _has_parser() -> bool:
    try:
        import bs4  # noqa: F401
    except ImportError:
        return False
    return True


def _parse_with_bs4(base_url: str, body: str, result: HTMLResult) -> None:
    from bs4 import BeautifulSoup

    try:
        soup = BeautifulSoup(body, "html.parser")
    except Exception:  # noqa: BLE001 - malformed markup must not abort a scan
        _parse_with_regex(base_url, body, result)
        return

    seen: set[str] = set()
    for tag in soup.find_all(True):
        name = (tag.name or "").lower()
        for attr in _RESOURCE_ATTRS.get(name, ()):
            value = tag.get(attr)
            if not isinstance(value, str) or not value.strip():
                continue
            if name == "source" and attr == "srcset":
                for piece in value.split(","):
                    _add(base_url, piece.strip().split(" ")[0], name, seen, result)
                continue
            _add(base_url, value, name, seen, result)

        if name == "script" and not tag.get("src"):
            code = tag.string
            if isinstance(code, str) and code.strip():
                result.inline_scripts.append(code)

    # Module preload / prefetch links point at chunks worth fetching.
    for link in soup.find_all("link"):
        rel = " ".join(link.get("rel") or []).lower()
        if not any(token in rel for token in ("preload", "prefetch", "modulepreload")):
            continue
        href = link.get("href")
        if isinstance(href, str) and href.strip():
            _add(base_url, href, "link", seen, result)


def _add(base_url: str, value: str, tag_name: str, seen: set[str], result: HTMLResult) -> None:
    """Queue one fetchable URL referenced by a document element."""
    value = value.strip()
    if value.startswith(_SKIP_SCHEMES):
        return
    try:
        absolute = urljoin(base_url, value)
    except ValueError:
        return
    if absolute in seen:
        return
    seen.add(absolute)
    pathname = urlparse(absolute).path.lower()
    if is_source_map_path(pathname):
        kind = Kind.SOURCEMAP
    elif is_javascript_path(pathname):
        kind = Kind.SCRIPT
    elif tag_name == "link" and pathname.endswith((".json", ".wasm")):
        kind = Kind.ASSET
    else:
        return
    result.candidates.append(Candidate(
        raw=absolute, kind=kind, source_url=base_url, source="html",
    ))


def _parse_with_regex(base_url: str, body: str, result: HTMLResult) -> None:
    """Pure-regex fallback used when BeautifulSoup is unavailable."""
    seen: set[str] = set()

    for match in _INLINE_SCRIPT_RE.finditer(body):
        attrs = match.group("attrs") or ""
        code = match.group("code") or ""
        src = _SRC_RE.search(attrs)
        if src:
            _add(base_url, src.group(1), "script", seen, result)
        elif code.strip():
            result.inline_scripts.append(code)

    for match in _INLINE_ATTR_RE.finditer(body):
        _add(base_url, match.group(1), "a", seen, result)

    for href in _HREF_RE.findall(body):
        _add(base_url, href, "link", seen, result)

    for target in _META_REFRESH_RE.findall(body):
        parts = target.split("=", 1)
        if len(parts) == 2 and parts[0].strip().lower() == "url":
            _add(base_url, parts[1].strip("'\" "), "meta", seen, result)


def _detect_frameworks(body: str) -> list[str]:
    # Only the head matters for fingerprinting; scanning a 5 MB bundle for
    # every signature is wasted work.
    head = body[:200_000]
    return [name for name, pattern in _FRAMEWORK_SIGNATURES if pattern.search(head)]


def _detect_spa(technologies: list[str]) -> SPAEvidence:
    return SPAEvidence(
        root_node=any(t in technologies for t in ("vue", "react", "angular", "svelte")),
        hash_routing="next.js" in technologies,
        webpack="webpack" in technologies,
        requirejs="requirejs" in technologies,
        vite="vite" in technologies,
    )


def _dedupe(result: HTMLResult) -> None:
    seen: set[str] = set()
    unique: list[Candidate] = []
    for candidate in result.candidates:
        if candidate.raw in seen:
            continue
        seen.add(candidate.raw)
        unique.append(candidate)
    result.candidates = unique


def page_base_dir(url: str) -> str:
    """Directory form of the entry document, used to resolve relative refs."""
    try:
        return ensure_directory_url(urljoin(url, "."))
    except ValueError:
        return url