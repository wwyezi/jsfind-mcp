"""Interface prefix extraction (axios ``baseURL`` and its relatives).

A declared prefix turns a relative reference into a full URL, so it is the
single highest-value constant in a front-end bundle. Two passes find it: the AST
pass reads the assignment itself, and the text pass catches prefixes living in a
config blob the parser does not model.
"""

from __future__ import annotations

import re

from ..utils import line_column, looks_like_path, resolve_url
from .types import BasePathCandidate

MAX_BASE_PATHS_PER_FILE = 16

# Field names that carry an interface prefix.
_BASE_PATH_FIELDS = frozenset({
    "baseurl", "base_url", "baseurl2", "apiurl", "api_url", "apipath",
    "api_path", "apibase", "api_base", "apibaseurl", "apibasepath",
    "prefix", "api", "gateway", "serviceurl", "service_url", "serverurl",
    "server_url", "backend", "backendurl", "endpoint", "host", "urlprefix",
})

_TEXT_RE = re.compile(
    r"""(?i)["']?(?P<name>%s)["']?\s*[:=]\s*"""
    r"""(?P<quote>["'`])(?P<value>[^"'`\s]{1,200})(?P=quote)"""
    % "|".join(sorted(_BASE_PATH_FIELDS))
)

_MAX_PREFIX_SEGMENTS = 4


def is_base_path_field_name(name: str) -> bool:
    """Whether an object key names an interface prefix."""
    return (name or "").strip().lower().replace("-", "_") in _BASE_PATH_FIELDS


def normalize_base_path(raw: str) -> str:
    """Return a normalized directory prefix, or "" when it is not one.

    A prefix must be a directory-like path or a root URL; ``https://api.x.com``
    qualifies, ``/v1/user`` does not (it is an endpoint, not a prefix).
    """
    value = (raw or "").strip()
    if not value or len(value) > 300:
        return ""
    if any(char in value for char in ("\n", "\r", "\t", " ")):
        return ""
    if value.startswith(("data:", "javascript:", "blob:")):
        return ""

    absolute = resolve_url("https://placeholder.invalid", value) or ""
    path = absolute.split("://", 1)[-1].split("/", 1)[-1] if "://" in absolute else value
    path = path.split("?", 1)[0].split("#", 1)[0]

    segments = [segment for segment in path.split("/") if segment]
    if not segments:
        return ""
    # Every segment must look like a path segment, not a file name or an
    # interpolation placeholder glued onto a real path.
    if any("." in segment for segment in segments):
        return ""
    if len(segments) > _MAX_PREFIX_SEGMENTS:
        return ""
    if not (value.startswith("/") or "://" in value or value.startswith("./")
            or value.startswith("../")):
        return ""
    return value if value.endswith("/") else value + "/"


def scan_base_path_text(body: str, limit: int = MAX_BASE_PATHS_PER_FILE) -> list[BasePathCandidate]:
    """Recover interface prefixes from raw text, including config blobs."""
    out: list[BasePathCandidate] = []
    seen: set[str] = set()
    for match in _TEXT_RE.finditer(body or ""):
        if len(out) >= limit:
            break
        normalized = normalize_base_path(match.group("value"))
        if not normalized or normalized in seen:
            continue
        # A prefix that is really a full endpoint is not a prefix.
        if not looks_like_path(normalized) and "://" not in normalized:
            continue
        seen.add(normalized)
        line, _column = line_column(body, match.start())
        out.append(BasePathCandidate(raw=normalized, kind="text", line=line))
    return out


def base_path_names(candidates: list[BasePathCandidate]) -> list[str]:
    """Deduplicated prefix list in discovery order."""
    out: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if candidate.raw and candidate.raw not in seen:
            seen.add(candidate.raw)
            out.append(candidate.raw)
    return out
