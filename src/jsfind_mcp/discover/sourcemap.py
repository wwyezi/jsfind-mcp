"""Source map discovery and original-source recovery.

A leaked ``.map`` usually restores the whole unminified front end, so a map is
treated as a first-class resource: its ``sourcesContent`` entries are fed back
into the extractors, which is how minified-only interfaces and hidden routes
become visible.
"""

from __future__ import annotations

import base64
import binascii
import json
import posixpath
import re
from dataclasses import dataclass
from urllib.parse import unquote, urlparse

_SOURCE_MAPPING_URL = re.compile(
    r"""(?m)[;#@]\s*sourceMappingURL\s*=\s*(\S+)\s*?\s*(?:$|\*/)"""
)
_DATA_URI_MAP = re.compile(r"""^data:application/json[^,]*;base64,(?P<payload>.+)$""",
                           re.S)
_MAX_INLINE_MAP_BYTES = 8 * 1024 * 1024


@dataclass
class SourceFile:
    """One original source recovered from a source map."""

    name: str = ""
    content: str = ""


def is_source_map_path(raw: str) -> bool:
    return urlparse(raw).path.lower().endswith(".map")


def source_map_reference(body: str) -> tuple[str, str]:
    """Return ``(inline_content, external_reference)`` for one script body.

    An inline data-URI map needs no extra request, so it is returned in
    ``inline_content``; an external reference is returned as-is for the caller
    to resolve against the script URL.
    """
    if not body:
        return "", ""
    # Only the tail matters; scanning a multi-megabyte bundle for the marker
    # wastes time and the marker is always near the end.
    tail = body[-4096:] if len(body) > 4096 else body
    match = None
    for match in _SOURCE_MAPPING_URL.finditer(tail):
        pass
    if not match:
        return "", ""
    reference = match.group(1).strip().strip("\"'")
    if not reference:
        return "", ""
    if reference.startswith("data:"):
        if len(reference) > _MAX_INLINE_MAP_BYTES:
            return "", ""
        data = _DATA_URI_MAP.match(reference)
        if not data:
            return "", ""
        try:
            raw = base64.b64decode(data.group("payload") + "===", validate=False)
        except (binascii.Error, ValueError):
            return "", ""
        try:
            return raw.decode("utf-8", "replace"), ""
        except Exception:  # noqa: BLE001
            return "", ""
    return "", reference


def parse_source_map(body: str) -> list[SourceFile]:
    """Extract ``sources``/``sourcesContent`` pairs from a source map."""
    if not body:
        return []
    try:
        document = json.loads(body)
    except (ValueError, TypeError):
        return []
    if not isinstance(document, dict):
        return []

    names = document.get("sources") or []
    contents = document.get("sourcesContent") or []
    out: list[SourceFile] = []
    for index, name in enumerate(names):
        if not isinstance(name, str):
            continue
        content = ""
        if index < len(contents) and isinstance(contents[index], str):
            content = contents[index]
        if not content:
            continue
        out.append(SourceFile(name=clean_source_name(name), content=content))
    return out


def clean_source_name(name: str) -> str:
    """Normalize a webpack-scheme source path into a stable pseudo-URL.

    ``webpack://my-app/./src/api/user.js`` becomes ``src/api/user.js`` so two
    bundles that embed the same original report one source, not several.
    """
    text = unquote(name or "").strip()
    if not text:
        return ""
    for prefix in ("webpack://", "webpack-internal://", "vite://", "rollup://"):
        if text.startswith(prefix):
            text = text[len(prefix):]
            # Drop the leading virtual namespace segment ("my-app/./src/...").
            if prefix.startswith("webpack"):
                text = text.split("/", 1)[-1] if "/" in text else text
            break
    if text.startswith("<") and text.endswith(">"):
        return ""
    text = text.replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    # An absolute URL keeps its own form; only relative paths get normalized.
    if "://" not in text:
        text = posixpath.normpath(text)
    if text.startswith("./"):
        text = text[2:]
    return text.lstrip("/")
