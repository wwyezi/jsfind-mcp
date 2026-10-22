"""Asset manifests and service-worker precache lists.

Most SPA loaders emit a machine-readable index of every file they will ever
serve: Create React App's ``asset-manifest.json``, webpack's
``precache-manifest.*.js`` / ``service-worker.js``, Vite's
``manifest.json``, Angular's ``manifest.webmanifest``, plus the generic
``build-manifest.json`` / ``mix-manifest.json`` / ``rev-manifest.json``.

This is the only discovery path in the project that is *complete* rather than
probabilistic: the manifest lists the files, so every lazily-loaded chunk can be
fetched instead of inferred. When one is present it beats every other route to
the same chunk, so it is worth looking for hard.
"""

from __future__ import annotations

import json
import re

from .types import Candidate, Kind

#: Manifest paths worth trying on a target, cheapest first. These are static
#: well-known locations, so trying them costs a handful of GETs and finds the
#: index even when the page never references it.
MANIFEST_PATHS = (
    "/asset-manifest.json",
    "/manifest.json",
    "/build-manifest.json",
    "/mix-manifest.json",
    "/rev-manifest.json",
    "/manifest.webmanifest",
    "/static/asset-manifest.json",
    "/static/manifest.json",
    "/dist/manifest.json",
    "/manifest/manifest.json",
)

#: Script names whose content is a manifest or a precache list.
_PRECACHE_SCRIPT = re.compile(
    r"""(?i)["'/?\w.-]*(?:
        service-worker|sw\.js|precache-manifest|workbox-|sw-precache
    )[\w.-]*\.js["']?"""
)
_SW_REGISTER = re.compile(
    r"""(?is)\.register\s*\(\s*["'`](?P<url>[^"'`]+)["'`]"""
)
_MANIFEST_FETCH = re.compile(
    r"""(?is)(?:fetch|axios\.get|\.get)\s*\(\s*["'`](?P<url>[^"'`]*"""
    r"""(?:asset-manifest|build-manifest|mix-manifest|rev-manifest|manifest)"""
    r"""[^"'`]*)["'`]"""
)

#: Workbox and sw-precache both assign their list to a global. The assignment
#: is not always ``name = [...]`` — workbox emits
#: ``self.__precacheManifest = (self.__precacheManifest || []).concat([...])`` —
#: so only the marker is matched and the array is located by bracket balancing.
_PRECACHE_MARKER = re.compile(
    r"""__precacheManifest|__PRECACHE_MANIFEST|__WB_MANIFEST"""
)
_ASSET_STRING = re.compile(r"""["']([^"']+\.(?:js|mjs|css|json|wasm|png|svg|woff2?))["']""")

#: Keys whose values are path lists in the common manifest shapes.
_MANIFEST_PATH_KEYS = (
    "files", "entrypoints", "assets", "precache", "staticFileNames",
    "initial", "async", "all", "resources",
)

_MAX_MANIFEST_FILES = 500


class AssetManifest:
    """One parsed manifest: where it came from, and every file it lists."""

    def __init__(self, url: str = "", kind: str = "manifest",
                 files: list[str] | None = None, notes: list[str] | None = None):
        self.url = url
        self.kind = kind
        self.files: list[str] = list(files or [])
        self.notes: list[str] = list(notes or [])

    def scripts(self) -> list[str]:
        """Only the script files, which are the ones worth downloading."""
        return [name for name in self.files
                if name.split("?")[0].lower().endswith((".js", ".mjs"))]

    def __bool__(self) -> bool:
        return bool(self.files)

    def to_dict(self) -> dict:
        return {"url": self.url, "kind": self.kind,
                "file_count": len(self.files),
                "script_count": len(self.scripts()),
                "notes": self.notes}


def find_manifest_references(source_url: str, body: str) -> list[Candidate]:
    """Locate manifests referenced by an HTML page or a service worker."""
    out: list[Candidate] = []
    seen: set[str] = set()

    def add(raw: str, kind: str, rule: str) -> None:
        raw = (raw or "").strip()
        if not raw or raw in seen or len(raw) > 512:
            return
        seen.add(raw)
        out.append(Candidate(raw=raw, kind=kind, source_url=source_url,
                             source="manifest", rule_id=rule))

    for match in _SW_REGISTER.finditer(body):
        add(match.group("url"), Kind.SCRIPT, "sw.register")
    for match in _PRECACHE_SCRIPT.finditer(body):
        add(match.group(0).strip("\"'"), Kind.SCRIPT, "sw.precache-script")
    for match in _MANIFEST_FETCH.finditer(body):
        add(match.group("url"), Kind.ASSET, "manifest.fetch")
    return out


def parse_manifest(url: str, body: str,
                   limit: int = _MAX_MANIFEST_FILES) -> AssetManifest:
    """Parse a manifest body, tolerating both JSON and JS-wrapped forms."""
    text = (body or "").strip()
    if not text:
        return AssetManifest(url=url, notes=["空清单"])

    notes: list[str] = []
    document = _as_json(text)
    files: list[str] = []
    kind = "manifest"

    if document is not None:
        files = _from_json(document)
        if not files:
            notes.append("JSON 未包含可识别的文件列表")
    else:
        files, notes, kind = _from_precache(text)
        if not files and not notes:
            notes.append("既不是 JSON 也不是 precache 数组")

    unique: list[str] = []
    seen: set[str] = set()
    for name in files:
        if not name or name in seen:
            continue
        seen.add(name)
        unique.append(name)
        if len(unique) >= limit:
            notes.append(f"文件列表超过 {limit} 条，已截断")
            break

    return AssetManifest(url=url, kind=kind, files=unique, notes=notes)


def _as_json(text: str):
    """Parse JSON, tolerating the XSSI prefix some CDNs prepend."""
    candidate = text.lstrip()
    if candidate.startswith(")]}'"):
        candidate = candidate.split("\n", 1)[-1]
    try:
        return json.loads(candidate)
    except (ValueError, TypeError):
        return None


def _from_json(document) -> list[str]:
    """Pull path lists out of the manifest shapes bundlers emit."""
    out: list[str] = []
    if isinstance(document, list):
        for item in document:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, dict):
                out.extend(str(value) for value in item.values()
                           if isinstance(value, str))
        return out
    if not isinstance(document, dict):
        return out

    # {"files": {"main.js": "/static/main.js", ...}}
    files = document.get("files")
    if isinstance(files, dict):
        out.extend(str(value) for value in files.values()
                   if isinstance(value, str))
        return out

    # {"entrypoints": ["static/runtime...", ...], "staticFileNames": [...]}
    for key in _MANIFEST_PATH_KEYS:
        value = document.get(key)
        if isinstance(value, list):
            out.extend(item for item in value if isinstance(item, str))
        elif isinstance(value, dict):
            out.extend(str(item) for item in value.values()
                       if isinstance(item, str))
    return out


def _balanced_array(text: str, start: int) -> str:
    """The first balanced ``[...]`` literal at or after ``start``.

    Bracket counting alone is wrong here because a precache list holds quoted
    filenames that may themselves contain brackets, so quotes are tracked too.
    """
    begin = text.find("[", start)
    if begin < 0:
        return ""
    depth = 0
    quote = ""
    index = begin
    while index < len(text):
        char = text[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = ""
        elif char in "\"'`":
            quote = char
        elif char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return text[begin:index + 1]
        index += 1
    return ""


def _array_files(array: str) -> tuple[list[str], str]:
    """Filenames in one array literal, plus a note when the shape was odd."""
    try:
        parsed = json.loads(array)
    except (ValueError, TypeError):
        parsed = None
    if isinstance(parsed, list):
        files = [item["url"] if isinstance(item, dict) and "url" in item
                 else item
                 for item in parsed if isinstance(item, (str, dict))]
        return [f for f in files if isinstance(f, str)], ""
    # Not valid JSON (trailing commas, unquoted keys): fall back to strings.
    names = _ASSET_STRING.findall(array)
    if names:
        return names, "precache 数组不是合法 JSON，已按字符串提取"
    return [], ""


def _from_precache(text: str) -> tuple[list[str], list[str], str]:
    """Pull the injected array literal out of a precache/service-worker file."""
    for marker in _PRECACHE_MARKER.finditer(text):
        cursor = marker.end()
        # Workbox writes ``(self.__precacheManifest || []).concat([...])``, so the
        # first array after the marker is the *existing* list, not the new one.
        # Step over each empty array until one actually carries entries.
        for _ in range(4):
            array = _balanced_array(text, cursor)
            if not array:
                break
            cursor = text.find(array, cursor) + len(array)
            names, note = _array_files(array)
            if names:
                return names, ([note] if note else []), "precache"
    return [], [], ""
