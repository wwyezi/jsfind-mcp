"""Search the JavaScript a scan collected.

Static extraction only reports what it was *looking for*. A pentester facing
an unfamiliar bundle routinely needs the opposite: "is there a signing routine
in here", "which file mentions mch_id", "grep every bundle for `sign`".
Answering that from outside means reading each file by hand.

This module makes the collected JavaScript — including the unminified
originals recovered from source maps — searchable, so those questions become
one tool call instead of a manual hunt.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

#: A pattern is not allowed to run unbounded: a pathological expression over a
#: multi-megabyte bundle can hang the server, and a hang in an MCP server reads
#: to the model as a dead tool.
_MAX_PATTERN_LENGTH = 512
_MAX_FILES = 200
_MAX_MATCHES_PER_FILE = 20
_MAX_TOTAL_MATCHES = 200
_MAX_FILE_BYTES = 24 * 1024 * 1024
_CONTEXT_CHARS = 220
_MAX_SNIPPET = 400

_SCRIPT_TYPES = ("script", "chunk")


@dataclass
class JsFile:
    """One searchable script artifact."""

    url: str = ""
    local_path: str = ""
    size: int = 0
    #: script | chunk | sourcemap-source
    origin: str = "script"
    source_url: str = ""

    def readable(self) -> bool:
        return bool(self.local_path) and Path(self.local_path).is_file()


@dataclass
class Match:
    """One hit inside one file."""

    url: str = ""
    local_path: str = ""
    #: script | chunk | sourcemap-source
    origin: str = "script"
    line: int = 0
    #: 0-based column, as the source itself has it
    column: int = 0
    #: the matched text, for precise highlighting
    matched: str = ""
    #: the source line, or the region around the hit inside a minified line
    snippet: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "local_path": self.local_path,
            "origin": self.origin,
            "line": self.line,
            "column": self.column,
            "matched": self.matched,
            "snippet": self.snippet,
        }


@dataclass
class SearchOutcome:
    """Aggregated result of one search."""

    matches: list[Match] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    truncated: bool = False
    error: str = ""

    @property
    def files_matched(self) -> int:
        return len({match.local_path or match.url for match in self.matches})


def collect_js_files(result) -> list[JsFile]:
    """Every script artifact a scan saved, de-duplicated by local path.

    Source-map-recovered originals are included and tagged ``sourcemap-source``:
    they are usually the only readable form of the application, and they are
    where a secret hidden in a minified bundle becomes legible.
    """
    out: list[JsFile] = []
    seen: set[str] = set()
    for resource in result.resources:
        if resource.type.value not in _SCRIPT_TYPES or not resource.local_path:
            continue
        if resource.local_path in seen:
            continue
        seen.add(resource.local_path)
        if "source map" in (resource.source_url or ""):
            origin = "sourcemap-source"
        elif resource.type.value == "chunk":
            origin = "chunk"
        else:
            origin = "script"
        out.append(JsFile(
            url=resource.url,
            local_path=resource.local_path,
            size=resource.size,
            origin=origin,
            source_url=resource.source_url,
        ))
    return out


def compile_pattern(pattern: str, ignore_case: bool = False) -> re.Pattern | None:
    """Compile a search pattern, or None when it is neither regex nor literal."""
    if not pattern or len(pattern) > _MAX_PATTERN_LENGTH:
        return None
    flags = re.IGNORECASE if ignore_case else 0
    try:
        return re.compile(pattern, flags)
    except re.error:
        # A literal search is almost always what was meant by a malformed regex.
        try:
            return re.compile(re.escape(pattern), flags)
        except re.error:  # pragma: no cover - re.escape output always compiles
            return None


def search(files: list[JsFile], pattern: str, ignore_case: bool = False,
           url_filter: str = "", max_matches: int = _MAX_TOTAL_MATCHES,
           ) -> SearchOutcome:
    """Run one pattern over every readable file.

    Files are visited largest-first: the bundle holding the interesting code
    tends to be the big one, so the useful hit surfaces before the cap rather
    than after it.
    """
    outcome = SearchOutcome()
    compiled = compile_pattern(pattern, ignore_case)
    if compiled is None:
        outcome.error = (f"pattern is neither a usable regex nor a literal: "
                         f"{pattern!r}")
        return outcome

    candidates = list(files)
    if url_filter:
        needle = url_filter.lower()
        candidates = [item for item in candidates if needle in item.url.lower()]

    cap = max(1, min(max_matches, _MAX_TOTAL_MATCHES))
    for js_file in sorted(candidates, key=lambda f: -f.size)[:_MAX_FILES]:
        if len(outcome.matches) >= cap:
            outcome.truncated = True
            break
        text = _read(js_file, outcome)
        if text is None:
            continue
        outcome.files_scanned += 1
        found = 0
        for match in compiled.finditer(text):
            if len(outcome.matches) >= cap:
                outcome.truncated = True
                break
            if found >= _MAX_MATCHES_PER_FILE:
                break
            outcome.matches.append(_build_match(js_file, text, match))
            found += 1
        if outcome.truncated:
            break

    outcome.matches.sort(key=lambda m: (m.url, m.line, m.column))
    return outcome


def _read(js_file: JsFile, outcome: SearchOutcome) -> str | None:
    if not js_file.readable():
        outcome.files_skipped += 1
        return None
    try:
        path = Path(js_file.local_path)
        if path.stat().st_size > _MAX_FILE_BYTES:
            outcome.files_skipped += 1
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        outcome.files_skipped += 1
        return None


def _build_match(js_file: JsFile, text: str, match: re.Match) -> Match:
    start, end = match.start(), match.end()
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end < 0:
        line_end = len(text)
    line_text = text[line_start:line_end].strip()

    # Inside a minified bundle a single line can be 200 KB; show the region
    # around the hit, which is what a reader can actually use.
    if len(line_text) > _MAX_SNIPPET:
        column = start - line_start
        offset = max(0, column - _CONTEXT_CHARS)
        window = text[line_start + offset:line_start + offset + _MAX_SNIPPET]
        prefix = "..." if offset else ""
        suffix = "..." if offset + _MAX_SNIPPET < (line_end - line_start) else ""
        snippet = (prefix + window.strip() + suffix)[:_MAX_SNIPPET]
    else:
        snippet = line_text[:_MAX_SNIPPET]

    return Match(
        url=js_file.url,
        local_path=js_file.local_path,
        origin=js_file.origin,
        line=text.count("\n", 0, start) + 1,
        column=start - line_start,
        matched=(match.group(0) or "")[:_MAX_SNIPPET],
        snippet=snippet,
    )


def top_strings(files: list[JsFile], keywords: tuple[str, ...],
                limit: int = 60) -> list[dict]:
    """Surface string literals that look like credentials or config keys.

    A narrow, keyword-driven pass — not a general string dump, which would be
    thousands of i18n labels. The point is to catch what a rule set does not
    cover: a vendor ``mch_id``, a custom ``appSecret``, an internal host bound
    to a variable no rule names.
    """
    literal = re.compile(r"""["'`]((?:\\.|[^"'`\\\n]){4,200})["'`]""")
    lowered = tuple(word.lower() for word in keywords)
    seen: set[str] = set()
    out: list[dict] = []

    for js_file in sorted(files, key=lambda f: -f.size)[:_MAX_FILES]:
        if len(out) >= limit:
            break
        outcome = SearchOutcome()
        text = _read(js_file, outcome)
        if text is None:
            continue
        for match in literal.finditer(text):
            if len(out) >= limit:
                break
            value = match.group(1)
            if len(value.strip()) < 8 or value in seen:
                continue
            if not any(word in value.lower() for word in lowered):
                continue
            seen.add(value)
            out.append({
                "value": value[:200],
                "url": js_file.url,
                "local_path": js_file.local_path,
                "origin": js_file.origin,
                "line": text.count("\n", 0, match.start()) + 1,
            })
    return out


#: keywords ``top_strings`` looks for; deliberately broad, because a miss here
#: is a credential nobody ends up testing
DEFAULT_KEYWORDS = (
    "secret", "appsecret", "token", "accesskey", "access_key", "privatekey",
    "private_key", "password", "passwd", "pwd", "credential", "apikey",
    "api_key", "authorization", "sign", "signature", "nonce", "appid",
    "app_id", "appkey", "app_key", "mch_id", "mchid", "merchant", "secretid",
    "secretkey", "client_secret", "jwt", "session", "cookie", "admin",
    "internal", "debug", "sandbox", "mock",
)
