"""Shared helpers: source context extraction, URL resolution, JS string decoding."""

from __future__ import annotations

import re

import bisect
from urllib.parse import urljoin, urlparse, urlunparse

from .model import ContextLine

CONTEXT_SPAN_LINES = 3

# Extensions that never identify an API endpoint: images, fonts, stylesheets,
# media, bundles, documents and archives.
STATIC_ASSET_EXTENSIONS = frozenset("""
.png .jpg .jpeg .gif .webp .svg .ico .bmp .tif .tiff .avif
.woff .woff2 .ttf .otf .eot .css .scss .sass .less .styl
.mp3 .wav .ogg .flac .m4a .swf .mp4 .webm .avi .mov .mkv
.js .mjs .jsx .ts .tsx .map
.pdf .doc .docx .xls .xlsx .ppt .pptx .zip .rar .7z .tar .gz .dmg .exe .dll .apk .iso
.xml .rels .bin .vml
.html .htm .wasm
""".split())

JS_EXTENSIONS = (".js", ".mjs", ".jsx", ".ts", ".tsx")

# Characters allowed inside one relative-path segment. Braces are kept so
# template paths ("/api/{id}") survive.
_PATH_SEGMENT_ALPHABET = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-{}"
)

# First path segments that mark a webpack module request ("lib/inflate",
# "utils/common") rather than an application route or endpoint. Chunks are full
# of these; keeping them drowns the real paths.
MODULE_DIRECTORY_NAMES = frozenset("""
audio blots core ace icon css formats image js modules text themes ui video
static contributors application lib utils lang locale locales plugins directives
mixins node_modules dist src
""".split())

_PATH_FORBIDDEN = set(" \t\n\r()[]<>|\\^$*\"'`,")


def line_starts(source: str) -> list[int]:
    """Byte offsets of every line start, for fast offset->line mapping."""
    starts = [0]
    index = source.find("\n")
    while index >= 0:
        starts.append(index + 1)
        index = source.find("\n", index + 1)
    return starts


def line_column(source: str, offset: int, starts: list[int] | None = None) -> tuple[int, int]:
    """Convert a character offset into 1-based (line, column)."""
    if offset < 0 or offset > len(source):
        return 0, 0
    starts = starts if starts is not None else line_starts(source)
    line = bisect.bisect_right(starts, offset)
    column = offset - starts[line - 1] + 1
    return line, column


def extract_context(
    source: str,
    offset: int,
    span: int = CONTEXT_SPAN_LINES,
    match_text: str = "",
) -> list[ContextLine]:
    """Return up to ``span`` lines before and after the match, with the match
    range marked so a report can highlight it without re-reading the file."""
    if offset < 0 or offset > len(source) or not match_text:
        return []
    starts = line_starts(source)
    line, _ = line_column(source, offset, starts)
    if line <= 0:
        return []
    first = max(0, line - 1 - span)
    last = min(len(starts) - 1, line - 1 + span)
    out: list[ContextLine] = []
    for index in range(first, last + 1):
        start = starts[index]
        end = source.find("\n", start)
        if end < 0:
            end = len(source)
        content = source[start:end]
        entry = ContextLine(line_number=index + 1, content=content)
        if index + 1 == line:
            rel = offset - start
            entry.match_start = rel
            entry.match_end = rel + len(match_text)
        out.append(entry)
    return out


def decode_js_string(raw: str) -> str:
    """Decode a JavaScript string literal *including* its quotes.

    Handles escapes, line continuations and template literals; anything that
    does not decode cleanly falls back to a simple quote strip so extraction is
    never blocked by an exotic literal.
    """
    if not raw:
        return ""
    quote = raw[0]
    if quote not in ("'", '"', "`"):
        return raw
    if len(raw) >= 2 and raw[-1] == quote and raw[-1] != "\\" + quote:
        body = raw[1:-1]
    else:
        body = raw[1:]
    out: list[str] = []
    index = 0
    length = len(body)
    simple = {
        "n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v",
        "0": "\0", "\\": "\\", "'": "'", '"': '"', "`": "`", "$": "$",
    }
    while index < length:
        char = body[index]
        if char != "\\":
            out.append(char)
            index += 1
            continue
        index += 1
        if index >= length:
            out.append("\\")
            break
        esc = body[index]
        if esc in simple:
            out.append(simple[esc])
            index += 1
        elif esc == "x" and index + 2 < length:
            out.append(_safe_chr(body[index + 1:index + 3], 16))
            index += 3
        elif esc == "u":
            if index + 1 < length and body[index + 1] == "{":
                close = body.find("}", index)
                if close > 0:
                    out.append(_safe_chr(body[index + 2:close], 16))
                    index = close + 1
                    continue
            if index + 4 < length:
                out.append(_safe_chr(body[index + 1:index + 5], 16))
                index += 5
            else:
                out.append("u")
                index += 1
        elif esc == "\n":
            index += 1  # line continuation
        else:
            out.append(esc)
            index += 1
    return "".join(out)


def _safe_chr(token: str, base: int) -> str:
    try:
        return chr(int(token, base))
    except ValueError:
        return ""


def is_static_asset_path(pathname: str) -> bool:
    """Whether a path ends in an extension that is never an API endpoint."""
    name = _basename(pathname).lower()
    dot = name.rfind(".")
    if dot <= 0:
        return False
    return name[dot:] in STATIC_ASSET_EXTENSIONS


def is_javascript_path(raw: str) -> bool:
    name = _basename(urlparse(raw).path).lower()
    dot = name.rfind(".")
    return dot > 0 and name[dot:] in JS_EXTENSIONS


def is_source_map_path(raw: str) -> bool:
    return urlparse(raw).path.lower().endswith(".map")


def _basename(pathname: str) -> str:
    return pathname.rsplit("/", 1)[-1]


#: Absolute build/source paths. These are disclosure signals and belong to the
#: sensitive rules, not to the interface list: reporting them as endpoints
#: buries the real ones. The rules already cover them, so dropping them here
#: loses nothing -- see the 构建信息 group in data/rules.yml.
_FS_PREFIXES = ("/home/", "/Users/", "/var/", "/builds/", "/opt/", "/tmp/",
                "/workspace/", "/src/", "/app/", "/usr/")


def is_filesystem_path(value: str) -> bool:
    """Whether this is an absolute source/build path rather than an interface."""
    raw = (value or "").strip()
    if not raw:
        return False
    if raw.startswith(_FS_PREFIXES):
        return True
    return bool(re.match(r"^[A-Za-z]:[\\/]", raw))


def looks_like_api_path(value: str) -> bool:
    """Whether a path-shaped string is worth listing as an interface.

    Cuts the three shapes that dominate a minified vendor bundle and mean
    nothing to a tester: webpack module keys (``/PVX``, ``/+5nO``), URL-parser
    test literals (``/a/b``, ``/a/i``), and format placeholders (``/%s``).
    """
    raw = (value or "").strip()
    if not raw.startswith("/") or not raw.isascii():
        return False
    if "%s" in raw or "%d" in raw:
        return False
    if is_filesystem_path(raw):
        return False
    segments = [s for s in raw.split("/") if s]
    if not segments:
        return False
    # /a/b, /a/i: URL-parser fixtures, every segment one character.
    if all(len(s) <= 1 for s in segments):
        return False
    # /PVX, /+5nO, /bQp: a lone short fragment with no word in it is a webpack
    # module key, not a path. "home", "policy" and "api" pass this.
    if len(segments) == 1 and len(segments[0]) <= 5 \
            and not re.search(r"[a-z]{3,}", segments[0]):
        return False
    return True

def looks_like_path(value: str) -> bool:
    """Whether an extracted string can plausibly be a request target.

    Minified bundles and i18n dictionaries yield thousands of quoted strings
    that are field names, labels or regex fragments; this gate keeps them out
    of the path reports.
    """
    if not value or len(value) > 2048:
        return False
    if any(char in _PATH_FORBIDDEN for char in value):
        return False
    if "://" in value:
        return True
    # "./x" and "../x" are module specifiers, never request targets.
    if value.startswith("./") or value.startswith("../"):
        return False
    if value.startswith("#/") or value.startswith("/"):
        return True
    # Bare relative path such as "user/login": require at least two
    # identifier-like segments so "mmol/L" or "m/d/yy" are rejected, and drop
    # the module directories chunks are full of.
    segments = value.split("/")
    if len(segments) < 2:
        return False
    if segments[0].lower() in MODULE_DIRECTORY_NAMES:
        return False
    for segment in segments:
        if len(segment) < 2:
            return False
        if any(char not in _PATH_SEGMENT_ALPHABET for char in segment):
            return False
    return True


def resolve_url(base: str, reference: str) -> str | None:
    """Join ``reference`` against ``base``; None when the result is unusable."""
    reference = (reference or "").strip()
    if not reference:
        return None
    if any(char in reference for char in ("\n", "\r", " ", "\t")):
        return None
    try:
        parsed = urlparse(reference)
        if parsed.scheme and parsed.scheme not in ("http", "https", "ws", "wss"):
            return None
        if parsed.scheme:
            return reference
        if not base:
            return None
        return urljoin(base, reference)
    except ValueError:
        return None


def ensure_directory_url(url: str) -> str:
    parts = urlparse(url)
    if not parts.path.endswith("/"):
        parts = parts._replace(path=parts.path + "/")
    return urlunparse(parts)


def normalize_url(url: str) -> str:
    """Drop the fragment so the same page reached two ways dedupes."""
    parts = urlparse(url)
    return urlunparse(parts._replace(fragment=""))


def origin_of(url: str) -> str:
    parts = urlparse(url)
    if not parts.scheme or not parts.netloc:
        return ""
    return f"{parts.scheme}://{parts.netloc}"


def join_base_url(base: str, raw: str) -> str:
    """Concatenate an axios-style base with a relative path."""
    if not raw or "://" in raw or raw.startswith("//"):
        return ""
    return base.rstrip("/") + "/" + raw.lstrip("/")


def truncate(value: str, limit: int = 240) -> str:
    """Shorten an over-long value for report display."""
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def use_utf8_stdio() -> None:
    """Force UTF-8 on stdout and stderr.

    Windows consoles default to a legacy code page, which turns the report's
    Chinese text — and the MCP client config block — into mojibake. Both the
    CLI and the MCP server call this at startup, and a frozen build needs it
    just as much because PyInstaller leaves the streams on the system code page.
    """
    import sys

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):  # pragma: no cover - redirected streams
            pass