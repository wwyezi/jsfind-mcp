"""Shared helpers: source context extraction, URL resolution, JS string decoding."""

from __future__ import annotations

import re

import bisect
from datetime import datetime
from pathlib import Path
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


#: Where stderr went, so ``jsfind_diagnostics`` can say it out loud. Empty when
#: stderr was left on the terminal it was given.
DIAGNOSTIC_LOG: Path | None = None


def _windows_process_tree() -> dict:
    """``pid -> parent pid`` for every running process, via Toolhelp32."""
    import ctypes
    from ctypes import wintypes

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_void_p),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_char * 260),
        ]

    kernel32 = ctypes.windll.kernel32
    TH32CS_SNAPPROCESS = 0x2
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot in (0, -1, None):
        return {}
    try:
        entry = PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
        table: dict = {}
        more = kernel32.Process32First(snapshot, ctypes.byref(entry))
        while more:
            table[entry.th32ProcessID] = entry.th32ParentProcessID
            more = kernel32.Process32Next(snapshot, ctypes.byref(entry))
        return table
    finally:
        kernel32.CloseHandle(snapshot)


def _ancestors() -> list:
    """Every process above us in the tree, nearest first.

    Only the *immediate* parent is not enough. A client that launches through a
    short-lived wrapper — a shell, a launcher, a supervisor helper — has that
    wrapper die within seconds while the client itself keeps using the server.
    Watching just the parent turns that into a suicide pact: the server kills a
    perfectly healthy session and the client, seeing a dead pipe, starts
    another. Walking the whole chain and requiring *all* of it to be gone is
    what "the client is actually gone" looks like.
    """
    import os

    try:
        parent = os.getppid()
    except (AttributeError, OSError):  # pragma: no cover - exotic hosts
        return []
    if parent in (0, 1):
        return []

    chain = [parent]
    if os.name == "nt":
        table = _windows_process_tree()
        seen = {parent}
        pid = table.get(parent, 0)
        while pid and pid not in seen:
            chain.append(pid)
            seen.add(pid)
            pid = table.get(pid, 0)
    return chain


def watch_parent(interval: float = 15.0) -> None:
    """Exit once every process above us has gone away.

    An MCP client that crashes or is killed can leave its stdio children behind:
    the pipe is gone but nothing told the child to stop, so it sits there
    holding its scans until someone notices the pile.

    Two things this deliberately gets wrong in the safe direction:

    * it watches the whole ancestor chain, not just the immediate parent, so a
      short-lived launcher dying mid-session does not kill a healthy server;
    * it requires two consecutive readings of "everyone is gone" and logs the
      decision first, so a transient lookup failure cannot fire it and a
      forensic trail exists when it does.

    The check is a daemon thread — it must never be the reason the process
    cannot exit.
    """
    import os
    import threading
    import time

    chain = _ancestors()
    if not chain:
        return

    def alive(pid: int) -> bool:
        if os.name == "nt":
            import ctypes

            kernel32 = ctypes.windll.kernel32
            # 0x1000 = PROCESS_QUERY_LIMITED_INFORMATION, the least demanding
            # right there is. A NULL handle here can mean "no such process" or
            # "not permitted"; GetLastError is what separates them, and only
            # the former counts as dead.
            handle = kernel32.OpenProcess(0x1000, False, pid)
            if not handle:
                return kernel32.GetLastError() != 87  # ERROR_INVALID_PARAMETER
            try:
                code = ctypes.c_uint()
                if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                    return True  # cannot tell: assume it lives
                return code.value == 259  # STILL_ACTIVE
            finally:
                kernel32.CloseHandle(handle)
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except OSError:
            return True  # EPERM and friends: it is there
        return True

    def watch() -> None:
        strikes = 0
        while True:
            time.sleep(interval)
            if any(alive(pid) for pid in chain):
                strikes = 0
                continue
            strikes += 1
            if strikes < 2:
                continue
            # _exit, not exit: nothing here is worth flushing at the cost of
            # hanging on a stuck stream, and the point is to go away. Say so
            # first, because a silent exit is indistinguishable from a crash.
            try:
                import sys
                print(f"jsfind-mcp: 客户端进程链 {chain} 已全部退出，"
                      "本进程随之结束。", file=sys.stderr, flush=True)
            except Exception:  # noqa: BLE001
                pass
            os._exit(0)

    threading.Thread(target=watch, name="jsfind-parent-watch",
                     daemon=True).start()


def count_siblings() -> int:
    """How many jsfind-mcp processes are running, this one included.

    Reported rather than enforced: a hard single-instance lock would refuse a
    second workspace its own server, and would make a client's restart collide
    with its own shutdown. Telling the operator "there are four of me" is the
    part that actually helps.
    """
    import os
    import subprocess

    name = "jsfind-mcp"
    try:
        if os.name == "nt":
            out = subprocess.run(
                ["tasklist", "/FI", f"IMAGENAME eq {name}.exe", "/FO", "CSV", "/NH"],
                capture_output=True, text=True, timeout=10, errors="replace")
            return sum(1 for line in out.stdout.splitlines()
                       if line.strip().startswith(f'"{name}'))
        out = subprocess.run(["pgrep", "-f", name], capture_output=True,
                             text=True, timeout=10, errors="replace")
        return len([line for line in out.stdout.splitlines() if line.strip()])
    except Exception:  # noqa: BLE001 - a missing tool is not a failure
        return 0

#: One log per session would grow without bound on a long-lived install, so the
#: previous one is kept and the current file starts over past this size.
_MAX_LOG_BYTES = 2 * 1024 * 1024


def redirect_diagnostics() -> Path | None:
    """Point stderr at a log file instead of at whatever the caller piped.

    An MCP client is free to ignore the stderr pipe it handed us. A scan logs
    every request through httpx and every tool call through FastMCP, so an
    unread pipe fills within one tool call, the write blocks, and the whole
    server stops answering — including ``tools/list``, which is why the client
    then shows an empty tool list until the process is restarted. A file write
    cannot block like that, so the transport stays responsive no matter what
    the caller does with stderr.

    The swap is done on file descriptor 2 rather than on ``sys.stderr`` alone:
    logging handlers, Rich and anything else that captured the stream at import
    time keep writing to that descriptor, and after ``dup2`` every one of them
    lands in the log.

    Returns the log file, or ``None`` when stderr is a terminal and was left
    alone — an operator watching a console wants the output where they are.
    """
    import os
    import sys
    import tempfile

    global DIAGNOSTIC_LOG

    try:
        if sys.stderr is not None and sys.stderr.isatty():
            return None
    except (ValueError, OSError):  # pragma: no cover - closed streams
        pass

    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except (ValueError, OSError):  # pragma: no cover
        pass

    log_path: Path | None = None
    handle = None
    try:
        override = os.environ.get("JSFIND_LOG", "").strip()
        if override:
            # Operator's choice, and what a test uses to stay off the real log.
            log_path = Path(override).expanduser()
            log_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            from .resources import user_config_dir

            log_dir = user_config_dir() / "logs"
            log_dir.mkdir(parents=True, exist_ok=True)
            log_path = log_dir / "server.log"
        if log_path.exists() and log_path.stat().st_size > _MAX_LOG_BYTES:
            log_path.replace(log_path.with_suffix(log_path.suffix + ".1"))
        handle = open(log_path, "a", encoding="utf-8", errors="replace")
    except OSError:
        # Even a dead end is better than the pipe: writes to devnull never
        # block, which is the property this function exists for.
        handle = open(os.devnull, "w", encoding="utf-8")
        log_path = None

    try:
        os.dup2(handle.fileno(), 2)
    except OSError:  # pragma: no cover - exotic hosts
        sys.stderr = handle
        DIAGNOSTIC_LOG = log_path
        return log_path

    # sys.stderr still wraps fd 2, which now names the log file, so Python
    # writes and captured-stream writes both end up there. Append mode keeps
    # the two file positions from interleaving badly.
    handle.close()
    DIAGNOSTIC_LOG = log_path
    if log_path is not None:
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n=== jsfind-mcp diagnostics {stamp} ===", file=sys.stderr,
              flush=True)
    return log_path