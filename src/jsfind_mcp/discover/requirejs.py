"""RequireJS module configuration extraction."""

from __future__ import annotations

import re

from ..utils import ensure_directory_url, resolve_url
from .types import Candidate, Kind

REQUIRE_BASE_URL = re.compile(r"""(?i)baseUrl\s*:\s*["']([^"']+)["']""")
REQUIRE_PATHS = re.compile(r"""(?is)paths\s*:\s*\{([^}]*)\}""")
REQUIRE_PAIR = re.compile(r"""["']?([A-Za-z0-9_./-]+)["']?\s*:\s*["']([^"']+)["']""")
REQUIRE_ARRAY = re.compile(r"""(?is)(?:define|require)\s*\(\s*\[([^\]]*)\]""")
REQUIRE_MODULE = re.compile(r"""["']([^"']+)["']""")

_PSEUDO_MODULES = frozenset({"require", "exports", "module", "text", "css"})


def from_requirejs(source: str, body: str, limit: int) -> list[Candidate]:
    """Resolve configured RequireJS modules into bounded script URLs."""
    if not source or limit <= 0:
        return []

    base = ensure_directory_url(resolve_url(source, ".") or source)
    match = REQUIRE_BASE_URL.search(body)
    if match:
        resolved = resolve_url(source, match.group(1))
        if resolved:
            base = ensure_directory_url(resolved)

    aliases: dict[str, str] = {}
    block = REQUIRE_PATHS.search(body)
    if block:
        aliases = {name: value for name, value in REQUIRE_PAIR.findall(block.group(1))}

    out: list[Candidate] = []
    seen: set[str] = set()
    for array in REQUIRE_ARRAY.findall(body):
        for module in REQUIRE_MODULE.findall(array):
            if len(out) >= limit:
                return out
            if module in _PSEUDO_MODULES:
                continue
            # "text!./tpl.html" — the plugin prefix is not part of the path.
            bang = module.rfind("!")
            if bang >= 0:
                module = module[bang + 1:]
            module = aliases.get(module, module)
            if not _has_js_extension(module):
                module += ".js"
            resolved = resolve_url(base, module)
            if not resolved or resolved in seen:
                continue
            seen.add(resolved)
            out.append(Candidate(raw=resolved, kind=Kind.CHUNK, source_url=source,
                                 source="regex"))
    return out


def _has_js_extension(raw: str) -> bool:
    lower = raw.lower()
    return lower.endswith(".js") or lower.endswith(".mjs")
